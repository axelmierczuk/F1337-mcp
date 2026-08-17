package mcpserver_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/mcpserver"
)

// negotiatedProtocolVersion is the version this server is built against.
const negotiatedProtocolVersion = "2026-07-28"

// TestStdio_InitializeThenListTools drives the server over a real stdio
// transport with a hand-written JSON-RPC fixture, rather than through the
// SDK's client. The fixture is the contract an agent CLI actually speaks, and
// a bug in framing or in the initialize response is invisible when both ends
// are the same library.
func TestStdio_InitializeThenListTools(t *testing.T) {
	responses := runOverStdio(t, slog.LevelInfo, []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"fixture-client","version":"1.0.0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
	})

	initResult := responses[1]
	// The legacy initialize handshake is capped below 2026-07-28 by the spec
	// — that version negotiates through server/discover instead, which
	// TestStdio_DiscoverNegotiatesLatestProtocol covers. What matters here is
	// that a client still speaking initialize gets a usable session.
	require.Contains(t, []any{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"},
		initResult["protocolVersion"], "initialize must negotiate a supported version")

	serverInfo, ok := initResult["serverInfo"].(map[string]any)
	require.True(t, ok, "initialize must report serverInfo")
	assert.Equal(t, mcpserver.ServerName, serverInfo["name"])

	instructions, _ := initResult["instructions"].(string)
	require.NotEmpty(t, instructions, "initialize must carry instructions")
	assert.Contains(t, instructions, "sandbox_select",
		"instructions must teach the select-then-act workflow")

	toolList, ok := responses[2]["tools"].([]any)
	require.True(t, ok, "tools/list must return a tools array")
	require.NotEmpty(t, toolList)

	seen := map[string]bool{}
	for _, raw := range toolList {
		tool, ok := raw.(map[string]any)
		require.True(t, ok)

		name, _ := tool["name"].(string)
		require.NotEmpty(t, name)
		seen[name] = true

		description, _ := tool["description"].(string)
		assert.NotEmptyf(t, description, "tool %s has no description", name)

		schema, ok := tool["inputSchema"].(map[string]any)
		require.Truef(t, ok, "tool %s has no input schema", name)
		assert.Equalf(t, "object", schema["type"], "tool %s input schema must be an object", name)
		properties, ok := schema["properties"].(map[string]any)
		require.Truef(t, ok, "tool %s input schema declares no properties", name)

		// "Complete" means every argument is described, not just present. An
		// undescribed argument is one the model has to guess at, and the
		// guess is made against a remote machine.
		for arg, raw := range properties {
			property, ok := raw.(map[string]any)
			require.Truef(t, ok, "tool %s argument %s is not an object", name, arg)
			assert.NotEmptyf(t, property["type"], "tool %s argument %s declares no type", name, arg)
			description, _ := property["description"].(string)
			assert.NotEmptyf(t, description,
				"tool %s argument %s has no description; add a jsonschema tag", name, arg)
		}

		output, ok := tool["outputSchema"].(map[string]any)
		require.Truef(t, ok, "tool %s has no output schema", name)
		assertEchoInSchema(t, name, output)
	}

	for _, want := range []string{"sandbox_list", "sandbox_select", "sandbox_add", "sandbox_remove", "sandbox_info"} {
		assert.Truef(t, seen[want], "tools/list is missing %s", want)
	}
}

// TestStdio_DiscoverNegotiatesLatestProtocol covers the version this server
// is built against. Protocol 2026-07-28 dropped the initialize handshake in
// favour of server/discover (SEP-2575), which is also what removed
// protocol-level sessions and made the whole selection model necessary — so
// serving it is not incidental here.
func TestStdio_DiscoverNegotiatesLatestProtocol(t *testing.T) {
	responses := runOverStdio(t, slog.LevelInfo, []string{
		`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"fixture-client","version":"1.0.0"},"io.modelcontextprotocol/clientCapabilities":{}}}}`,
	})

	result := responses[1]
	versions, ok := result["supportedVersions"].([]any)
	require.True(t, ok, "server/discover must report supported versions")
	require.NotEmpty(t, versions)
	assert.Equal(t, negotiatedProtocolVersion, versions[0],
		"the newest version offered must be the one this server is built against")
	assert.Contains(t, versions, negotiatedProtocolVersion)

	instructions, _ := result["instructions"].(string)
	assert.Contains(t, instructions, "sandbox_select")

	capabilities, ok := result["capabilities"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, capabilities, "tools")
}

// TestSession_RunsAtLatestProtocol checks the negotiated result an SDK client
// actually ends up with, rather than only what the server offers.
func TestSession_RunsAtLatestProtocol(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	init := f.session.InitializeResult()
	require.NotNil(t, init)
	assert.Equal(t, negotiatedProtocolVersion, init.ProtocolVersion)
}

// assertEchoInSchema is the structural half of the echo guarantee: whatever a
// tool returns, its advertised output schema must require the sandbox field.
// A tool added later with raw mcp.AddTool — bypassing the registration
// helpers that stamp the echo — fails here.
func assertEchoInSchema(t *testing.T, tool string, schema map[string]any) {
	t.Helper()

	properties, ok := schema["properties"].(map[string]any)
	require.Truef(t, ok, "tool %s output schema has no properties", tool)
	sandbox, ok := properties["sandbox"].(map[string]any)
	require.Truef(t, ok, "tool %s does not echo the resolved sandbox in its result", tool)
	assert.Equalf(t, "string", sandbox["type"], "tool %s sandbox echo must be a string", tool)

	required, ok := schema["required"].([]any)
	require.Truef(t, ok, "tool %s output schema marks nothing required", tool)
	assert.Containsf(t, required, "sandbox", "tool %s must mark its sandbox echo required", tool)
}

// TestStdio_StdoutCarriesOnlyJSONRPC is the guard on the single failure that
// has no diagnostic: a stray write to stdout corrupts the protocol stream,
// and the symptom the user sees is a client that disconnects for no stated
// reason. The run logs at debug level so that every log line the server emits
// is in play.
//
// It deliberately does not hand the server a log writer. Injecting one is what
// a test naturally reaches for, and it is exactly what makes this test stop
// working: with the destination overridden, a server whose *default* logger
// wrote to stdout would still pass. So the server takes its default, and the
// run asserts on both halves — the debug lines have to arrive on stderr, and
// nothing but JSON-RPC may arrive on stdout.
func TestStdio_StdoutCarriesOnlyJSONRPC(t *testing.T) {
	stdout, stderr := runOverStdioRaw(t, slog.LevelDebug, []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"fixture-client","version":"1.0.0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sandbox_list","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"sandbox_info","arguments":{}}}`,
	}, 4)

	require.NotEmpty(t, stdout, "the server wrote nothing to stdout at all")
	for i, line := range stdout {
		var msg map[string]any
		require.NoErrorf(t, json.Unmarshal([]byte(line), &msg),
			"stdout line %d is not JSON — something printed to stdout: %q", i, line)
		assert.Equalf(t, "2.0", msg["jsonrpc"],
			"stdout line %d is JSON but not JSON-RPC: %q", i, line)
	}

	// The other half: the logging this run provoked has to have gone
	// somewhere, and that somewhere is stderr. Without this the test passes
	// just as well against a server that logs nothing at all — including one
	// whose logger was pointed at a discarded writer to make it pass.
	joined := strings.Join(stderr, "\n")
	assert.Contains(t, joined, "serving MCP over stdio",
		"the server's own log lines must arrive on stderr")
	assert.Contains(t, joined, "level=DEBUG",
		"the run must actually log at debug level, or it proves nothing about debug output")
}

// TestStdio_ExitsWhenStdinCloses covers the client going away. An MCP server
// launched over stdio has exactly one client; if it outlives it, nothing will
// ever connect to it again and it is a leaked process on the user's machine.
func TestStdio_ExitsWhenStdinCloses(t *testing.T) {
	stdinR, stdinW, err := os.Pipe()
	require.NoError(t, err)
	stdoutR, stdoutW, err := os.Pipe()
	require.NoError(t, err)

	restore := swapStdio(t, stdinR, stdoutW, os.Stderr)
	defer restore()

	// Drain stdout so the server never blocks on a full pipe.
	go func() { _, _ = io.Copy(io.Discard, stdoutR) }()

	server, err := mcpserver.New(mcpserver.Options{
		ConfigDir: t.TempDir(),
		Clients:   newFakeClients(),
		LogWriter: &testWriter{t: t},
	})
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() { done <- server.Run(context.Background()) }()

	_, err = stdinW.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"fixture-client","version":"1.0.0"}}}` + "\n"))
	require.NoError(t, err)

	require.NoError(t, stdinW.Close())

	select {
	case err := <-done:
		assert.NoError(t, err, "a client disconnecting is a normal shutdown, not a failure")
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after stdin closed: the process would outlive its client")
	}

	_ = stdoutW.Close()
	_ = stdoutR.Close()
	_ = stdinR.Close()
}

// TestServer_RegistersTheFleetGroup pins which tools resolve a sandbox
// before they run and which name their own subject. sandbox_info is the only
// fleet tool that targets: the other four operate on the registry, which is
// what makes them usable before anything has been selected.
func TestServer_RegistersTheFleetGroup(t *testing.T) {
	f := newFixture(t, fixtureOptions{})

	targeted := map[string]bool{}
	for _, registration := range f.server.Registrations() {
		targeted[registration.Name] = registration.Targeted
	}

	assert.Equal(t, map[string]bool{
		"sandbox_list":   false,
		"sandbox_select": false,
		"sandbox_add":    false,
		"sandbox_remove": false,
		"sandbox_info":   true,

		"sandbox_exec":     true,
		"sandbox_read":     true,
		"sandbox_write":    true,
		"sandbox_edit":     true,
		"sandbox_ls":       true,
		"sandbox_glob":     true,
		"sandbox_grep":     true,
		"sandbox_transfer": true,
	}, targeted)
}

// TestServer_StartsWithoutCredentials covers the fresh-workstation case: a
// user who has not yet issued themselves a control leaf must still get a
// server that starts and can tell them so, rather than one that refuses to
// launch with nothing to ask.
func TestServer_StartsWithoutCredentials(t *testing.T) {
	dir := t.TempDir()
	server, err := mcpserver.New(mcpserver.Options{ConfigDir: dir, LogWriter: &testWriter{t: t}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(t.Context(), serverTransport)
	require.NoError(t, err)
	defer func() { _ = serverSession.Close() }()

	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).
		Connect(t.Context(), clientTransport, nil)
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	// Registry-only tools work with no certificate at all.
	res, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "sandbox_add",
		Arguments: map[string]any{"name": "build-box", "address": "build-box.internal:8722"},
	})
	require.NoError(t, err)
	require.False(t, res.IsError, resultText(res))

	// The first call that has to reach an agent names the missing file and
	// the command that creates it.
	res, err = session.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "sandbox_info",
		Arguments: map[string]any{"sandbox": "build-box"},
	})
	require.NoError(t, err)
	require.True(t, res.IsError)
	text := resultText(res)
	assert.Contains(t, text, filepath.Join(dir, "ca", "ca.crt"))
	assert.Contains(t, text, "sandboxctl")
}

// ---------------------------------------------------------------- helpers

// runOverStdio drives the server over the real stdio transport and returns
// the decoded JSON-RPC responses, keyed by request id.
func runOverStdio(t *testing.T, level slog.Level, requests []string) map[int]map[string]any {
	t.Helper()

	stdout, _ := runOverStdioRaw(t, level, requests, countResponses(requests))
	byID := map[int]map[string]any{}
	for _, line := range stdout {
		var msg struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		require.NoError(t, json.Unmarshal([]byte(line), &msg))
		require.Nilf(t, msg.Error, "request %d failed: %s", msg.ID, msg.Error)
		if msg.Result == nil {
			continue
		}
		var result map[string]any
		require.NoError(t, json.Unmarshal(msg.Result, &result))
		byID[msg.ID] = result
	}
	return byID
}

// countResponses is how many of these requests carry an id and so expect a
// response; a notification does not.
func countResponses(requests []string) int {
	n := 0
	for _, req := range requests {
		var msg struct {
			ID *json.RawMessage `json:"id"`
		}
		if json.Unmarshal([]byte(req), &msg) == nil && msg.ID != nil {
			n++
		}
	}
	return n
}

// runOverStdioRaw feeds requests to a server connected to the process's real
// stdin, stdout and stderr — temporarily replaced with pipes — and returns
// every line the server wrote to each of stdout and stderr.
//
// Replacing os.Stdout is what makes this a stdout test rather than a
// transport test: anything anywhere in the server that prints, logs, or
// panics to stdout lands in the captured lines. Replacing os.Stderr too is
// what lets the server keep its default log destination, so the test covers
// the wiring a real `sandboxd-mcp serve` uses rather than one the test chose.
//
// It waits for wantResponses lines before closing stdin. Closing it earlier
// races the handlers: the transport tears the session down on EOF, and a
// response still being written loses that race.
func runOverStdioRaw(t *testing.T, level slog.Level, requests []string, wantResponses int) (stdout, stderr []string) {
	t.Helper()

	stdinR, stdinW, err := os.Pipe()
	require.NoError(t, err)
	stdoutR, stdoutW, err := os.Pipe()
	require.NoError(t, err)
	stderrR, stderrW, err := os.Pipe()
	require.NoError(t, err)

	restore := swapStdio(t, stdinR, stdoutW, stderrW)
	defer restore()

	// No LogWriter: the server must take its own default, or this test cannot
	// tell a logger pointed at stderr from one pointed at stdout.
	server, err := mcpserver.New(mcpserver.Options{
		ConfigDir: t.TempDir(),
		Clients:   newFakeClients(),
		LogLevel:  level,
	})
	require.NoError(t, err)

	outLines := scanLines(stdoutR)
	errLines := scanLines(stderrR)

	done := make(chan error, 1)
	go func() { done <- server.Run(context.Background()) }()

	for _, req := range requests {
		_, err := stdinW.Write([]byte(req + "\n"))
		require.NoError(t, err)
	}

	deadline := time.After(20 * time.Second)
	for len(stdout) < wantResponses {
		select {
		case line, ok := <-outLines:
			if !ok {
				t.Fatalf("stdout closed after %d of %d responses", len(stdout), wantResponses)
			}
			stdout = append(stdout, line)
		case line := <-errLines:
			stderr = append(stderr, line)
		case <-deadline:
			t.Fatalf("timed out after %d of %d responses", len(stdout), wantResponses)
		}
	}

	// Closing stdin is how a client disconnects, and how this run ends.
	require.NoError(t, stdinW.Close())
	for draining := true; draining; {
		select {
		case err := <-done:
			require.NoError(t, err)
			draining = false
		case line := <-errLines:
			stderr = append(stderr, line)
		case <-deadline:
			t.Fatal("server did not shut down after stdin closed")
		}
	}

	require.NoError(t, stdoutW.Close())
	for line := range outLines {
		stdout = append(stdout, line)
	}
	require.NoError(t, stderrW.Close())
	for line := range errLines {
		stderr = append(stderr, line)
	}
	require.NoError(t, stdoutR.Close())
	require.NoError(t, stderrR.Close())
	_ = stdinR.Close()

	for _, line := range stderr {
		t.Logf("server stderr: %s", line)
	}
	return stdout, stderr
}

// scanLines drains r into a channel, so a writer never blocks on a full pipe.
func scanLines(r *os.File) <-chan string {
	lines := make(chan string, 256)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			if line := strings.TrimSpace(scanner.Text()); line != "" {
				lines <- line
			}
		}
	}()
	return lines
}

// swapStdio points the process's standard streams at pipes for the duration
// of one test. Tests that call it must not run in parallel: os.Stdin,
// os.Stdout and os.Stderr are process-wide.
func swapStdio(t *testing.T, stdin, stdout, stderr *os.File) func() {
	t.Helper()
	origIn, origOut, origErr := os.Stdin, os.Stdout, os.Stderr
	os.Stdin, os.Stdout, os.Stderr = stdin, stdout, stderr
	return func() { os.Stdin, os.Stdout, os.Stderr = origIn, origOut, origErr }
}
