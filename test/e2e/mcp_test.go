//go:build integration

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver/selection"
)

// session is a live MCP session against a real `fleet-mcp serve` subprocess.
//
// The transport is stdio with newline-delimited JSON-RPC, which is what an
// agent CLI speaks: no in-memory transport, no calling a handler directly. A
// tool result observed here is a result a model would have observed, including
// the parts of it — the structured content, the error flag, the mandatory
// sandbox echo — that only exist because the call went through the protocol.
type session struct {
	t      *testing.T
	fleet  *fleet
	client *mcp.ClientSession
	errs   *syncBuffer

	// cwd is the server process's working directory. A pull writes to this
	// workstation's filesystem and fleet_transfer confines it to the server's
	// working directory unless told otherwise, so a test that pulls needs to
	// know where "here" is.
	cwd string

	// stopped guards stop, which the cleanup calls and a scenario may have
	// called first.
	stopped bool
}

// stop closes the session, which closes the stdio transport and ends the
// fleet-mcp process behind it.
//
// A scenario calls it when the server going away is the thing under test — a
// listener the server owns has to be released with it — and the cleanup calls
// it otherwise. Idempotent, so both can.
func (s *session) stop(t *testing.T) {
	t.Helper()
	if s.stopped {
		return
	}
	s.stopped = true
	if err := s.client.Close(); err != nil {
		t.Logf("closing the MCP session: %v", err)
	}
}

// connect starts fleet-mcp against this fleet's config directory and completes
// the MCP handshake.
func (f *fleet) connect(t *testing.T) *session {
	t.Helper()
	return f.connectAt(t, f.ctlDir, "workstation")
}

// connectAt is connect against a config directory of the caller's choosing, so
// a scenario can drive a server that holds different credentials from the one
// this fleet set up for itself. cwdName keeps each server's working directory
// distinct, because a pull writes into it.
func (f *fleet) connectAt(t *testing.T, configDir, cwdName string) *session {
	t.Helper()

	cwd := filepath.Join(f.root, cwdName)
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatalf("create workstation directory: %v", err)
	}

	errs := &syncBuffer{}
	cmd := exec.Command(bins.mcp, "serve", "--config-dir", configDir, "--log-level", "debug")
	cmd.Env = f.configEnv(configDir)
	cmd.Dir = cwd
	cmd.Stderr = errs

	client := mcp.NewClient(&mcp.Implementation{Name: "fleet-e2e", Version: "1.0.0"}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect to fleet-mcp over stdio: %v\nstderr:\n%s", err, errs.String())
	}

	s := &session{t: t, fleet: f, client: cs, errs: errs, cwd: cwd}
	t.Cleanup(func() {
		s.stop(t)
		if t.Failed() {
			t.Logf("fleet-mcp stderr:\n%s", errs.String())
		}
	})
	return s
}

// callOptions are the per-call knobs a scenario needs.
type callOptions struct {
	// identity is sent as the explicit client id in _meta. Empty leaves the
	// server to fall back to the client implementation name, which is what an
	// ordinary client does.
	identity string
	// timeout bounds this call. Zero uses a minute, which is far longer than
	// any tool here should take and short enough that a hung call fails the
	// test rather than the whole package.
	timeout time.Duration
}

// call invokes a tool and returns the result as a client sees it. A tool that
// reports failure is a result, not an error: only a protocol-level failure
// fails the test here.
func (s *session) call(name string, args map[string]any, opts callOptions) *mcp.CallToolResult {
	s.t.Helper()

	res, err := s.tryCall(name, args, opts)
	if err != nil {
		s.t.Fatalf("%s failed at the protocol level: %v\nfleet-mcp stderr:\n%s", name, err, s.errs.String())
	}
	return res
}

// tryCall is call for a caller that must not fail the test from where it
// stands — the concurrent scenario, whose calls run on goroutines of their own.
// See decodeStructured.
func (s *session) tryCall(name string, args map[string]any, opts callOptions) (*mcp.CallToolResult, error) {
	timeout := opts.timeout
	if timeout == 0 {
		timeout = time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	params := &mcp.CallToolParams{Name: name, Arguments: args}
	if opts.identity != "" {
		params.Meta = mcp.Meta{selection.MetaKeyClientID: opts.identity}
	}
	return s.client.CallTool(ctx, params)
}

// ok calls a tool and fails the test if the tool reported an error.
func (s *session) ok(name string, args map[string]any) *mcp.CallToolResult {
	s.t.Helper()
	return s.okAs(name, args, callOptions{})
}

// okAs is ok with explicit call options.
func (s *session) okAs(name string, args map[string]any, opts callOptions) *mcp.CallToolResult {
	s.t.Helper()
	res := s.call(name, args, opts)
	if res.IsError {
		s.t.Fatalf("%s reported an error: %s", name, resultText(res))
	}
	return res
}

// fails calls a tool that is expected to report an error, and returns its text.
func (s *session) fails(name string, args map[string]any) string {
	s.t.Helper()
	return s.failsAs(name, args, callOptions{})
}

// failsAs is fails with explicit call options.
func (s *session) failsAs(name string, args map[string]any, opts callOptions) string {
	s.t.Helper()
	res := s.call(name, args, opts)
	if !res.IsError {
		s.t.Fatalf("%s should have reported an error, got: %s", name, resultText(res))
	}
	return resultText(res)
}

// tools lists the server's tool surface.
func (s *session) tools() []string {
	s.t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	listed, err := s.client.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		s.t.Fatalf("tools/list: %v", err)
	}
	names := make([]string, 0, len(listed.Tools))
	for _, tool := range listed.Tools {
		names = append(names, tool.Name)
	}
	return names
}

// resultText concatenates a result's text content.
func resultText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// structured decodes a result's structured content into T.
func structured[T any](t *testing.T, res *mcp.CallToolResult) T {
	t.Helper()

	out, err := decodeStructured[T](res)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// decodeStructured is structured for a caller that is not the test's own
// goroutine.
//
// t.Fatalf from a goroutine other than the one running the test does not do
// what it looks like it does — it stops that goroutine and leaves the test to
// carry on — so the concurrent scenario collects failures and reports them from
// the test goroutine instead. Keeping both spellings over one decoder means the
// two cannot disagree about what a result is.
func decodeStructured[T any](res *mcp.CallToolResult) (T, error) {
	var out T
	if res.StructuredContent == nil {
		return out, fmt.Errorf("tool result carries no structured content: %s", resultText(res))
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		return out, fmt.Errorf("re-encode structured content: %w", err)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("decode structured content into %T: %w\n%s", out, err, raw)
	}
	return out, nil
}

// echoOf reads the sandbox echo every tool result carries.
//
// Read it on every targeted call. It is the field that makes silent target
// confusion visible, and a test that trusts its own idea of where a call went
// is not testing the thing that matters.
func echoOf(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	m := structured[map[string]any](t, res)
	v, ok := m["sandbox"]
	if !ok {
		t.Fatalf("tool result carries no sandbox echo: %v", m)
	}
	name, ok := v.(string)
	if !ok {
		t.Fatalf("sandbox echo is not a string: %v", v)
	}
	return name
}
