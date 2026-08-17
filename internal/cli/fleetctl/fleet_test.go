package fleetctl_test

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/registry"
)

// blackHole returns the address of a listener that accepts connections and then
// says nothing at all — the powered-down-but-still-routed host, which is the
// case that hangs a client with no deadline. A refused connection fails fast on
// its own and would not exercise anything.
func blackHole(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })

	go func() {
		var held []net.Conn
		defer func() {
			for _, c := range held {
				_ = c.Close()
			}
		}()
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			// Held, not closed: closing would hand the client a fast failure,
			// which is the opposite of what this fixture is for.
			held = append(held, conn)
		}
	}()
	return lis.Addr().String()
}

// enroll a sandbox into the registry directly. The end-to-end test does it the
// real way; these tests are about what `list` does with the entries, not about
// how they got there.
func addSandbox(t *testing.T, configDir string, sb registry.Sandbox) {
	t.Helper()
	fleet, err := registry.Open(filepath.Join(configDir, "registry.yaml"))
	require.NoError(t, err)
	require.NoError(t, fleet.Add(sb))
}

// A fleet with a dead host in it must still produce a listing, promptly. The
// bound here is deliberately far above the 300ms probe deadline: this test is
// not measuring latency, it is catching the failure where `list` blocks
// indefinitely on a socket that never answers.
func TestList_DoesNotHangOnAnUnreachableSandbox(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)
	_, code = run(t, dir, "ca", "sign", "--profile", "control")
	require.Equal(t, 0, code)

	addSandbox(t, dir, registry.Sandbox{Name: "black-hole", Address: blackHole(t)})
	// A second dead host, unroutable rather than silent, so the listing has to
	// survive both shapes of failure at once.
	addSandbox(t, dir, registry.Sandbox{Name: "refused", Address: "127.0.0.1:1"})

	select {
	case out := <-runAsync(t, dir, "list", "--timeout", "300ms"):
		assert.Contains(t, out, "black-hole")
		assert.Contains(t, out, "unreachable")
		// Both hosts, not just the fast one: a listing that reported only the
		// host that failed quickly would be hiding the interesting half.
		assert.Equal(t, 2, strings.Count(out, "unreachable"), "both dead hosts must be reported dead:\n%s", out)
	case <-time.After(20 * time.Second):
		t.Fatal("list blocked on an unreachable sandbox; a fleet with one dead host must still list")
	}
}

// Probes run concurrently, so N dead hosts cost one timeout rather than N.
func TestList_ProbesConcurrently(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)
	_, code = run(t, dir, "ca", "sign", "--profile", "control")
	require.Equal(t, 0, code)

	const hosts = 6
	address := blackHole(t)
	for i := range hosts {
		addSandbox(t, dir, registry.Sandbox{Name: fmt.Sprintf("dead-%d", i), Address: address})
	}

	start := time.Now()
	out, code := run(t, dir, "list", "--timeout", "1s")
	elapsed := time.Since(start)

	require.Equal(t, 0, code, out)
	assert.Equal(t, hosts, strings.Count(out, "unreachable"))
	// Serialised, this would take at least six seconds. The ceiling is loose
	// enough for a loaded CI runner and still nowhere near six.
	assert.Less(t, elapsed, 4*time.Second, "probes are serialised; %d hosts took %s", hosts, elapsed)
}

func TestList_JSONParses(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)
	_, code = run(t, dir, "ca", "sign", "--profile", "control")
	require.Equal(t, 0, code)
	addSandbox(t, dir, registry.Sandbox{
		Name:    "build-box",
		Address: "127.0.0.1:1",
		Labels:  map[string]string{"arch": "arm64"},
	})

	out, code := run(t, dir, "list", "--json", "--timeout", "300ms")
	require.Equal(t, 0, code, out)

	var doc struct {
		Sandboxes []struct {
			Name    string            `json:"name"`
			Address string            `json:"address"`
			Health  string            `json:"health"`
			Labels  map[string]string `json:"labels"`
		} `json:"sandboxes"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc), "list --json did not produce parseable JSON:\n%s", out)
	require.Len(t, doc.Sandboxes, 1)
	assert.Equal(t, "build-box", doc.Sandboxes[0].Name)
	assert.Equal(t, "unreachable", doc.Sandboxes[0].Health)
	assert.Equal(t, map[string]string{"arch": "arm64"}, doc.Sandboxes[0].Labels)
}

// An empty fleet is JSON too. A caller piping into jq should not have to handle
// "sometimes a sentence, sometimes a document".
func TestList_JSONParsesOnAnEmptyFleet(t *testing.T) {
	out, code := run(t, t.TempDir(), "list", "--json")
	require.Equal(t, 0, code, out)

	var doc struct {
		Sandboxes []any `json:"sandboxes"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc), "output was not JSON:\n%s", out)
	assert.Empty(t, doc.Sandboxes)
}

// Health this workstation cannot determine is reported as unknown, with the
// command that fixes it — not as a failure, and not as false confidence that
// every host is fine.
func TestList_WithoutControlCredentialsSaysWhatIsMissing(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)
	addSandbox(t, dir, registry.Sandbox{Name: "build-box", Address: "127.0.0.1:1"})

	out, code := run(t, dir, "list")
	require.Equal(t, 0, code, out)
	assert.Contains(t, out, "unknown")
	assert.Contains(t, out, "fleetctl ca sign --profile control")
}

// Running before `ca init` must name the command, not a path and an errno.
func TestList_BeforeCAInitNamesTheCommandToRun(t *testing.T) {
	dir := t.TempDir()
	addSandbox(t, dir, registry.Sandbox{Name: "build-box", Address: "127.0.0.1:1"})

	out, code := run(t, dir, "list")
	require.Equal(t, 0, code, out)
	assert.Contains(t, out, "fleetctl ca init")
}

func TestInfo_ReportsAnUnreachableSandboxRatherThanFailing(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)
	_, code = run(t, dir, "ca", "sign", "--profile", "control")
	require.Equal(t, 0, code)
	addSandbox(t, dir, registry.Sandbox{
		Name:       "build-box",
		Address:    blackHole(t),
		EnrolledAt: time.Now().UTC(),
	})

	out, code := run(t, dir, "info", "build-box", "--json", "--timeout", "300ms")
	require.Equal(t, 0, code, out)

	var doc struct {
		Name       string `json:"name"`
		Health     string `json:"health"`
		Detail     string `json:"detail"`
		EnrolledAt string `json:"enrolled_at"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc), "info --json did not parse:\n%s", out)
	assert.Equal(t, "build-box", doc.Name)
	assert.Equal(t, "unreachable", doc.Health)
	assert.NotEmpty(t, doc.Detail)
	// What the registry knows is still reported: an operator asking about a
	// host that is down mostly wants the facts that do not depend on it.
	assert.NotEmpty(t, doc.EnrolledAt)
}

// An unknown name is answered with the names that do exist. "no sandbox named
// typo-box" alone leaves the operator to go and look the answer up.
func TestInfo_UnknownSandboxListsTheFleet(t *testing.T) {
	dir := t.TempDir()
	addSandbox(t, dir, registry.Sandbox{Name: "build-box", Address: "127.0.0.1:1"})

	out, code := runCapturingErrors(t, dir, "info", "typo-box")
	assert.NotEqual(t, 0, code)
	assert.Contains(t, out, "typo-box")
	assert.Contains(t, out, "build-box")
}

func TestRemove_DeregistersAndSaysWhatItDidNotDo(t *testing.T) {
	dir := t.TempDir()
	addSandbox(t, dir, registry.Sandbox{Name: "build-box", Address: "127.0.0.1:8722"})

	out, code := run(t, dir, "remove", "build-box")
	require.Equal(t, 0, code, out)
	assert.Contains(t, out, "removed build-box")
	// The most common wrong assumption about this command, stated in its own
	// output rather than left to the docs.
	assert.Contains(t, out, "still installed")

	fleet, err := registry.Open(filepath.Join(dir, "registry.yaml"))
	require.NoError(t, err)
	all, err := fleet.List()
	require.NoError(t, err)
	assert.Empty(t, all)

	// A second removal fails, and says which sandboxes do exist.
	_, code = run(t, dir, "remove", "build-box")
	assert.NotEqual(t, 0, code)
}

func TestRemove_ClearsSelectionsPointingAtIt(t *testing.T) {
	dir := t.TempDir()
	addSandbox(t, dir, registry.Sandbox{Name: "build-box", Address: "127.0.0.1:8722"})

	fleet, err := registry.Open(filepath.Join(dir, "registry.yaml"))
	require.NoError(t, err)
	require.NoError(t, fleet.SetSelection("client:editor", "build-box"))

	out, code := run(t, dir, "remove", "build-box", "--json")
	require.Equal(t, 0, code, out)

	var doc struct {
		SelectionsCleared int `json:"selections_cleared"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc), "remove --json did not parse:\n%s", out)
	assert.Equal(t, 1, doc.SelectionsCleared)

	_, ok, err := fleet.GetSelection("client:editor")
	require.NoError(t, err)
	assert.False(t, ok, "a selection pointing at a removed sandbox is worse than none")
}

func TestVersion_JSONParses(t *testing.T) {
	out, code := run(t, t.TempDir(), "version", "--json")
	require.Equal(t, 0, code, out)

	var doc struct {
		Version  string `json:"version"`
		Platform string `json:"platform"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc), "version --json did not parse:\n%s", out)
	assert.NotEmpty(t, doc.Version)
	assert.Contains(t, doc.Platform, "/")
}
