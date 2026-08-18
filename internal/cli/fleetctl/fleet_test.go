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

// hostileStrings are what a compromised sandbox would put in the fields it gets
// to choose, and what each has to be reduced to before it reaches a terminal.
// The escape byte goes and its parameters stay as literal text; a carriage
// return becomes a separator rather than a way to overwrite the line; a bidi
// override goes entirely.
var hostileStrings = []string{"\x1b", "\r", "\u202e"}

// `list` defuses the platform and agent version it reads out of the registry.
// `info` reads the same two fields from the same place and did not, so a
// sandbox that had once answered a fleet_info call could write escape sequences
// into the operator's terminal simply by not answering the next one.
//
// The registry is not a clean source for these: enrollment bounds what a host
// says about itself, but fleet_info overwrites both from a live GetHostInfo
// every time the model asks, and nothing checks them on that path — which is
// what UpdateHostInfo below is standing in for.
func TestInfo_DefusesAgentSuppliedStringsCachedInTheRegistry(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)
	_, code = run(t, dir, "ca", "sign", "--profile", "control")
	require.Equal(t, 0, code)

	addSandbox(t, dir, registry.Sandbox{
		Name: "build-box", Address: "127.0.0.1:1", EnrolledAt: time.Now().UTC(),
	})
	fleet, err := registry.Open(filepath.Join(dir, "registry.yaml"))
	require.NoError(t, err)
	require.NoError(t, fleet.UpdateHostInfo("build-box", registry.Platform{
		OS:            "linux\x1b[2K",
		Arch:          "amd64",
		KernelVersion: "6.1.0\rserving",
		Hostname:      "build\u202ekcatta",
	}, "v0.3.0\x1b[31m"))

	// The host is unreachable, which is the reading that comes out of the
	// registry rather than off the wire — and the one nothing sanitised.
	text, code := run(t, dir, "info", "build-box", "--timeout", "300ms")
	require.Equal(t, 0, code, text)
	for _, hostile := range hostileStrings {
		assert.NotContains(t, text, hostile, "info passed %q from the registry to the terminal", hostile)
	}
	// Still a description of the host, not a blank one.
	assert.Contains(t, text, "linux")
	assert.Contains(t, text, "amd64")

	// JSON is checked on the decoded values rather than on the document text:
	// the encoder writes an escape byte as the six characters \u001b, so a
	// document that reads clean can still hand a live escape to whatever
	// prints the field after unmarshalling it.
	outJSON, code := run(t, dir, "info", "build-box", "--json", "--timeout", "300ms")
	require.Equal(t, 0, code, outJSON)
	var doc struct {
		Platform string `json:"platform"`
		Kernel   string `json:"kernel"`
		Hostname string `json:"hostname"`
		Agent    string `json:"agent"`
	}
	require.NoError(t, json.Unmarshal([]byte(outJSON), &doc), "info --json did not parse:\n%s", outJSON)
	for field, value := range map[string]string{
		"platform": doc.Platform, "kernel": doc.Kernel, "hostname": doc.Hostname, "agent": doc.Agent,
	} {
		require.NotEmpty(t, value, "%s was dropped rather than defused", field)
		for _, hostile := range hostileStrings {
			assert.NotContains(t, value, hostile, "info --json carried %q through in %s", hostile, field)
		}
	}

	// `list` reads the same two fields from the same registry and already
	// defused them. Asserted here rather than left to the sanitiser's own unit
	// test, which passes just as happily when nothing calls it.
	listed, code := run(t, dir, "list", "--timeout", "300ms")
	require.Equal(t, 0, code, listed)
	for _, hostile := range hostileStrings {
		assert.NotContains(t, listed, hostile, "list passed %q from the registry to the terminal", hostile)
	}
	assert.Contains(t, listed, "linux")
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

// ---------------------------------------------------------------- #85

// `fleetctl list` shows what authenticates each sandbox, per sandbox, and says
// what "none" costs.
//
// The column alone is not enough: "none" in a table reads as an absence — of a
// value, of a probe — rather than as the whole of a sandbox's authentication,
// and the operator this is for is the one who inherited a fleet and has never
// seen the setting.
func TestList_ShowsWhichSandboxesAreAuthenticated(t *testing.T) {
	dir := t.TempDir()
	addSandbox(t, dir, registry.Sandbox{Name: "build-box", Address: "127.0.0.1:1"})
	addSandbox(t, dir, registry.Sandbox{Name: "tailnet-box", Address: "127.0.0.1:2", Insecure: true})

	out, code := run(t, dir, "list", "--no-probe")
	require.Equal(t, 0, code, out)

	assert.Contains(t, out, "AUTH")
	assert.Regexp(t, `build-box\s+127\.0\.0\.1:1\s+mtls`, out)
	assert.Regexp(t, `tailnet-box\s+127\.0\.0\.1:2\s+none`, out)
	assert.Contains(t, out, "auth none (tailnet-box)")
	assert.Contains(t, out, "nothing in this fleet authenticates either end")
	assert.NotContains(t, out, "auth none (build-box")
}

// A fleet that is entirely mTLS says nothing about it, so the note above means
// something when it appears.
func TestList_SaysNothingAboutUnauthenticatedSandboxesWhenThereAreNone(t *testing.T) {
	dir := t.TempDir()
	addSandbox(t, dir, registry.Sandbox{Name: "build-box", Address: "127.0.0.1:1"})

	out, code := run(t, dir, "list", "--no-probe")
	require.Equal(t, 0, code, out)
	assert.NotContains(t, out, "auth none")
}

// The JSON view carries it too — `--json` is the supported interface for
// scripts, and a fleet audit is exactly the script somebody writes.
func TestList_JSONCarriesTheAuthPosture(t *testing.T) {
	dir := t.TempDir()
	addSandbox(t, dir, registry.Sandbox{Name: "build-box", Address: "127.0.0.1:1"})
	addSandbox(t, dir, registry.Sandbox{Name: "tailnet-box", Address: "127.0.0.1:2", Insecure: true})

	out, code := run(t, dir, "list", "--no-probe", "--json")
	require.Equal(t, 0, code, out)

	var doc struct {
		Sandboxes []struct {
			Name string `json:"name"`
			Auth string `json:"auth"`
		} `json:"sandboxes"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc), "output was not JSON:\n%s", out)
	got := map[string]string{}
	for _, sb := range doc.Sandboxes {
		got[sb.Name] = sb.Auth
	}
	assert.Equal(t, map[string]string{"build-box": "mtls", "tailnet-box": "none"}, got)
}

// A fleet whose members all run without mTLS is fully usable from a
// workstation that has never run `ca init` — that is the whole point of the
// option — and `list` does not lecture it about a certificate it will never
// need.
func TestList_DoesNotDemandACertificateForAFleetThatUsesNone(t *testing.T) {
	dir := t.TempDir()
	addSandbox(t, dir, registry.Sandbox{Name: "tailnet-box", Address: blackHole(t), Insecure: true})

	out, code := run(t, dir, "list", "--timeout", "300ms")
	require.Equal(t, 0, code, out)
	assert.NotContains(t, out, "fleetctl ca init")
	assert.NotContains(t, out, "fleetctl ca sign")
	// Probed and found nothing, rather than never looked: the dial happened.
	assert.Contains(t, out, "unreachable")
}

// `fleetctl info` reports the posture for one host, including one that does not
// answer — the reading an operator gets when they are deciding whether a host
// is safe where it is.
func TestInfo_ReportsTheAuthPostureOfAnUnreachableSandbox(t *testing.T) {
	dir := t.TempDir()
	addSandbox(t, dir, registry.Sandbox{
		Name:       "tailnet-box",
		Address:    blackHole(t),
		Insecure:   true,
		EnrolledAt: time.Now().UTC(),
	})

	out, code := run(t, dir, "info", "tailnet-box", "--timeout", "300ms")
	require.Equal(t, 0, code, out)
	assert.Contains(t, out, "auth:")
	assert.Contains(t, out, "none")
	assert.Contains(t, out, "No client certificate is presented")

	out, code = run(t, dir, "info", "tailnet-box", "--json", "--timeout", "300ms")
	require.Equal(t, 0, code, out)
	var doc struct {
		Auth string `json:"auth"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc), "info --json did not parse:\n%s", out)
	assert.Equal(t, "none", doc.Auth)
}

// The command announces an unauthenticated connection where an operator will
// see it, and keeps it out of the document a script parses.
//
// Both halves matter. A control plane that took an unauthenticated connection
// without saying so would be the one participant in this posture that never
// mentions it — and a warning written onto stdout would break every `--json`
// consumer, which is the supported interface for scripts.
func TestList_AnnouncesAnUnauthenticatedDialOnStderrOnly(t *testing.T) {
	dir := t.TempDir()
	addSandbox(t, dir, registry.Sandbox{Name: "tailnet-box", Address: blackHole(t), Insecure: true})

	both, code := runCapturingErrors(t, dir, "list", "--timeout", "300ms")
	require.Equal(t, 0, code, both)
	assert.Contains(t, both, "CONNECTING TO A SANDBOX THIS FLEET DOES NOT AUTHENTICATE")
	assert.Contains(t, both, "tailnet-box")

	// The same command with --json: the result is a parseable document, and the
	// warning is not in it.
	out, code := run(t, dir, "list", "--json", "--timeout", "300ms")
	require.Equal(t, 0, code, out)
	var doc struct {
		Sandboxes []struct {
			Auth string `json:"auth"`
		} `json:"sandboxes"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc), "the result was not JSON:\n%s", out)
	require.Len(t, doc.Sandboxes, 1)
	assert.Equal(t, "none", doc.Sandboxes[0].Auth)
	assert.NotContains(t, out, "DOES NOT AUTHENTICATE")
}
