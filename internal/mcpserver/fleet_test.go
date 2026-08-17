package mcpserver_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/client"
	"github.com/axelmierczuk/sandboxd-mcp/internal/registry"
)

// listResult mirrors the sandbox_list output shape.
type listResult struct {
	Sandbox   string `json:"sandbox"`
	Hint      string `json:"hint"`
	Sandboxes []struct {
		Name     string            `json:"name"`
		Address  string            `json:"address"`
		Platform string            `json:"platform"`
		Health   string            `json:"health"`
		Detail   string            `json:"detail"`
		Agent    string            `json:"agent"`
		LastSeen string            `json:"last_seen"`
		Labels   map[string]string `json:"labels"`
		Selected bool              `json:"selected"`
	} `json:"sandboxes"`
}

type selectResult struct {
	Sandbox       string   `json:"sandbox"`
	Handle        string   `json:"handle"`
	Address       string   `json:"address"`
	Platform      string   `json:"platform"`
	PathSeparator string   `json:"path_separator"`
	AllowedRoots  []string `json:"allowed_roots"`
	Unconfined    bool     `json:"unconfined"`
	Health        string   `json:"health"`
	Note          string   `json:"note"`
}

type infoResult struct {
	Sandbox   string `json:"sandbox"`
	Address   string `json:"address"`
	Handle    string `json:"handle"`
	Platform  string `json:"platform"`
	Kernel    string `json:"kernel"`
	Hostname  string `json:"hostname"`
	Resources struct {
		CPUCores        uint32 `json:"cpu_cores"`
		MemoryTotal     string `json:"memory_total"`
		MemoryAvailable string `json:"memory_available"`
		DiskTotal       string `json:"disk_total"`
		DiskAvailable   string `json:"disk_available"`
	} `json:"resources"`
	AllowedRoots []string `json:"allowed_roots"`
	Unconfined   bool     `json:"unconfined"`
	Toolchains   []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"toolchains"`
	Agent  string `json:"agent"`
	Uptime string `json:"uptime"`
	Health string `json:"health"`
	Note   string `json:"note"`
}

type removeResult struct {
	Sandbox           string `json:"sandbox"`
	SelectionsCleared int    `json:"selections_cleared"`
	Note              string `json:"note"`
}

// TestList_EmptyRegistryIsNotAnError covers the first call a brand-new user
// makes. An error here reads as "the tool is broken"; an empty list with an
// enrollment hint reads as "there is nothing here yet, and this is how you
// change that".
func TestList_EmptyRegistryIsNotAnError(t *testing.T) {
	f := newFixture(t, fixtureOptions{})

	res := f.ok("sandbox_list", map[string]any{}, "")
	out := structured[listResult](t, res)

	assert.Empty(t, out.Sandboxes)
	assert.Empty(t, out.Sandbox, "nothing is selected, so the echo is empty")
	assert.Contains(t, out.Hint, "sandboxctl enroll mint")
	assert.Contains(t, out.Hint, "sandbox_add")
}

// TestList_RefreshProbesAndCacheDoesNot is asserted on probe count rather
// than elapsed time: "fast" is a property of the machine running the test,
// but "issued no RPC" is a property of the code.
func TestList_RefreshProbesAndCacheDoesNot(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.add("build-box", "build-box.internal:8722", nil)
	f.add("gpu-01", "gpu-01.internal:8722", nil)

	f.clients.setCached("build-box", client.HealthStatus{
		Reachable: true, Status: sandboxdv1.HealthResponse_STATUS_SERVING,
		AgentVersion: "0.1.0-cached", CheckedAt: time.Now(),
	})

	res := f.ok("sandbox_list", map[string]any{"refresh": false}, "")
	out := structured[listResult](t, res)
	require.Len(t, out.Sandboxes, 2)

	for _, sb := range out.Sandboxes {
		probes, _, _ := f.clients.host(sb.Name).counts()
		assert.Zerof(t, probes, "refresh:false must not probe %s", sb.Name)
	}
	assert.Equal(t, "serving", out.Sandboxes[0].Health, "cached health is reported")
	assert.Equal(t, "0.1.0-cached", out.Sandboxes[0].Agent)
	assert.Equal(t, "unknown", out.Sandboxes[1].Health, "a sandbox nothing has dialed reads as unknown, not unreachable")

	res = f.ok("sandbox_list", map[string]any{"refresh": true}, "")
	out = structured[listResult](t, res)
	require.Len(t, out.Sandboxes, 2)
	for _, sb := range out.Sandboxes {
		probes, _, _ := f.clients.host(sb.Name).counts()
		assert.Equalf(t, 1, probes, "refresh:true must probe %s exactly once", sb.Name)
		assert.Equal(t, "serving", sb.Health)
		assert.NotEqual(t, "never", sb.LastSeen)
	}
}

// TestList_UnreachableDetailNeverLeaksTheGRPCEnvelope covers both halves of
// the listing's health, because they used to disagree: the live probe ran its
// failure through the central mapping and the cached one did not, so a
// powered-off box read as "connection refused" after a refresh and as
// "rpc error: code = Unavailable desc = connection refused" from cache — the
// exact envelope issue #19 says must never reach a model's context.
func TestList_UnreachableDetailNeverLeaksTheGRPCEnvelope(t *testing.T) {
	f := newFixture(t, fixtureOptions{probeTimeout: 200 * time.Millisecond})
	f.add("cached", "cached.internal:8722", nil)
	f.add("probed", "probed.internal:8722", nil)

	// A cached failed probe, as the pool's background health loop records it:
	// the raw gRPC error, exactly as it came off the wire.
	f.clients.setCached("cached", client.HealthStatus{
		Reachable: false,
		CheckedAt: time.Now(),
		Err:       status.Error(codes.Unavailable, "connection refused"),
	})
	f.clients.host("probed").setErr(status.Error(codes.Unavailable, "connection refused"))

	for _, refresh := range []bool{false, true} {
		out := structured[listResult](t, f.ok("sandbox_list", map[string]any{"refresh": refresh}, ""))
		require.Len(t, out.Sandboxes, 2)

		name := "cached"
		if refresh {
			name = "probed"
		}
		var line string
		for _, sb := range out.Sandboxes {
			if sb.Name == name {
				require.Equal(t, "unreachable", sb.Health)
				line = sb.Detail
			}
		}
		require.NotEmptyf(t, line, "%s should say why it is unreachable (refresh=%v)", name, refresh)
		assert.NotContainsf(t, line, "rpc error: code =",
			"refresh=%v leaked the gRPC envelope into the model's context: %q", refresh, line)
		assert.NotContainsf(t, line, "desc =", "refresh=%v leaked the gRPC envelope: %q", refresh, line)
		assert.Containsf(t, line, "connection refused",
			"refresh=%v dropped the reason along with the envelope: %q", refresh, line)
	}
}

// TestList_UnreachableSandboxDoesNotHangTheCall covers the powered-off box.
// One of them must not hold up the listing, and a per-sandbox deadline is
// what makes that true regardless of how many are off.
func TestList_UnreachableSandboxDoesNotHangTheCall(t *testing.T) {
	f := newFixture(t, fixtureOptions{probeTimeout: 200 * time.Millisecond})
	f.add("up", "up.internal:8722", nil)
	f.add("down-1", "down-1.internal:8722", nil)
	f.add("down-2", "down-2.internal:8722", nil)

	// Two hosts that never answer, simulated as a probe that outlives its
	// deadline rather than one that refuses the connection.
	for _, name := range []string{"down-1", "down-2"} {
		f.clients.host(name).delay = time.Hour
	}

	started := time.Now()
	res := f.ok("sandbox_list", map[string]any{"refresh": true}, "")
	elapsed := time.Since(started)

	out := structured[listResult](t, res)
	require.Len(t, out.Sandboxes, 3)
	assert.Equal(t, "serving", out.Sandboxes[0].Health)
	for _, sb := range out.Sandboxes[1:] {
		assert.Equalf(t, "unreachable", sb.Health, "%s should read as unreachable", sb.Name)
		assert.NotEmptyf(t, sb.Detail, "%s should say why it is unreachable", sb.Name)
	}

	// Serialised, two dead hosts would cost two deadlines. Probing in
	// parallel means one, plus slack for a loaded CI machine.
	assert.Less(t, elapsed, 3*time.Second, "probes must run in parallel")
}

// TestList_FiltersByLabel covers the label filter, and the case where it
// matches nothing — which must not read the same as an empty fleet.
func TestList_FiltersByLabel(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.add("build-box", "build-box.internal:8722", map[string]string{"arch": "amd64"})
	f.add("gpu-01", "gpu-01.internal:8722", map[string]string{"arch": "arm64", "gpu": "a100"})

	out := structured[listResult](t, f.ok("sandbox_list", map[string]any{"label": "arch=arm64"}, ""))
	require.Len(t, out.Sandboxes, 1)
	assert.Equal(t, "gpu-01", out.Sandboxes[0].Name)

	out = structured[listResult](t, f.ok("sandbox_list", map[string]any{"label": "gpu=h100"}, ""))
	assert.Empty(t, out.Sandboxes)
	assert.Contains(t, out.Hint, "gpu=h100")
	assert.NotContains(t, out.Hint, "sandboxctl enroll mint",
		"a filter that matched nothing is not an empty fleet")

	text := f.fails("sandbox_list", map[string]any{"label": "arm64"}, "")
	assert.Contains(t, text, "key=value")
}

// TestList_ReportsAStaleSelectionRatherThanEchoingIt. Echoing a sandbox that
// does not appear in the very list being returned reads as a bug in the tool;
// saying the selection is gone is what the model can act on.
func TestList_ReportsAStaleSelectionRatherThanEchoingIt(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.add("build-box", "build-box.internal:8722", map[string]string{"arch": "amd64"})
	f.add("gpu-01", "gpu-01.internal:8722", nil)
	f.ok("sandbox_select", map[string]any{"name": "gpu-01"}, "")

	// Removed underneath the server, as sandboxctl would.
	require.NoError(t, f.fleet.Remove("gpu-01"))

	out := structured[listResult](t, f.ok("sandbox_list", map[string]any{}, ""))
	assert.Empty(t, out.Sandbox, "the echo must not name a sandbox that is not in the list")
	assert.Contains(t, out.Hint, "gpu-01")
	assert.Contains(t, out.Hint, "no longer registered")

	// A label filter that excludes the selection is not the same thing: it is
	// still selected, just not shown.
	f.ok("sandbox_select", map[string]any{"name": "build-box"}, "")
	out = structured[listResult](t, f.ok("sandbox_list", map[string]any{"label": "arch=arm64"}, ""))
	assert.Equal(t, "build-box", out.Sandbox)
	assert.NotContains(t, out.Hint, "no longer registered")
}

// TestList_TwentySandboxesStayCompact guards the size of a result that lands
// in model context on every fleet check.
func TestList_TwentySandboxesStayCompact(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	for i := range 20 {
		f.add(fmt.Sprintf("sandbox-%02d", i), fmt.Sprintf("sandbox-%02d.internal:8722", i),
			map[string]string{"arch": "amd64"})
	}

	res := f.ok("sandbox_list", map[string]any{}, "")
	out := structured[listResult](t, res)
	require.Len(t, out.Sandboxes, 20)

	text := resultText(res)
	assert.Equal(t, 0, strings.Count(text, "\n"),
		"the listing must not be pretty-printed into hundreds of lines")
	assert.Lessf(t, len(text), 4096,
		"a twenty-sandbox listing is %d bytes; it is paid for on every fleet check", len(text))
}

// TestSelect_ReturnsHandlePlatformAndRoots covers the reason select returns
// more than an acknowledgement: without the roots, the model's next call is
// always sandbox_info.
func TestSelect_ReturnsHandlePlatformAndRoots(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.add("build-box", "build-box.internal:8722", nil)

	out := structured[selectResult](t, f.ok("sandbox_select", map[string]any{"name": "build-box"}, ""))

	assert.Equal(t, "build-box", out.Sandbox)
	assert.NotEmpty(t, out.Handle)
	assert.Equal(t, "linux/amd64", out.Platform)
	assert.Equal(t, "/", out.PathSeparator)
	assert.Equal(t, []string{"/home/build/workspace"}, out.AllowedRoots)
	assert.Equal(t, "serving", out.Health)
}

// TestUnconfinedHost_ReadsAsEveryPathWritableNotNone.
//
// The path jail and ExecService are mutually exclusive — a caller with exec
// writes anywhere its user can, so the jail is enforced only on an agent with
// exec disabled — and such an agent reports no allowed roots. sandbox_select
// returns roots precisely so the model learns where it may write, so the empty
// case is the one that must be said out loud: an absent allowed_roots reads as
// "nowhere is writable", which is the opposite of the truth and would stop a
// model even trying.
func TestUnconfinedHost_ReadsAsEveryPathWritableNotNone(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.add("open-box", "open-box.internal:8722", nil)

	host := f.clients.host("open-box")
	host.mu.Lock()
	host.info.AllowedRoots = nil
	host.mu.Unlock()

	sel := structured[selectResult](t, f.ok("sandbox_select", map[string]any{"name": "open-box"}, ""))
	assert.Empty(t, sel.AllowedRoots)
	assert.True(t, sel.Unconfined, "an agent with no jail must say so, not just omit the roots")
	assert.Contains(t, sel.Note, "unconfined")
	assert.Contains(t, sel.Note, "writable", "the note must say every path is writable, not that none is")
	assert.Contains(t, sel.Note, "exec", "and why: roots are only enforced with exec disabled")

	info := structured[infoResult](t, f.ok("sandbox_info", map[string]any{"sandbox": "open-box"}, ""))
	assert.Empty(t, info.AllowedRoots)
	assert.True(t, info.Unconfined)
	assert.Contains(t, info.Note, "unconfined")
	// The optional-probe note still composes, and does not displace the one
	// about where the model may write.
	assert.Contains(t, info.Note, "include_toolchains")
	assert.Less(t, strings.Index(info.Note, "unconfined"), strings.Index(info.Note, "include_toolchains"),
		"which paths are writable outranks a note about an optional probe")

	// A confined agent is unchanged: roots listed, no flag, no note about it.
	f.add("closed-box", "closed-box.internal:8722", nil)
	sel = structured[selectResult](t, f.ok("sandbox_select", map[string]any{"name": "closed-box"}, ""))
	assert.Equal(t, []string{"/home/build/workspace"}, sel.AllowedRoots)
	assert.False(t, sel.Unconfined)
	assert.NotContains(t, sel.Note, "unconfined")
}

// TestSelect_UnknownNameListsValidNames: a model that mistypes a name needs
// the right ones, not a restatement that it was wrong.
func TestSelect_UnknownNameListsValidNames(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.add("build-box", "build-box.internal:8722", nil)
	f.add("gpu-01", "gpu-01.internal:8722", nil)

	text := f.fails("sandbox_select", map[string]any{"name": "buildbox"}, "")
	assert.Contains(t, text, "buildbox")
	assert.Contains(t, text, "build-box")
	assert.Contains(t, text, "gpu-01")
}

// TestSelect_UnreachableSandboxStillSelects: the box may simply be booting.
// Refusing to select it would leave the model unable to address it at all
// once it came up.
func TestSelect_UnreachableSandboxStillSelects(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.add("build-box", "build-box.internal:8722", nil)
	f.clients.host("build-box").setErr(unavailable("build-box"))

	res := f.ok("sandbox_select", map[string]any{"name": "build-box"}, "")
	out := structured[selectResult](t, res)

	assert.Equal(t, "build-box", out.Sandbox)
	assert.Equal(t, "unreachable", out.Health)
	assert.Contains(t, out.Note, "build-box.internal:8722", "the note must name the address to check")

	// The selection stuck despite the failure.
	name, ok, err := f.fleet.GetSelection(f.identity)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "build-box", name)
}

// TestAdd_ValidatesAddressBeforeTouchingTheRegistry: a rejected call must
// leave no trace, or the fleet accumulates entries nothing can dial.
func TestAdd_ValidatesAddressBeforeTouchingTheRegistry(t *testing.T) {
	f := newFixture(t, fixtureOptions{})

	for _, address := range []string{"build-box", "build-box:", ":8722", "build-box:0", "build-box:99999", "https://build-box:8722", "build-box:http"} {
		t.Run(address, func(t *testing.T) {
			text := f.fails("sandbox_add", map[string]any{"name": "build-box", "address": address}, "")
			assert.Contains(t, strings.ToLower(text), "address")

			sandboxes, err := f.fleet.List()
			require.NoError(t, err)
			assert.Empty(t, sandboxes, "a rejected address must not leave a registry entry")
		})
	}
}

// TestAdd_RefusesToOverwriteAnExistingName: silently repointing a name at a
// new address is how a later call reaches the wrong host.
func TestAdd_RefusesToOverwriteAnExistingName(t *testing.T) {
	f := newFixture(t, fixtureOptions{})

	res := f.ok("sandbox_add", map[string]any{"name": "build-box", "address": "build-box.internal:8722"}, "")
	added := structured[map[string]any](t, res)
	assert.Equal(t, "build-box", added["sandbox"])
	assert.Contains(t, added["note"], "does not enroll", "the result must say it did not enroll")

	text := f.fails("sandbox_add", map[string]any{"name": "build-box", "address": "elsewhere.internal:8722"}, "")
	assert.Contains(t, text, "already registered")
	assert.Contains(t, text, "build-box.internal:8722", "the error must name the address it kept")

	sb, err := f.fleet.Get("build-box")
	require.NoError(t, err)
	assert.Equal(t, "build-box.internal:8722", sb.Address, "the address must be unchanged")
}

// TestAdd_RejectsUnusableNames guards the identifier that becomes a registry
// key, a certificate subject, and a line in a table.
func TestAdd_RejectsUnusableNames(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	for _, name := range []string{"", "build box", "build\tbox", "build\nbox", "sbx_deadbeef", strings.Repeat("a", 129)} {
		text := f.fails("sandbox_add", map[string]any{"name": name, "address": "host:8722"}, "")
		assert.Contains(t, strings.ToLower(text), "name", "rejecting %q should explain the name is the problem", name)
	}
}

// TestRemove_ClearsTheSelectionAndSaysWhatItDidNotDo covers the criterion
// that a dangling selection is worse than none, and the one that stops a
// reader assuming the host was cleaned up.
func TestRemove_ClearsTheSelectionAndSaysWhatItDidNotDo(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.add("build-box", "build-box.internal:8722", nil)
	f.ok("sandbox_select", map[string]any{"name": "build-box"}, "")

	// A second client has it selected too. Removing must reach both, not
	// just the caller's.
	f.ok("sandbox_select", map[string]any{"name": "build-box"}, "other-client")

	res := f.ok("sandbox_remove", map[string]any{"name": "build-box"}, "")
	out := structured[removeResult](t, res)

	assert.Equal(t, "build-box", out.Sandbox)
	assert.Equal(t, 2, out.SelectionsCleared, "every client's selection must be cleared, not just the caller's")
	assert.Contains(t, out.Note, "uninstall")
	assert.True(t, f.clients.wasRemoved("build-box"), "the pooled channel must be dropped too")

	_, ok, err := f.fleet.GetSelection(f.identity)
	require.NoError(t, err)
	assert.False(t, ok, "the caller's selection must be gone")
	_, ok, err = f.fleet.GetSelection("meta:other-client")
	require.NoError(t, err)
	assert.False(t, ok, "the other client's selection must be gone")

	_, err = f.fleet.Get("build-box")
	assert.ErrorIs(t, err, registry.ErrNotFound)
}

// TestRemove_UnknownNameListsValidNames keeps removal consistent with
// selection: an unknown name is answered with the ones that exist.
func TestRemove_UnknownNameListsValidNames(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.add("build-box", "build-box.internal:8722", nil)

	text := f.fails("sandbox_remove", map[string]any{"name": "gpu-01"}, "")
	assert.Contains(t, text, "gpu-01")
	assert.Contains(t, text, "build-box")
}

// TestInfo_ReportsPlatformResourcesAndRoots, and gates toolchain detection
// behind the flag that pays for it.
func TestInfo_ReportsPlatformResourcesAndRoots(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.add("build-box", "build-box.internal:8722", nil)
	f.clients.host("build-box").toolchainDelay = 250 * time.Millisecond

	started := time.Now()
	out := structured[infoResult](t, f.ok("sandbox_info", map[string]any{"sandbox": "build-box"}, ""))
	withoutToolchains := time.Since(started)

	assert.Equal(t, "build-box", out.Sandbox)
	assert.Equal(t, "linux/amd64", out.Platform)
	assert.Equal(t, "6.8.0", out.Kernel)
	assert.Equal(t, uint32(8), out.Resources.CPUCores)
	assert.Equal(t, "16.0 GiB", out.Resources.MemoryTotal)
	assert.Equal(t, "512.0 GiB", out.Resources.DiskTotal)
	assert.Equal(t, []string{"/home/build/workspace"}, out.AllowedRoots)
	assert.Equal(t, "0.1.0-test", out.Agent)
	assert.NotEmpty(t, out.Uptime)
	assert.Empty(t, out.Toolchains, "toolchains must not be probed unless asked for")
	assert.Contains(t, out.Note, "include_toolchains")

	started = time.Now()
	out = structured[infoResult](t, f.ok("sandbox_info",
		map[string]any{"sandbox": "build-box", "include_toolchains": true}, ""))
	withToolchains := time.Since(started)

	require.Len(t, out.Toolchains, 1)
	assert.Equal(t, "go", out.Toolchains[0].Name)

	_, _, toolchainCalls := f.clients.host("build-box").counts()
	assert.Equal(t, 1, toolchainCalls, "exactly one call asked the host to probe toolchains")
	assert.Greater(t, withToolchains, withoutToolchains,
		"include_toolchains is the slower path, which is why it is opt-in")
	assert.GreaterOrEqual(t, withToolchains, 200*time.Millisecond)
}

// TestInfo_CachesPlatformIntoTheRegistry: a listing should not have to dial
// every host to say what it is.
func TestInfo_CachesPlatformIntoTheRegistry(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.add("build-box", "build-box.internal:8722", nil)

	before, err := f.fleet.Get("build-box")
	require.NoError(t, err)
	require.Empty(t, before.Platform.OS)

	f.ok("sandbox_info", map[string]any{"sandbox": "build-box"}, "")

	after, err := f.fleet.Get("build-box")
	require.NoError(t, err)
	assert.Equal(t, "linux", after.Platform.OS)
	assert.Equal(t, "amd64", after.Platform.Arch)
	assert.Equal(t, "0.1.0-test", after.AgentVersion)
	assert.False(t, after.LastSeenAt.IsZero())

	out := structured[listResult](t, f.ok("sandbox_list", map[string]any{}, ""))
	require.Len(t, out.Sandboxes, 1)
	assert.Equal(t, "linux/amd64", out.Sandboxes[0].Platform)
}

// TestInfo_UnavailableSurfacesAsAReadableToolError is issue #19's error
// mapping seen from the outside: a gRPC status the model cannot read becomes
// a sentence naming the host, the address, and what to check.
func TestInfo_UnavailableSurfacesAsAReadableToolError(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.add("build-box", "build-box.internal:8722", nil)
	f.clients.host("build-box").setErr(unavailable("build-box"))

	text := f.fails("sandbox_info", map[string]any{"sandbox": "build-box"}, "")

	assert.Contains(t, text, "build-box", "the error must name the sandbox")
	assert.Contains(t, text, "build-box.internal:8722", "and the address it could not reach")
	assert.Contains(t, text, "unreachable")
	assert.NotContains(t, text, "rpc error: code =", "no gRPC envelope in the model's context")
	assert.NotContains(t, text, "*status.", "no Go type names in the model's context")
}

// TestInfo_PermissionDeniedNamesTheReason: the fix for a policy denial is
// never a certificate, so the message must carry the agent's reason.
func TestInfo_PermissionDeniedNamesTheReason(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.add("build-box", "build-box.internal:8722", nil)
	f.clients.host("build-box").setErr(
		status.Error(codes.PermissionDenied, "path /etc/shadow escapes allowed roots"))

	text := f.fails("sandbox_info", map[string]any{"sandbox": "build-box"}, "")
	assert.Contains(t, text, "build-box")
	assert.Contains(t, text, "escapes allowed roots")
	assert.NotContains(t, text, "rpc error: code =")
}

// TestInfo_DeadlineNamesTheLimit: a model told only "deadline exceeded"
// cannot tell which knob to turn.
func TestInfo_DeadlineNamesTheLimit(t *testing.T) {
	f := newFixture(t, fixtureOptions{callTimeout: 150 * time.Millisecond})
	f.add("build-box", "build-box.internal:8722", nil)
	f.clients.host("build-box").delay = time.Hour

	text := f.fails("sandbox_info", map[string]any{"sandbox": "build-box"}, "")
	assert.Contains(t, text, "build-box")
	assert.Contains(t, text, "timed out")
	assert.Contains(t, text, "deadline", "the limit that was hit must be named")
}

// TestFleetResults_AreValidAgainstTheirSchemas is a sanity check that the
// declared output schemas match what the handlers actually return: the SDK
// validates output against the schema, so a mismatch is a protocol error
// rather than a wrong answer.
func TestFleetResults_AreValidAgainstTheirSchemas(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.add("build-box", "build-box.internal:8722", nil)

	for _, call := range []struct {
		tool string
		args map[string]any
	}{
		{"sandbox_list", map[string]any{}},
		{"sandbox_select", map[string]any{"name": "build-box"}},
		{"sandbox_info", map[string]any{}},
		{"sandbox_add", map[string]any{"name": "gpu-01", "address": "gpu-01.internal:8722"}},
		{"sandbox_remove", map[string]any{"name": "gpu-01"}},
	} {
		res := f.ok(call.tool, call.args, "")
		require.NotNilf(t, res.StructuredContent, "%s returned no structured content", call.tool)
		raw, err := json.Marshal(res.StructuredContent)
		require.NoError(t, err)
		assert.Truef(t, strings.HasPrefix(string(raw), "{"), "%s must return a JSON object", call.tool)
	}
}
