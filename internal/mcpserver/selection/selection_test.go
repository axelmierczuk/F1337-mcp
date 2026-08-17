package selection_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/mcpserver/selection"
	"github.com/axelmierczuk/sandboxd-mcp/internal/registry"
)

func newFleet(t *testing.T, names ...string) *registry.Registry {
	t.Helper()
	fleet, err := registry.Open(filepath.Join(t.TempDir(), "registry.yaml"))
	require.NoError(t, err)
	for _, name := range names {
		require.NoError(t, fleet.Add(registry.Sandbox{Name: name, Address: name + ".internal:8722"}))
	}
	return fleet
}

// request builds a tools/call request carrying the given _meta.
func request(meta mcp.Meta) *mcp.CallToolRequest {
	return &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "sandbox_info", Meta: meta}}
}

// TestHandle_IsOpaqueStableAndDistinct. Stability is what lets a handle
// survive a restart with nothing persisted for it; opacity is what stops a
// model from constructing one for a sandbox it was never given.
func TestHandle_IsOpaqueStableAndDistinct(t *testing.T) {
	a := selection.HandleFor("build-box")
	assert.Equal(t, a, selection.HandleFor("build-box"), "the same name must always yield the same handle")
	assert.NotEqual(t, a, selection.HandleFor("gpu-01"))
	assert.NotContains(t, a, "build-box")
	assert.True(t, strings.HasPrefix(a, "sbx_"))
	assert.Len(t, a, len("sbx_")+16)
}

// TestIdentity_DerivationOrder covers the three sources, in precedence order.
func TestIdentity_DerivationOrder(t *testing.T) {
	fleet := newFleet(t)
	resolver := selection.NewResolver(fleet, &selection.Options{FallbackIdentity: "process:test"})

	// 1. The explicit key wins over everything.
	both := request(mcp.Meta{
		selection.MetaKeyClientID:            "session-7",
		"io.modelcontextprotocol/clientInfo": map[string]any{"name": "editor", "version": "1.0.0"},
	})
	assert.Equal(t, selection.Identity("meta:session-7"), resolver.IdentityFor(both))

	// 2. Otherwise the client implementation name, which protocol 2026-07-28
	// carries in _meta.
	info := request(mcp.Meta{
		"io.modelcontextprotocol/clientInfo": map[string]any{"name": "editor", "version": "1.0.0"},
	})
	assert.Equal(t, selection.Identity("client:editor"), resolver.IdentityFor(info))

	// The version is deliberately not part of the identity: upgrading a
	// client must not silently drop its selection.
	upgraded := request(mcp.Meta{
		"io.modelcontextprotocol/clientInfo": map[string]any{"name": "editor", "version": "2.0.0"},
	})
	assert.Equal(t, resolver.IdentityFor(info), resolver.IdentityFor(upgraded))

	// 3. And a request with no identity at all falls back per process.
	assert.Equal(t, selection.Identity("process:test"), resolver.IdentityFor(request(nil)))
	assert.Equal(t, selection.Identity("process:test"), resolver.IdentityFor(nil))
}

// TestIdentity_DefaultFallbackIsPerProcess documents what the fallback
// actually is when nothing overrides it.
func TestIdentity_DefaultFallbackIsPerProcess(t *testing.T) {
	resolver := selection.NewResolver(newFleet(t), nil)
	assert.Equal(t, selection.Identity(fmt.Sprintf("process:%d", os.Getpid())), resolver.IdentityFor(nil))
}

// TestIdentity_IsSanitisedBeforeItBecomesARegistryKey. The value comes from
// the client, unvalidated, and ends up as a key in a YAML file.
func TestIdentity_IsSanitisedBeforeItBecomesARegistryKey(t *testing.T) {
	resolver := selection.NewResolver(newFleet(t), &selection.Options{FallbackIdentity: "process:test"})

	for input, want := range map[string]selection.Identity{
		"  spaced  ":             "meta:spaced",
		"line\nbreak":            "meta:linebreak",
		"tab\tseparated":         "meta:tabseparated",
		strings.Repeat("x", 400): selection.Identity("meta:" + strings.Repeat("x", 128)),
		"":                       "process:test",
		"   ":                    "process:test",
		"\x00\x01":               "process:test",
	} {
		got := resolver.IdentityFor(request(mcp.Meta{selection.MetaKeyClientID: input}))
		assert.Equalf(t, want, got, "identity for %q", input)
	}

	// A non-string value is ignored rather than coerced.
	assert.Equal(t, selection.Identity("process:test"),
		resolver.IdentityFor(request(mcp.Meta{selection.MetaKeyClientID: 42})))
}

// TestResolve_Order is the rule the whole package exists to enforce.
func TestResolve_Order(t *testing.T) {
	fleet := newFleet(t, "build-box", "gpu-01")
	resolver := selection.NewResolver(fleet, nil)
	const alice = selection.Identity("meta:alice")

	// 3. Nothing named and nothing selected.
	_, err := resolver.ResolveFor(alice, "")
	var noTarget *selection.NoTargetError
	require.ErrorAs(t, err, &noTarget)
	assert.Equal(t, []string{"build-box", "gpu-01"}, noTarget.Available)

	// 2. The sticky default.
	_, err = resolver.Select(alice, "build-box")
	require.NoError(t, err)
	target, err := resolver.ResolveFor(alice, "")
	require.NoError(t, err)
	assert.Equal(t, "build-box", target.Name())
	assert.Equal(t, selection.SourceSticky, target.Source)

	// 1. The explicit argument, by name and by handle.
	target, err = resolver.ResolveFor(alice, "gpu-01")
	require.NoError(t, err)
	assert.Equal(t, "gpu-01", target.Name())
	assert.Equal(t, selection.SourceArgument, target.Source)

	target, err = resolver.ResolveFor(alice, selection.HandleFor("gpu-01"))
	require.NoError(t, err)
	assert.Equal(t, "gpu-01", target.Name())

	// Whitespace around a reference is the model's, not the operator's.
	target, err = resolver.ResolveFor(alice, "  gpu-01 ")
	require.NoError(t, err)
	assert.Equal(t, "gpu-01", target.Name())
}

// TestResolve_NeverPicksTheOnlySandbox is the rule that has no exception.
func TestResolve_NeverPicksTheOnlySandbox(t *testing.T) {
	resolver := selection.NewResolver(newFleet(t, "build-box"), nil)

	_, err := resolver.ResolveFor("meta:alice", "")
	var noTarget *selection.NoTargetError
	require.ErrorAs(t, err, &noTarget)
	assert.Contains(t, err.Error(), "sandbox_select")
	assert.Contains(t, err.Error(), "build-box")
}

// TestResolve_UnknownReferenceListsWhatExists.
func TestResolve_UnknownReferenceListsWhatExists(t *testing.T) {
	resolver := selection.NewResolver(newFleet(t, "build-box", "gpu-01"), nil)

	_, err := resolver.ResolveFor("meta:alice", "buildbox")
	var unknown *selection.UnknownSandboxError
	require.ErrorAs(t, err, &unknown)
	assert.Equal(t, "buildbox", unknown.Ref)
	assert.Equal(t, []string{"build-box", "gpu-01"}, unknown.Available)

	// A handle that matches nothing is an unknown reference too, not a
	// crash and not a silent miss.
	_, err = resolver.ResolveFor("meta:alice", selection.HandleFor("never-registered"))
	require.ErrorAs(t, err, &unknown)
}

// TestResolve_ANameShapedLikeAHandleCannotShadowIt.
//
// sandbox_add refuses a name starting with sbx_, but it is not the only way a
// name enters the registry: an enrollment token that reserves no name lets the
// enrolling host choose its own, checked only for length and printable ASCII.
// A host that names itself after another sandbox's handle would then collect
// every call aimed at that handle — the model passing back the opaque reference
// it was handed, and reaching a different machine. Handles therefore win over
// names for a handle-shaped reference.
func TestResolve_ANameShapedLikeAHandleCannotShadowIt(t *testing.T) {
	fleet := newFleet(t, "build-box")

	// What an enrolling host would compute offline and ask to be named.
	impostor := selection.HandleFor("build-box")
	require.NoError(t, fleet.Add(registry.Sandbox{Name: impostor, Address: "impostor.internal:8722"}))

	resolver := selection.NewResolver(fleet, nil)

	target, err := resolver.ResolveFor("meta:alice", impostor)
	require.NoError(t, err)
	assert.Equal(t, "build-box", target.Name(),
		"a handle must reach the sandbox it was minted for, not one merely named after it")
	assert.Equal(t, "build-box.internal:8722", target.Address())

	// A handle-shaped name that shadows nothing stays addressable, so the rule
	// costs a legitimately odd name nothing.
	require.NoError(t, fleet.Add(registry.Sandbox{Name: "sbx_0000000000000000", Address: "odd.internal:8722"}))
	target, err = resolver.ResolveFor("meta:alice", "sbx_0000000000000000")
	require.NoError(t, err)
	assert.Equal(t, "sbx_0000000000000000", target.Name())
}

// TestResolve_StaleSelectionIsItsOwnError so the model is told to re-select
// rather than to fix a name it typed correctly.
func TestResolve_StaleSelectionIsItsOwnError(t *testing.T) {
	fleet := newFleet(t, "build-box", "gpu-01")
	resolver := selection.NewResolver(fleet, nil)
	const alice = selection.Identity("meta:alice")

	_, err := resolver.Select(alice, "gpu-01")
	require.NoError(t, err)
	require.NoError(t, fleet.Remove("gpu-01"))

	_, err = resolver.ResolveFor(alice, "")
	var stale *selection.StaleSelectionError
	require.ErrorAs(t, err, &stale)
	assert.Equal(t, "gpu-01", stale.Name)
	assert.Contains(t, err.Error(), "no longer registered")
	assert.Contains(t, err.Error(), "build-box")
}

// TestErrors_ReadUsefullyOnAnEmptyFleet: with nothing registered, "call
// sandbox_select" is advice the model cannot follow.
func TestErrors_ReadUsefullyOnAnEmptyFleet(t *testing.T) {
	noTarget := (&selection.NoTargetError{}).Error()
	assert.Contains(t, noTarget, "none are registered")
	assert.Contains(t, noTarget, "sandbox_add")
	assert.NotContains(t, noTarget, "Registered: \n")

	unknown := (&selection.UnknownSandboxError{Ref: "build-box"}).Error()
	assert.Contains(t, unknown, "no sandboxes are registered")

	stale := (&selection.StaleSelectionError{Name: "gpu-01"}).Error()
	assert.Contains(t, stale, "sandbox_add")
}

// TestSelection_IsPerIdentityAndPersisted covers the two properties the
// registry file is there for.
func TestSelection_IsPerIdentityAndPersisted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.yaml")

	fleet, err := registry.Open(path)
	require.NoError(t, err)
	require.NoError(t, fleet.Add(registry.Sandbox{Name: "build-box", Address: "build-box.internal:8722"}))
	require.NoError(t, fleet.Add(registry.Sandbox{Name: "gpu-01", Address: "gpu-01.internal:8722"}))

	resolver := selection.NewResolver(fleet, nil)
	_, err = resolver.Select("meta:alice", "build-box")
	require.NoError(t, err)
	_, err = resolver.Select("meta:bob", "gpu-01")
	require.NoError(t, err)

	// A second resolver over a second handle on the same file: what a
	// restarted server sees.
	reopened, err := registry.Open(path)
	require.NoError(t, err)
	restarted := selection.NewResolver(reopened, nil)

	target, err := restarted.ResolveFor("meta:alice", "")
	require.NoError(t, err)
	assert.Equal(t, "build-box", target.Name())

	target, err = restarted.ResolveFor("meta:bob", "")
	require.NoError(t, err)
	assert.Equal(t, "gpu-01", target.Name())

	require.NoError(t, restarted.Clear("meta:alice"))
	_, err = restarted.ResolveFor("meta:alice", "")
	require.Error(t, err)

	target, err = restarted.ResolveFor("meta:bob", "")
	require.NoError(t, err)
	assert.Equal(t, "gpu-01", target.Name(), "clearing one identity must not touch another")
}

// TestSelection_UnderTheProcessFallbackDoesNotOutliveTheProcess.
//
// The fallback identity is "process:<pid>", and pids are reused. Persisting a
// selection under one means an unrelated later process handed the same pid
// silently inherits a target chosen by a session that ended long ago — the
// wrong host, picked implicitly, which is the failure the whole resolution
// order exists to prevent. So it is held in memory and written nowhere.
func TestSelection_UnderTheProcessFallbackDoesNotOutliveTheProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.yaml")
	fleet, err := registry.Open(path)
	require.NoError(t, err)
	require.NoError(t, fleet.Add(registry.Sandbox{Name: "build-box", Address: "build-box.internal:8722"}))
	require.NoError(t, fleet.Add(registry.Sandbox{Name: "gpu-01", Address: "gpu-01.internal:8722"}))

	opts := &selection.Options{FallbackIdentity: "process:4242"}
	first := selection.NewResolver(fleet, opts)
	fallback := first.IdentityFor(nil)
	require.Equal(t, selection.Identity("process:4242"), fallback)

	_, err = first.Select(fallback, "gpu-01")
	require.NoError(t, err)

	// It works for the process that made it.
	target, err := first.ResolveFor(fallback, "")
	require.NoError(t, err)
	assert.Equal(t, "gpu-01", target.Name())

	// It is not in the file...
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "process:4242",
		"a selection with nothing stable to key it to must not be persisted")

	// ...and a later process handed the same pid inherits nothing.
	reopened, err := registry.Open(path)
	require.NoError(t, err)
	second := selection.NewResolver(reopened, opts)
	_, err = second.ResolveFor(second.IdentityFor(nil), "")
	var noTarget *selection.NoTargetError
	require.ErrorAs(t, err, &noTarget,
		"a new process must start with no selection, whatever pid it was handed")

	// An identified client is unaffected: that selection does persist.
	_, err = first.Select("meta:alice", "build-box")
	require.NoError(t, err)
	target, err = second.ResolveFor("meta:alice", "")
	require.NoError(t, err)
	assert.Equal(t, "build-box", target.Name())
}

// TestSelection_APersistedProcessKeyIsNeverInherited is the other half of the
// pid-reuse story, and the half a fresh registry file cannot show.
//
// Not writing the fallback's selection stops one from being created. It does
// not remove the ones already on disk: every registry.yaml written by a build
// from before that fix still carries `process:<pid>` keys, and one of those
// pids will eventually be handed to a new sandboxd-mcp. Resolution must read
// the fallback identity from memory only, so an inherited key is inert rather
// than merely unlikely.
func TestSelection_APersistedProcessKeyIsNeverInherited(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.yaml")
	fleet, err := registry.Open(path)
	require.NoError(t, err)
	require.NoError(t, fleet.Add(registry.Sandbox{Name: "build-box", Address: "build-box.internal:8722"}))
	require.NoError(t, fleet.Add(registry.Sandbox{Name: "gpu-01", Address: "gpu-01.internal:8722"}))

	// Exactly what an older build left behind, under the pid this process was
	// handed — the collision, fabricated.
	pid := fmt.Sprintf("process:%d", os.Getpid())
	require.NoError(t, fleet.SetSelection(pid, "gpu-01"))

	resolver := selection.NewResolver(fleet, nil)
	require.Equal(t, selection.Identity(pid), resolver.IdentityFor(nil),
		"this test is only meaningful if the fallback is the key that was planted")

	_, err = resolver.ResolveFor(resolver.IdentityFor(nil), "")
	var noTarget *selection.NoTargetError
	require.ErrorAs(t, err, &noTarget,
		"a selection left on disk under a recycled pid must not be inherited")

	name, ok, err := resolver.Selected(resolver.IdentityFor(nil))
	require.NoError(t, err)
	assert.False(t, ok, "and it must not be visible as a selection either")
	assert.Empty(t, name)
}

// TestClearSelectionsFor_ReachesTheInMemoryOne. sandbox_remove has to clear
// every selection pointing at the sandbox, and the unidentified client's is
// the one the registry file cannot see.
func TestClearSelectionsFor_ReachesTheInMemoryOne(t *testing.T) {
	fleet := newFleet(t, "build-box", "gpu-01")
	resolver := selection.NewResolver(fleet, &selection.Options{FallbackIdentity: "process:test"})
	const fallback = selection.Identity("process:test")

	_, err := resolver.Select(fallback, "gpu-01")
	require.NoError(t, err)
	_, err = resolver.Select("meta:alice", "gpu-01")
	require.NoError(t, err)
	_, err = resolver.Select("meta:bob", "build-box")
	require.NoError(t, err)

	cleared, err := resolver.ClearSelectionsFor("gpu-01")
	require.NoError(t, err)
	assert.Equal(t, 2, cleared, "both the persisted and the in-memory selection must be counted")

	_, ok, err := resolver.Selected(fallback)
	require.NoError(t, err)
	assert.False(t, ok, "the in-memory selection must be cleared, not left dangling")

	name, ok, err := resolver.Selected("meta:bob")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "build-box", name, "a selection pointing elsewhere must be left alone")
}

// TestSelect_UnknownNameDoesNotRecordASelection: a failed select that still
// moved the default would be worse than one that did nothing.
func TestSelect_UnknownNameDoesNotRecordASelection(t *testing.T) {
	fleet := newFleet(t, "build-box")
	resolver := selection.NewResolver(fleet, nil)
	const alice = selection.Identity("meta:alice")

	_, err := resolver.Select(alice, "build-box")
	require.NoError(t, err)

	_, err = resolver.Select(alice, "does-not-exist")
	require.Error(t, err)

	name, ok, err := resolver.Selected(alice)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "build-box", name, "a failed select must leave the previous one alone")
}

// TestTarget_CarriesEnoughForErrorMapping: a handler should not have to
// restate which host it was talking to when a call fails.
func TestTarget_CarriesEnoughForErrorMapping(t *testing.T) {
	resolver := selection.NewResolver(newFleet(t, "build-box"), nil)
	target, err := resolver.ResolveFor("meta:alice", "build-box")
	require.NoError(t, err)

	assert.Equal(t, "build-box", target.Name())
	assert.Equal(t, "build-box.internal:8722", target.Address())
	assert.Equal(t, selection.HandleFor("build-box"), target.Handle)

	call := target.Call()
	assert.Equal(t, "build-box", call.Sandbox)
	assert.Equal(t, "build-box.internal:8722", call.Address)
}
