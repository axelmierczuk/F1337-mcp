package fleetctl

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver/selection"
	"github.com/axelmierczuk/fleet-mcp/internal/registry"
)

// The resolution order itself, asserted against resolveTarget.
//
// It cannot be driven through `fleetctl shell` from a test process: the command
// refuses before it resolves anything when stdin is not a terminal, and a
// `go test` binary's stdin never is. What is asserted here is the order and the
// advice; that the command uses this function rather than a second order of its
// own is a one-line call in shell.go.

// fleetAt writes a registry holding the named sandboxes and returns its path.
func fleetAt(t *testing.T, names ...string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "registry.yaml")
	fleet, err := registry.Open(path)
	require.NoError(t, err)
	for i, name := range names {
		require.NoError(t, fleet.Add(registry.Sandbox{
			Name:    name,
			Address: fmt.Sprintf("127.0.0.1:%d", 9000+i),
		}))
	}
	return path
}

// TestResolveTarget_ExplicitArgumentWins is the first rule.
func TestResolveTarget_ExplicitArgumentWins(t *testing.T) {
	path := fleetAt(t, "build-box", "gpu-01")

	res, err := resolver(path)
	require.NoError(t, err)
	_, err = res.Select(cliIdentity, "build-box")
	require.NoError(t, err)

	target, err := resolveTarget(path, "gpu-01")
	require.NoError(t, err)
	assert.Equal(t, "gpu-01", target.Name(), "an explicit argument has to beat the sticky selection")
	assert.Equal(t, selection.SourceArgument, target.Source)

	// And it does not move the selection: naming a host for one command is not
	// choosing it for the next.
	after, err := resolveTarget(path, "")
	require.NoError(t, err)
	assert.Equal(t, "build-box", after.Name())
}

// TestResolveTarget_FallsBackToTheStickySelection is the second rule.
func TestResolveTarget_FallsBackToTheStickySelection(t *testing.T) {
	path := fleetAt(t, "build-box", "gpu-01")

	res, err := resolver(path)
	require.NoError(t, err)
	_, err = res.Select(cliIdentity, "gpu-01")
	require.NoError(t, err)

	target, err := resolveTarget(path, "")
	require.NoError(t, err)
	assert.Equal(t, "gpu-01", target.Name())
	assert.Equal(t, selection.SourceSticky, target.Source)
}

// TestResolveTarget_AHandleResolvesToItsSandbox: the opaque reference the MCP
// tools hand a model works here too, so an operator can paste one from a tool
// result into a command.
func TestResolveTarget_AHandleResolvesToItsSandbox(t *testing.T) {
	path := fleetAt(t, "build-box")

	target, err := resolveTarget(path, selection.HandleFor("build-box"))
	require.NoError(t, err)
	assert.Equal(t, "build-box", target.Name())
}

// TestResolveTarget_RefusesToGuessWithOneSandboxEnrolled is the third rule, and
// the rule that is deliberately absent.
//
// A fleet of exactly one does not resolve implicitly. Implicit targeting is how
// the wrong host gets written to, and a fleet grows from one to two without
// anybody revisiting the commands written while it had one member.
func TestResolveTarget_RefusesToGuessWithOneSandboxEnrolled(t *testing.T) {
	path := fleetAt(t, "build-box")

	_, err := resolveTarget(path, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no sandbox selected")
	assert.Contains(t, err.Error(), "fleetctl select build-box", "the advice has to name a command an operator can run")
	assert.NotContains(t, err.Error(), "fleet_select", "an operator at a terminal cannot call an MCP tool")
}

func TestResolveTarget_UnknownNameIsAnsweredWithTheOnesThatExist(t *testing.T) {
	path := fleetAt(t, "build-box", "gpu-01")

	_, err := resolveTarget(path, "typo-box")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "typo-box")
	assert.Contains(t, err.Error(), "build-box")
	assert.Contains(t, err.Error(), "gpu-01")
}

// TestResolveTarget_AStaleSelectionSaysSoRatherThanReadingAsATypo: the operator
// did nothing wrong and the fix is different — re-select, do not correct a
// spelling.
func TestResolveTarget_AStaleSelectionSaysSoRatherThanReadingAsATypo(t *testing.T) {
	path := fleetAt(t, "build-box", "gpu-01")

	res, err := resolver(path)
	require.NoError(t, err)
	_, err = res.Select(cliIdentity, "gpu-01")
	require.NoError(t, err)
	require.NoError(t, res.Registry().Remove("gpu-01"))

	_, err = resolveTarget(path, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no longer enrolled")
	assert.Contains(t, err.Error(), "gpu-01")
}

// TestResolveTarget_EmptyFleetPointsAtEnrollment: the answer to "no sandbox
// selected" on a machine with nothing enrolled is not "select one".
func TestResolveTarget_EmptyFleetPointsAtEnrollment(t *testing.T) {
	path := fleetAt(t)

	_, err := resolveTarget(path, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "none are enrolled")
	assert.Contains(t, err.Error(), "fleetctl enroll mint")
}

// TestCLISelectionIsItsOwn: fleetctl's sticky default is keyed to fleetctl, not
// borrowed from whichever MCP client last chose something.
//
// Selections are per client identity by design — an editor and a terminal hold
// different ones — and a CLI that read another client's would send an
// operator's shell to whichever host a model happened to be working on.
func TestCLISelectionIsItsOwn(t *testing.T) {
	path := fleetAt(t, "build-box", "gpu-01")

	res, err := resolver(path)
	require.NoError(t, err)

	// A model, through the MCP server, selects one host.
	_, err = res.Select(selection.Identity("client:some-editor"), "gpu-01")
	require.NoError(t, err)

	// The CLI still has none, and says so rather than inheriting it.
	_, err = resolveTarget(path, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no sandbox selected")

	// And choosing one here does not move the model's.
	_, err = res.Select(cliIdentity, "build-box")
	require.NoError(t, err)
	name, ok, err := res.Selected(selection.Identity("client:some-editor"))
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "gpu-01", name)
}
