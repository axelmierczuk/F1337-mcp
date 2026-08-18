package fleetctl_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/registry"
)

// Which sandbox a command acts on.
//
// The order is the selection package's — explicit argument, then the sticky
// selection, then a structured error — and these assert that `fleetctl` uses it
// rather than growing a second one. The rule that matters most is the one that
// is not there: a fleet holding exactly one sandbox still refuses to resolve
// implicitly, because implicit targeting is how the wrong host gets a shell.

// enrolled writes a registry with the named sandboxes, as `fleetctl enroll`
// would have left it.
func enrolled(t *testing.T, dir string, names ...string) *registry.Registry {
	t.Helper()

	fleet, err := registry.Open(filepath.Join(dir, "registry.yaml"))
	require.NoError(t, err)
	for i, name := range names {
		require.NoError(t, fleet.Add(registry.Sandbox{
			Name:    name,
			Address: "127.0.0.1:" + itoa(9000+i),
		}))
	}
	return fleet
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func TestSelect_RecordsAndReportsTheStickyTarget(t *testing.T) {
	dir := t.TempDir()
	enrolled(t, dir, "build-box", "gpu-01")

	out, code := run(t, dir, "select")
	require.Equal(t, 0, code, out)
	assert.Contains(t, out, "nothing selected")

	out, code = run(t, dir, "select", "gpu-01")
	require.Equal(t, 0, code, out)
	assert.Contains(t, out, "selected gpu-01")

	out, code = run(t, dir, "select", "--json")
	require.Equal(t, 0, code, out)
	assert.Contains(t, out, `"name": "gpu-01"`)
	assert.Contains(t, out, `"selected": true`)
}

// TestSelect_RefusesASandboxThatIsNotEnrolled checks that the advice an
// operator gets names what they can act on rather than the MCP tool a model
// would call.
func TestSelect_RefusesASandboxThatIsNotEnrolled(t *testing.T) {
	dir := t.TempDir()
	enrolled(t, dir, "build-box")

	out, code := runCapturingErrors(t, dir, "select", "typo-box")
	assert.NotEqual(t, 0, code)
	assert.Contains(t, out, "typo-box")
	assert.Contains(t, out, "build-box", "an unknown name has to be answered with the names that do exist")
	assert.NotContains(t, out, "fleet_select", "an operator at a terminal cannot call an MCP tool")
}

// TestSelect_ReportsASelectionWhoseSandboxIsGone: a selection pointing at a
// removed sandbox is reported as no selection, not as an error. The operator
// asked what is selected, and "that host is gone" is the answer.
func TestSelect_ReportsASelectionWhoseSandboxIsGone(t *testing.T) {
	dir := t.TempDir()
	fleet := enrolled(t, dir, "build-box")

	_, code := run(t, dir, "select", "build-box")
	require.Equal(t, 0, code)

	require.NoError(t, fleet.Remove("build-box"))

	out, code := run(t, dir, "select")
	require.Equal(t, 0, code, out)
	assert.Contains(t, out, "no longer enrolled")
}

// TestShell_RefusesWhenStdinIsNotATerminal is the check that keeps an
// interactive command out of a script.
//
// A shell whose input is a pipe cannot be driven: the far end sits at a prompt
// nobody can answer until the agent's idle timeout reaps it. The message names
// the tool that runs a command and collects its output, because that is what
// the caller wanted.
//
// The test binary's own stdin is not a terminal, which is what makes this
// assertable without a pty: `go test` gives it /dev/null.
func TestShell_RefusesWhenStdinIsNotATerminal(t *testing.T) {
	dir := t.TempDir()
	enrolled(t, dir, "build-box")

	out, code := runCapturingErrors(t, dir, "shell", "build-box")
	assert.NotEqual(t, 0, code)
	assert.Contains(t, out, "not a terminal")
	assert.Contains(t, out, "fleet_exec")
}

// TestShell_RefusesMoreThanOneSandbox keeps `fleetctl shell box ls` from being
// read as a command to run: a command goes after `--`, and silently treating a
// second argument as one would run something the operator did not ask for.
func TestShell_RefusesMoreThanOneSandbox(t *testing.T) {
	dir := t.TempDir()
	enrolled(t, dir, "build-box", "gpu-01")

	out, code := runCapturingErrors(t, dir, "shell", "build-box", "gpu-01")
	assert.NotEqual(t, 0, code)
	assert.Contains(t, out, "at most one sandbox name")
}

// The rest of the resolution order is asserted in target_internal_test.go,
// against resolveTarget itself. It cannot be driven through the command from a
// test process: `fleetctl shell` refuses before it resolves anything when stdin
// is not a terminal, and a `go test` binary's stdin never is. The order of
// those two checks is deliberate — a session that could not be driven fails for
// that reason whatever it was aimed at — and the test above is what pins it.
