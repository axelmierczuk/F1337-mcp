package fleetctl_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The `tui` command's own tests. What it draws is internal/tui's business and
// is tested there; what is here is the two things this file decides — that the
// command exists, and that it refuses to run when there is nothing to draw on.

// TestTUIRefusesWithoutATerminal.
//
// This is the branch every test in this package takes, because the command tree
// these tests build writes to a buffer. A full-screen program whose output is
// not a terminal produces escape sequences and no frames, which reads as a hang
// — so it says so, and names the command that does have machine-readable
// output rather than leaving the reader to find it.
func TestTUIRefusesWithoutATerminal(t *testing.T) {
	dir := t.TempDir()

	out, code := runCapturingErrors(t, dir, "tui")
	require.Equal(t, 1, code, out)
	assert.Contains(t, out, "needs a terminal")
	assert.Contains(t, out, "fleetctl list --json")

	// And it refuses before it touches the CA: an operator on a workstation
	// with no fleet CA at all should be told what is actually wrong, not that
	// they should run `ca init` for a command that could not have run anyway.
	assert.NotContains(t, out, "ca init")
}

// TestTUIIsRegisteredAndSaysWhatItIs. The registration list is the whole
// surface; a command missing from it fails as "unknown command", which is a
// long way from the cause.
func TestTUIIsRegisteredAndSaysWhatItIs(t *testing.T) {
	dir := t.TempDir()

	out, code := run(t, dir, "tui", "--help")
	require.Equal(t, 0, code, out)
	assert.Contains(t, out, "full-screen")
	// The two properties an operator most needs to know before pressing a key
	// in it, both stated in the help rather than discovered.
	assert.Contains(t, out, "asks first, naming the sandbox and the")
	assert.Contains(t, out, "Press ? for the keys")

	// And it is in the root listing, so it can be found without being known.
	out, code = run(t, dir, "--help")
	require.Equal(t, 0, code, out)
	assert.Contains(t, out, "tui")
}

// TestTUIFlagsMatchTheOtherFleetCommands, so an operator who has learned
// --registry, --cert or --timeout on `list` does not have to learn them again.
func TestTUIFlagsMatchTheOtherFleetCommands(t *testing.T) {
	dir := t.TempDir()

	out, code := run(t, dir, "tui", "--help")
	require.Equal(t, 0, code, out)
	for _, flag := range []string{"--ca-dir", "--cert", "--key", "--timeout", "--registry", "--refresh"} {
		assert.Containsf(t, out, flag, "`tui` does not take %s", flag)
	}
}
