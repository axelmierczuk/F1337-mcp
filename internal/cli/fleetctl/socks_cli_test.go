package fleetctl_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/registry"
)

// `--allow` that narrows nothing is refused to the operator's face.
//
// The rule itself is asserted against ParseAllowList in internal/socks, and
// that is not enough: a rule the command never reaches is a rule an operator
// never meets. Reverting the guard leaves internal/socks red and every test
// under internal/cli green, which is the shape three consecutive rounds on
// PR #54 found — the fix landed in the library and the CLI short-circuited
// ahead of it. So this drives the command, with the flag spelled the way the
// shell spells it when the variable behind it is unset.
func TestSocksCommand_RefusesAnAllowFlagThatNarrowsNothing(t *testing.T) {
	dir := t.TempDir()
	registryPath := filepath.Join(dir, "registry.yaml")
	fleet, err := registry.Open(registryPath)
	require.NoError(t, err)
	require.NoError(t, fleet.Add(registry.Sandbox{
		Name: "build-box",
		// Loopback and closed, so a command that got past the flag and went to
		// the network fails there instead of hanging: this test asserts *which*
		// of the two refused it.
		Address:    "127.0.0.1:1",
		EnrolledAt: time.Now(),
	}))

	// `fleetctl socks build-box --allow "$NARROW"` with NARROW unset. The
	// operator asked for a narrower proxy; the widest one must not be what they
	// get.
	out, code := runCapturingErrors(t, dir, "socks", "build-box", "--allow", "", "--registry", registryPath)
	assert.NotEqual(t, 0, code, out)
	assert.Contains(t, out, "empty",
		"the refusal has to say the entry was empty, not fail somewhere later for another reason")
	assert.NotContains(t, out, "listening on",
		"a proxy must not be opened by a command whose narrowing was refused")

	// The same for an entry that names a port and no host, which builds a rule
	// nothing can match.
	out, code = runCapturingErrors(t, dir, "socks", "build-box", "--allow", ":8080", "--registry", registryPath)
	assert.NotEqual(t, 0, code, out)
	assert.Contains(t, out, "no host")
	assert.NotContains(t, out, "listening on")

	// And the control: an entry that does narrow something gets past the flag
	// and fails at the *next* step instead — this fleet has no CA, so there is
	// nothing to open a connection with. That is what makes the two refusals
	// above about the flag rather than about everything in this fixture
	// failing.
	out, code = runCapturingErrors(t, dir, "socks", "build-box", "--allow", "db.internal", "--registry", registryPath)
	assert.NotEqual(t, 0, code, out)
	assert.NotContains(t, out, "empty")
	assert.NotContains(t, out, "no host")
	assert.Contains(t, out, "fleetctl ca init",
		"a well-formed --allow is accepted, and the command goes on to the material it needs to reach an agent")
}
