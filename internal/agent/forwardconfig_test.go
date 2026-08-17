package agent_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/agent"
)

// The forward section's defaults are a security decision, not a convenience:
// an empty allowed_hosts is what keeps an agent from being a general-purpose
// network pivot, and it has to stay empty on a config that never mentions it.

func TestForwardConfig_DefaultsAreLoopbackOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
listen: "0.0.0.0:8722"
tls:
  certificate: "agent.crt"
  private_key: "agent.key"
  ca_bundle: "ca.crt"
`), 0o600))

	cfg, err := agent.Load(path)
	require.NoError(t, err)

	assert.True(t, cfg.Forward.IsEnabled(), "forwarding to loopback is on by default; it is what closes the dev loop")
	assert.Empty(t, cfg.Forward.AllowedHosts,
		"a config that never mentions forwarding must not permit a non-loopback target")
	assert.False(t, cfg.Forward.HostAllowed("10.0.0.1"))
	assert.Equal(t, 64, cfg.Forward.MaxConnections)
	assert.Equal(t, 10*time.Second, cfg.Forward.DialTimeout.Duration())
}

func TestForwardConfig_CanBeTurnedOff(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
listen: "0.0.0.0:8722"
tls:
  certificate: "agent.crt"
  private_key: "agent.key"
  ca_bundle: "ca.crt"
forward:
  enabled: false
`), 0o600))

	cfg, err := agent.Load(path)
	require.NoError(t, err)
	// A plain bool could not tell this from a key nobody wrote, which is why
	// the field is a pointer.
	assert.False(t, cfg.Forward.IsEnabled())
}

func TestForwardConfig_AllowedHostsAreMatchedCaseInsensitively(t *testing.T) {
	cfg := agent.ForwardConfig{AllowedHosts: []string{"Build-Host.Internal", " 10.0.4.7 "}}
	assert.True(t, cfg.HostAllowed("build-host.internal"))
	assert.True(t, cfg.HostAllowed("BUILD-HOST.INTERNAL"))
	assert.True(t, cfg.HostAllowed("10.0.4.7"))
	assert.False(t, cfg.HostAllowed("build-host.internal.evil.test"),
		"the match is on the whole host, not a prefix")
	assert.False(t, cfg.HostAllowed(""))
}

// The shipped example documents the forward section; this is what stops it
// drifting from what the code accepts.
func TestForwardConfig_ShippedExampleParses(t *testing.T) {
	path, err := filepath.Abs(filepath.Join("..", "..", "examples", "agent.yaml"))
	require.NoError(t, err)

	cfg, err := agent.Load(path)
	require.NoError(t, err)
	assert.True(t, cfg.Forward.IsEnabled())
	assert.Empty(t, cfg.Forward.AllowedHosts)
	assert.Equal(t, 64, cfg.Forward.MaxConnections)
	assert.Equal(t, 10*time.Second, cfg.Forward.DialTimeout.Duration())
}
