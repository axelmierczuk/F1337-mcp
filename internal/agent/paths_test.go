package agent_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/agent"
)

// TestDefaultConfigPath_LegacyEnv covers the upgrade path the fleet rebrand
// created: a service unit written by a pre-rebrand agent passes the config
// path in SANDBOXD_AGENT_CONFIG, and that unit is not rewritten until
// `fleet-agent service install` runs again. An agent that ignored the old
// variable would go looking for a config it was handed the path to.
func TestDefaultConfigPath_LegacyEnv(t *testing.T) {
	t.Run("the new variable is used", func(t *testing.T) {
		t.Setenv(agent.EnvConfig, "/new/agent.yaml")
		t.Setenv(agent.LegacyEnvConfig, "")
		path, err := agent.DefaultConfigPath()
		require.NoError(t, err)
		assert.Equal(t, "/new/agent.yaml", path)
	})

	t.Run("the deprecated variable is still honoured", func(t *testing.T) {
		t.Setenv(agent.EnvConfig, "")
		t.Setenv(agent.LegacyEnvConfig, "/legacy/agent.yaml")
		path, err := agent.DefaultConfigPath()
		require.NoError(t, err)
		assert.Equal(t, "/legacy/agent.yaml", path)
	})

	t.Run("the new variable wins when both are set", func(t *testing.T) {
		t.Setenv(agent.EnvConfig, "/new/agent.yaml")
		t.Setenv(agent.LegacyEnvConfig, "/legacy/agent.yaml")
		path, err := agent.DefaultConfigPath()
		require.NoError(t, err)
		assert.Equal(t, "/new/agent.yaml", path)
	})
}

// TestSystemPathsAreOnTheNewName guards the direction of the rename: these
// resolve to the pre-rebrand path only when it actually holds something, and
// on a machine with neither they must name the new one. A regression here
// would have every fresh install writing to /etc/sandboxd again.
func TestSystemPathsAreOnTheNewName(t *testing.T) {
	// No pre-rebrand directory exists on a CI runner, so these take the
	// new-name branch. Asserting on the substring rather than the whole path
	// keeps this true across the three platforms' different roots.
	assert.Contains(t, agent.SystemConfigDir(), "fleet")
	assert.NotContains(t, agent.SystemConfigDir(), "sandboxd")
	assert.Contains(t, agent.DefaultStateDir(), "fleet")
	assert.NotContains(t, agent.DefaultStateDir(), "sandboxd")
	assert.Contains(t, agent.DefaultLogDir(), "fleet")
	assert.NotContains(t, agent.DefaultLogDir(), "sandboxd")
}
