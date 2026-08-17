package agent_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/agent"
)

// legacySystemDirs are the pre-rebrand machine-wide directories for this
// platform — the ones internal/legacypath falls back to when they hold
// something and the new ones do not.
func legacySystemDirs() []string {
	switch runtime.GOOS {
	case "windows":
		dir := os.Getenv("ProgramData")
		if dir == "" {
			dir = `C:\ProgramData`
		}
		return []string{filepath.Join(dir, "sandboxd")}
	case "darwin":
		return []string{
			"/Library/Application Support/sandboxd",
			"/Library/Logs/sandboxd",
		}
	default:
		return []string{"/etc/sandboxd", "/var/lib/sandboxd", "/var/log/sandboxd"}
	}
}

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
	// This asserts the fresh-install branch, so it only means anything on a
	// machine that has nothing to fall back to. A developer box actually
	// running a pre-rebrand agent would legitimately resolve to the old paths,
	// and failing there would be the test reporting the compatibility path
	// working as designed.
	for _, legacy := range legacySystemDirs() {
		if entries, err := os.ReadDir(legacy); err == nil && len(entries) > 0 {
			t.Skipf("this machine has a pre-rebrand install at %s, so these resolve to it by design", legacy)
		}
	}

	// Asserting on the substring rather than the whole path keeps this true
	// across the three platforms' different roots.
	assert.Contains(t, agent.SystemConfigDir(), "fleet")
	assert.NotContains(t, agent.SystemConfigDir(), "sandboxd")
	assert.Contains(t, agent.DefaultStateDir(), "fleet")
	assert.NotContains(t, agent.DefaultStateDir(), "sandboxd")
	assert.Contains(t, agent.DefaultLogDir(), "fleet")
	assert.NotContains(t, agent.DefaultLogDir(), "sandboxd")
}
