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
// created: an operator who exported SANDBOXD_AGENT_CONFIG in a shell profile, a
// CI job or a container image gets no signal from the rename, so an agent that
// ignored the old variable would silently go looking for a config it was handed
// the path to. (The installed service units never used either variable — all
// three pass `serve --config` in argv — so this is about hand-set environments.)
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

// TestNestedDirsFollowTheResolvedConfigDir is the other half of the migration
// rule, and the half a fresh CI machine cannot see: on the platforms where the
// state and log directories live *inside* the config directory, they have to
// come off the same resolution rather than repeating it.
//
// Resolving them separately lets them disagree on a host that enrolled before
// the rebrand, and the disagreement is self-inflicting. The supervisor creates
// <state>/processes on every start. If the state directory resolved to the new
// name while the config directory resolved to the old one — which happens on
// macOS whenever the pre-rebrand state directory is empty or absent — that
// mkdir puts contents in the new *config* directory, and the next call to
// SystemConfigDir prefers it. The agent then looks for agent.yaml under a name
// nothing wrote it to, with the real enrollment intact a few characters away.
//
// The pinned value stands in for "whichever name this host resolved to"; both
// branches are compiled-in absolute roots on macOS, so there is no other way to
// arrange for the two to differ.
func TestNestedDirsFollowTheResolvedConfigDir(t *testing.T) {
	resolved := filepath.Join(t.TempDir(), "sandboxd")
	restore := agent.PinSystemConfigDirForTest(resolved)
	t.Cleanup(restore)

	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		assert.Equal(t, filepath.Join(resolved, "state"), agent.DefaultStateDir(),
			"state nests inside the config directory here, so it must follow the name that directory resolved to")
	} else {
		assert.NotContains(t, agent.DefaultStateDir(), resolved,
			"Linux keeps state under its own root, so it does not follow the config directory")
	}

	// Logs nest on Windows only; macOS puts them under /Library/Logs, which is
	// its own root and so resolves independently by design.
	if runtime.GOOS == "windows" {
		assert.Equal(t, filepath.Join(resolved, "logs"), agent.DefaultLogDir())
	} else {
		assert.NotContains(t, agent.DefaultLogDir(), resolved)
	}
}
