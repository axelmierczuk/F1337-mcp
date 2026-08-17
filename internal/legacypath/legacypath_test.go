package legacypath_test

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/legacypath"
)

// captureLogs points the default logger at a buffer for the duration of the
// test and clears the once-per-process warning state, so a test can observe a
// notice an earlier one already tripped.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	legacypath.ResetWarningsForTest()
	buf := &bytes.Buffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() {
		slog.SetDefault(previous)
		legacypath.ResetWarningsForTest()
	})
	return buf
}

func TestEnv(t *testing.T) {
	t.Run("new name wins", func(t *testing.T) {
		logs := captureLogs(t)
		t.Setenv("FLEET_TEST_VAR", "/new")
		t.Setenv("SANDBOXD_TEST_VAR", "/old")

		assert.Equal(t, "/new", legacypath.Env("FLEET_TEST_VAR", "SANDBOXD_TEST_VAR"))
		assert.Empty(t, logs.String(), "the new name is the supported one; using it is not worth a warning")
	})

	t.Run("falls back to the deprecated name and says so once", func(t *testing.T) {
		logs := captureLogs(t)
		t.Setenv("FLEET_TEST_VAR", "")
		t.Setenv("SANDBOXD_TEST_VAR", "/old")

		assert.Equal(t, "/old", legacypath.Env("FLEET_TEST_VAR", "SANDBOXD_TEST_VAR"))
		assert.Contains(t, logs.String(), "SANDBOXD_TEST_VAR")
		assert.Contains(t, logs.String(), "FLEET_TEST_VAR", "the notice has to name the replacement, or it is not actionable")

		// Resolvers are called per request. One notice per process, not per call.
		before := logs.Len()
		for range 5 {
			assert.Equal(t, "/old", legacypath.Env("FLEET_TEST_VAR", "SANDBOXD_TEST_VAR"))
		}
		assert.Equal(t, before, logs.Len(), "the deprecation notice must not repeat on every lookup")
	})

	t.Run("neither set", func(t *testing.T) {
		captureLogs(t)
		t.Setenv("FLEET_TEST_VAR", "")
		t.Setenv("SANDBOXD_TEST_VAR", "")
		assert.Empty(t, legacypath.Env("FLEET_TEST_VAR", "SANDBOXD_TEST_VAR"))
	})
}

func TestDir(t *testing.T) {
	// populated builds a directory with something in it, which is what makes
	// Dir prefer it.
	populated := func(t *testing.T, path string) string {
		t.Helper()
		require.NoError(t, os.MkdirAll(path, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(path, "registry.yaml"), []byte("sandboxes: []\n"), 0o600))
		return path
	}

	t.Run("new directory has contents", func(t *testing.T) {
		logs := captureLogs(t)
		root := t.TempDir()
		newDir := populated(t, filepath.Join(root, "fleet"))
		oldDir := populated(t, filepath.Join(root, "sandboxd"))

		assert.Equal(t, newDir, legacypath.Dir(newDir, oldDir))
		assert.Empty(t, logs.String())
	})

	t.Run("only the pre-rebrand directory has contents", func(t *testing.T) {
		logs := captureLogs(t)
		root := t.TempDir()
		newDir := filepath.Join(root, "fleet")
		oldDir := populated(t, filepath.Join(root, "sandboxd"))

		assert.Equal(t, oldDir, legacypath.Dir(newDir, oldDir))
		assert.Contains(t, logs.String(), oldDir)
		assert.Contains(t, logs.String(), newDir, "the notice has to name where to move it to")
	})

	// The failure this package exists to prevent: an empty new directory beside
	// a populated old one resolving to the empty one, so an operator with a
	// fully enrolled fleet is told they have none.
	t.Run("an empty new directory does not strand a populated old one", func(t *testing.T) {
		captureLogs(t)
		root := t.TempDir()
		newDir := filepath.Join(root, "fleet")
		require.NoError(t, os.MkdirAll(newDir, 0o700))
		oldDir := populated(t, filepath.Join(root, "sandboxd"))

		assert.Equal(t, oldDir, legacypath.Dir(newDir, oldDir),
			"an empty new directory must not hide a populated old one")
	})

	t.Run("a fresh install starts on the new name", func(t *testing.T) {
		logs := captureLogs(t)
		root := t.TempDir()
		newDir := filepath.Join(root, "fleet")
		oldDir := filepath.Join(root, "sandboxd")

		assert.Equal(t, newDir, legacypath.Dir(newDir, oldDir))
		assert.Empty(t, logs.String(), "a host with neither directory has nothing to migrate")
	})

	t.Run("a plain file where a directory should be is not contents", func(t *testing.T) {
		captureLogs(t)
		root := t.TempDir()
		newDir := filepath.Join(root, "fleet")
		oldDir := filepath.Join(root, "sandboxd")
		require.NoError(t, os.WriteFile(oldDir, []byte("not a directory"), 0o600))

		assert.Equal(t, newDir, legacypath.Dir(newDir, oldDir))
	})
}
