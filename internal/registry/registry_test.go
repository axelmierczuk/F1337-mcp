package registry_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/registry"
)

func newTestRegistry(t *testing.T) (*registry.Registry, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.yaml")
	r, err := registry.Open(path)
	require.NoError(t, err)
	return r, path
}

func TestConfigDir(t *testing.T) {
	t.Run("explicit override wins", func(t *testing.T) {
		t.Setenv("SANDBOXD_CONFIG_DIR", "/custom/config")
		dir, err := registry.ConfigDir()
		require.NoError(t, err)
		assert.Equal(t, "/custom/config", dir)
	})

	t.Run("falls back to home when nothing set", func(t *testing.T) {
		t.Setenv("SANDBOXD_CONFIG_DIR", "")
		t.Setenv("XDG_CONFIG_HOME", "")
		t.Setenv("APPDATA", "")
		dir, err := registry.ConfigDir()
		require.NoError(t, err)
		assert.NotEmpty(t, dir)
		assert.Contains(t, dir, "sandboxd")
	})
}

func TestRoundTrip_AllFieldsSurvive(t *testing.T) {
	r, path := newTestRegistry(t)

	now := time.Now().UTC().Truncate(time.Second)
	sandboxes := []registry.Sandbox{
		{
			Name:    "build-box",
			Address: "10.0.0.1:8722",
			Labels:  map[string]string{"arch": "amd64", "role": "build"},
			Platform: registry.Platform{
				OS: "linux", Arch: "amd64", KernelVersion: "6.1.0", Hostname: "build-box", PathSeparator: "/",
			},
			EnrolledAt:   now,
			LastSeenAt:   now.Add(time.Minute),
			AgentVersion: "0.1.0",
		},
		{
			Name:       "mac-mini",
			Address:    "10.0.0.2:8722",
			Labels:     map[string]string{"arch": "arm64"},
			EnrolledAt: now,
		},
		{
			Name:       "test-rig",
			Address:    "10.0.0.3:8722",
			EnrolledAt: now,
		},
	}
	for _, sb := range sandboxes {
		require.NoError(t, r.Add(sb))
	}

	// Reload from disk with a fresh Registry handle.
	reloaded, err := registry.Open(path)
	require.NoError(t, err)

	got, err := reloaded.List()
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, sandboxes, got)
}

func TestAdd_DuplicateNameFails(t *testing.T) {
	r, _ := newTestRegistry(t)
	require.NoError(t, r.Add(registry.Sandbox{Name: "a", Address: "x:1"}))
	err := r.Add(registry.Sandbox{Name: "a", Address: "y:2"})
	require.ErrorIs(t, err, registry.ErrExists)
}

func TestAdd_RequiresName(t *testing.T) {
	r, _ := newTestRegistry(t)
	err := r.Add(registry.Sandbox{Address: "x:1"})
	require.Error(t, err)
}

func TestGet_NotFound(t *testing.T) {
	r, _ := newTestRegistry(t)
	_, err := r.Get("missing")
	require.ErrorIs(t, err, registry.ErrNotFound)
}

func TestRemove(t *testing.T) {
	r, _ := newTestRegistry(t)
	require.NoError(t, r.Add(registry.Sandbox{Name: "a", Address: "x:1"}))
	require.NoError(t, r.Add(registry.Sandbox{Name: "b", Address: "y:2"}))

	require.NoError(t, r.Remove("a"))

	_, err := r.Get("a")
	require.ErrorIs(t, err, registry.ErrNotFound)

	got, err := r.List()
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "b", got[0].Name)
}

func TestRemove_NotFound(t *testing.T) {
	r, _ := newTestRegistry(t)
	err := r.Remove("missing")
	require.ErrorIs(t, err, registry.ErrNotFound)
}

func TestUpdateLastSeen(t *testing.T) {
	r, _ := newTestRegistry(t)
	require.NoError(t, r.Add(registry.Sandbox{Name: "a", Address: "x:1"}))

	seen := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, r.UpdateLastSeen("a", seen))

	got, err := r.Get("a")
	require.NoError(t, err)
	assert.Equal(t, seen, got.LastSeenAt)
}

func TestUpdateHostInfo(t *testing.T) {
	r, _ := newTestRegistry(t)
	require.NoError(t, r.Add(registry.Sandbox{Name: "a", Address: "x:1"}))

	platform := registry.Platform{OS: "darwin", Arch: "arm64"}
	require.NoError(t, r.UpdateHostInfo("a", platform, "0.2.0"))

	got, err := r.Get("a")
	require.NoError(t, err)
	assert.Equal(t, platform, got.Platform)
	assert.Equal(t, "0.2.0", got.AgentVersion)
}

func TestSelection_PersistsAcrossRestart(t *testing.T) {
	r, path := newTestRegistry(t)
	require.NoError(t, r.SetSelection("client-1", "build-box"))

	reloaded, err := registry.Open(path)
	require.NoError(t, err)

	name, ok, err := reloaded.GetSelection("client-1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "build-box", name)
}

func TestSelection_IndependentPerClient(t *testing.T) {
	r, _ := newTestRegistry(t)
	require.NoError(t, r.SetSelection("client-1", "build-box"))
	require.NoError(t, r.SetSelection("client-2", "mac-mini"))

	name1, ok1, err := r.GetSelection("client-1")
	require.NoError(t, err)
	require.True(t, ok1)
	assert.Equal(t, "build-box", name1)

	name2, ok2, err := r.GetSelection("client-2")
	require.NoError(t, err)
	require.True(t, ok2)
	assert.Equal(t, "mac-mini", name2)

	// Changing one client's selection must not affect the other's.
	require.NoError(t, r.SetSelection("client-1", "test-rig"))
	name2Again, _, err := r.GetSelection("client-2")
	require.NoError(t, err)
	assert.Equal(t, "mac-mini", name2Again)
}

func TestSelection_Unset(t *testing.T) {
	r, _ := newTestRegistry(t)
	_, ok, err := r.GetSelection("nobody")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestSelection_Clear(t *testing.T) {
	r, _ := newTestRegistry(t)
	require.NoError(t, r.SetSelection("client-1", "build-box"))
	require.NoError(t, r.ClearSelection("client-1"))

	_, ok, err := r.GetSelection("client-1")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestMalformedFile_ClearErrorNamingPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.yaml")
	require.NoError(t, os.WriteFile(path, []byte("not: valid: yaml: [unterminated"), 0o600))

	_, err := registry.Open(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), path)
}

func TestTruncatedFile_DoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.yaml")
	require.NoError(t, os.WriteFile(path, []byte("version: 1\nsandboxes:\n  - name: a\n    addr"), 0o600))

	assert.NotPanics(t, func() {
		_, _ = registry.Open(path)
	})
}

func TestEmptyFile_TreatedAsEmptyRegistry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.yaml")
	require.NoError(t, os.WriteFile(path, []byte(""), 0o600))

	r, err := registry.Open(path)
	require.NoError(t, err)
	got, err := r.List()
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestConcurrentWriters_DoNotCorruptFile(t *testing.T) {
	r, path := newTestRegistry(t)

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			err := r.Add(registry.Sandbox{
				Name:    sandboxName(i),
				Address: "10.0.0.1:8722",
			})
			assert.NoError(t, err)
		}(i)
	}
	wg.Wait()

	// The file must still be a single, well-formed document...
	reloaded, err := registry.Open(path)
	require.NoError(t, err)

	// ...and every writer's sandbox must have survived: the in-process mutex
	// serializes the read-modify-write cycle, so no update is lost even
	// though every goroutine raced to read-modify-write the same file.
	got, err := reloaded.List()
	require.NoError(t, err)
	assert.Len(t, got, n)

	seen := map[string]bool{}
	for _, sb := range got {
		seen[sb.Name] = true
	}
	for i := 0; i < n; i++ {
		assert.True(t, seen[sandboxName(i)], "missing sandbox %s", sandboxName(i))
	}
}

func TestConcurrentSelections_DoNotCorruptFile(t *testing.T) {
	r, _ := newTestRegistry(t)

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			err := r.SetSelection(sandboxName(i), "build-box")
			assert.NoError(t, err)
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		name, ok, err := r.GetSelection(sandboxName(i))
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, "build-box", name)
	}
}

func TestFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	r, path := newTestRegistry(t)
	require.NoError(t, r.Add(registry.Sandbox{Name: "a", Address: "x:1"}))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func sandboxName(i int) string {
	return "sandbox-" + strconv.Itoa(i)
}
