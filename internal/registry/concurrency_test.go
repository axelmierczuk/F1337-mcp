package registry_test

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/fsutil"
	"github.com/axelmierczuk/fleet-mcp/internal/registry"
)

// Two Registry handles on one path stand in for two processes: separate
// in-process mutexes, one shared file. The sticky selection is keyed by client
// identity precisely so that several MCP servers can share a config
// directory, so this is a supported configuration, not a pathological one.
//
// Without a cross-process lock, the read-modify-write cycles interleave and
// updates are silently lost — the file stays valid YAML, it just quietly
// forgets sandboxes.
func TestSeparateHandles_ConcurrentAddsAllSurvive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.yaml")

	const writers = 8
	const perWriter = 6

	var wg sync.WaitGroup
	wg.Add(writers)
	for w := 0; w < writers; w++ {
		go func(w int) {
			defer wg.Done()
			// A fresh handle per writer: this is the point of the test.
			reg, err := registry.Open(path)
			if err != nil {
				t.Errorf("open registry: %v", err)
				return
			}
			for i := 0; i < perWriter; i++ {
				name := fmt.Sprintf("sandbox-%d-%d", w, i)
				if err := reg.Add(registry.Sandbox{Name: name, Address: name + ":8722"}); err != nil {
					t.Errorf("add %s: %v", name, err)
				}
			}
		}(w)
	}
	wg.Wait()

	reg, err := registry.Open(path)
	require.NoError(t, err)
	sandboxes, err := reg.List()
	require.NoError(t, err)
	assert.Len(t, sandboxes, writers*perWriter, "every concurrently added sandbox must survive")

	seen := map[string]bool{}
	for _, sb := range sandboxes {
		assert.False(t, seen[sb.Name], "duplicate entry for %s", sb.Name)
		seen[sb.Name] = true
	}
}

// Selections are a map inside the same file, so a lost update there loses one
// client's target rather than a fleet member.
func TestSeparateHandles_ConcurrentSelectionsAllSurvive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.yaml")

	seed, err := registry.Open(path)
	require.NoError(t, err)
	require.NoError(t, seed.Add(registry.Sandbox{Name: "build-box", Address: "build-box:8722"}))

	const clients = 12
	var wg sync.WaitGroup
	wg.Add(clients)
	for c := 0; c < clients; c++ {
		go func(c int) {
			defer wg.Done()
			reg, err := registry.Open(path)
			if err != nil {
				t.Errorf("open registry: %v", err)
				return
			}
			if err := reg.SetSelection(fmt.Sprintf("client-%d", c), "build-box"); err != nil {
				t.Errorf("set selection: %v", err)
			}
		}(c)
	}
	wg.Wait()

	reg, err := registry.Open(path)
	require.NoError(t, err)
	for c := 0; c < clients; c++ {
		name, ok, err := reg.GetSelection(fmt.Sprintf("client-%d", c))
		require.NoError(t, err)
		assert.True(t, ok, "client-%d's selection was lost", c)
		assert.Equal(t, "build-box", name)
	}
}

// Open parses the registry eagerly, and that parse is a read of a file other
// processes replace by rename. It has to happen under the same lock every other
// access takes.
//
// This is asserted directly rather than through a race, because the race only
// bites on Windows: POSIX rename is atomic against a concurrent reader, so an
// unlocked read there is invisible. On Windows a reader's handle carries no
// FILE_SHARE_DELETE, so an overlapping MoveFileEx fails — intermittently, and
// only under load. Holding the lock and requiring Open to wait for it pins the
// invariant on every platform, including the ones that cannot reproduce the
// symptom.
func TestOpen_ParsesUnderTheCrossProcessLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.yaml")
	seed, err := registry.Open(path)
	require.NoError(t, err)
	require.NoError(t, seed.Add(registry.Sandbox{Name: "build-box", Address: "build-box:8722"}))

	// Stand in for a concurrent mutate, which holds this lock across its whole
	// read-modify-write — the rename included.
	release, err := fsutil.Lock(path)
	require.NoError(t, err)

	opened := make(chan error, 1)
	go func() {
		_, err := registry.Open(path)
		opened <- err
	}()

	select {
	case err := <-opened:
		t.Fatalf("Open returned (err=%v) while the registry lock was held; "+
			"its eager parse reads outside the lock and so races WriteAtomic's rename", err)
	case <-time.After(250 * time.Millisecond):
	}

	require.NoError(t, release())
	select {
	case err := <-opened:
		require.NoError(t, err, "Open must succeed once the lock is free")
	case <-time.After(10 * time.Second):
		t.Fatal("Open never completed after the lock was released")
	}
}

// The shape the CI failure actually took: handles being opened while other
// handles write. On Windows this is where the sharing violation lands, and a
// caller whose Open failed never makes the write it opened the registry to
// make — which reads downstream as a lost update, in a registry that never lost
// one.
func TestSeparateHandles_OpenConcurrentWithWritesAlwaysSucceeds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.yaml")
	seed, err := registry.Open(path)
	require.NoError(t, err)
	require.NoError(t, seed.Add(registry.Sandbox{Name: "build-box", Address: "build-box:8722"}))

	const workers = 12
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 8; i++ {
				reg, err := registry.Open(path)
				if err != nil {
					t.Errorf("worker %d: open registry: %v", w, err)
					return
				}
				if err := reg.SetSelection(fmt.Sprintf("client-%d-%d", w, i), "build-box"); err != nil {
					t.Errorf("worker %d: set selection: %v", w, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	reg, err := registry.Open(path)
	require.NoError(t, err)
	for w := 0; w < workers; w++ {
		for i := 0; i < 8; i++ {
			name, ok, err := reg.GetSelection(fmt.Sprintf("client-%d-%d", w, i))
			require.NoError(t, err)
			assert.True(t, ok, "client-%d-%d's selection was lost", w, i)
			assert.Equal(t, "build-box", name)
		}
	}
}

// Exists backs the enrollment collision check, so its failure direction
// matters: an unknown name is free, anything else is treated as taken.
func TestExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.yaml")
	reg, err := registry.Open(path)
	require.NoError(t, err)
	require.NoError(t, reg.Add(registry.Sandbox{Name: "build-box", Address: "build-box:8722"}))

	assert.True(t, reg.Exists("build-box"))
	assert.False(t, reg.Exists("not-a-sandbox"))
}
