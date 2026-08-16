package registry_test

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/registry"
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
