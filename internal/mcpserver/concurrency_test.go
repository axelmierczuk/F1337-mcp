package mcpserver_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/mcpserver"
)

// TestConcurrent_SelectionsDoNotInterfere drives the whole stack from several
// client identities at once. Everything here runs under -race in CI, and the
// selection is a read-modify-write of a file shared by every identity — a lost
// update would move one client's target onto another's host, which is the one
// failure mode this system must not have.
func TestConcurrent_SelectionsDoNotInterfere(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	const identities = 8
	const rounds = 6
	for i := range identities {
		f.add(fmt.Sprintf("box-%02d", i), fmt.Sprintf("box-%02d.internal:8722", i), nil)
	}

	var wg sync.WaitGroup
	for i := range identities {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("client-%02d", i)
			mine := fmt.Sprintf("box-%02d", i)
			for range rounds {
				f.ok("sandbox_select", map[string]any{"name": mine}, id)
				// The sticky default must still be this identity's own, no
				// matter what the other seven did in between.
				assert.Equal(t, mine, echoOf(t, f.ok("sandbox_info", map[string]any{}, id)))
				f.ok("sandbox_list", map[string]any{}, id)
			}
		}(i)
	}
	wg.Wait()

	for i := range identities {
		name, ok, err := f.fleet.GetSelection(fmt.Sprintf("meta:client-%02d", i))
		require.NoError(t, err)
		require.Truef(t, ok, "client-%02d lost its selection entirely", i)
		assert.Equalf(t, fmt.Sprintf("box-%02d", i), name, "client-%02d's selection was overwritten", i)
	}
}

// TestConcurrent_AddNeverRegistersANameTwice hammers the registry with the same
// ten names from six goroutines. Add is a read-modify-write of a shared file:
// two of them interleaving would leave a name registered twice, and a later
// call would then reach whichever copy sorted first.
func TestConcurrent_AddNeverRegistersANameTwice(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	const workers = 6

	var wg sync.WaitGroup
	added := make([]int, workers)
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := range 10 {
				name := fmt.Sprintf("box-%02d", i)
				res := f.call("sandbox_add", map[string]any{"name": name, "address": name + ".internal:8722"}, "")
				if !res.IsError {
					added[w]++
				}
			}
		}(w)
	}
	wg.Wait()

	total := 0
	for _, n := range added {
		total += n
	}
	assert.Equal(t, 10, total, "exactly one add per name may succeed; the rest must be refused")

	sandboxes, err := f.fleet.List()
	require.NoError(t, err)
	assert.Len(t, sandboxes, 10, "the registry must hold each name exactly once")
}

// TestConcurrent_CloseIsSafeAndIdempotent. Run closes the server from a defer,
// so a caller that drives Run in a goroutine and also writes `defer
// server.Close()` — the obvious way to write it — has two closes that can
// genuinely overlap. Read-modify-writing the closer list without a lock is a
// data race that -race would eventually catch as a CI flake.
func TestConcurrent_CloseIsSafeAndIdempotent(t *testing.T) {
	server, err := mcpserver.New(mcpserver.Options{
		ConfigDir: t.TempDir(),
		LogWriter: &testWriter{t: t},
	})
	require.NoError(t, err)

	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = server.Close()
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoErrorf(t, err, "close %d failed", i)
	}
}
