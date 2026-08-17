package mcpserver_test

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver"
	"github.com/axelmierczuk/fleet-mcp/internal/security/ca"
)

// TestConcurrent_ClosingWithHandlersInFlightLeaksNoGoroutines is the running
// half of the lifecycle guarantee, and the half a functional test cannot see.
//
// TestLazyPool_DoesNotRebuildAfterClose proves a call arriving after Close is
// refused. What it cannot prove is that nothing was left running: a pool built
// on the way out starts a background health loop per channel, and once
// Server.Close has dropped its closers there is nothing left to stop them. The
// process exiting hides it on the stdio path; on the Connect path, which exists
// for embedding, it accumulates. So: real credentials, a real pool, handlers
// racing Close, repeated — and the goroutine count has to come back down.
func TestConcurrent_ClosingWithHandlersInFlightLeaksNoGoroutines(t *testing.T) {
	dir := t.TempDir()
	authority, err := ca.Init(filepath.Join(dir, "ca"), false)
	require.NoError(t, err)
	certPEM, keyPEM := signLeaf(t, authority, ca.ProfileControl, "sandboxd-mcp", nil)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "control.crt"), certPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "control.key"), keyPEM, 0o600))

	const rounds = 5
	// A few goroutines belong to the test harness and to gRPC's own lazily
	// started machinery, and neither is this package's to account for. The
	// assertion is on growth per round, which a leak produces and a fixed
	// overhead does not.
	const slack = 8

	before := goroutinesAfterSettling(t, 0, 300*time.Millisecond)

	for range rounds {
		server, err := mcpserver.New(mcpserver.Options{
			ConfigDir:   dir,
			LogWriter:   &testWriter{t: t},
			CallTimeout: 500 * time.Millisecond,
		})
		require.NoError(t, err)

		clientTransport, serverTransport := mcp.NewInMemoryTransports()
		serverSession, err := server.Connect(t.Context(), serverTransport)
		require.NoError(t, err)
		session, err := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0.0"}, nil).
			Connect(t.Context(), clientTransport, nil)
		require.NoError(t, err)

		// 127.0.0.1:1 is closed, so the call reaches the pool and fails there
		// rather than at the credentials: the pool is genuinely built.
		callTool(t, session, "sandbox_add", map[string]any{"name": "closed", "address": "127.0.0.1:1"}, false)

		var wg sync.WaitGroup
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Ignored on purpose: whether each call answers or is refused
				// depends on where it was when Close landed, and both are
				// correct. What is asserted is what is left behind.
				_, _ = session.CallTool(t.Context(), &mcp.CallToolParams{
					Name: "sandbox_info", Arguments: map[string]any{"sandbox": "closed"},
				})
			}()
		}
		go func() { _ = server.Close() }()
		wg.Wait()

		require.NoError(t, server.Close())
		require.NoError(t, session.Close())
		_ = serverSession.Wait()

		// A fresh registry each round, so the next add is not a duplicate.
		require.NoError(t, os.Remove(filepath.Join(dir, "registry.yaml")))
	}

	after := goroutinesAfterSettling(t, before+slack, 10*time.Second)
	if after > before+slack {
		buf := make([]byte, 1<<20)
		t.Logf("goroutines still running:\n%s", buf[:runtime.Stack(buf, true)])
	}
	require.LessOrEqualf(t, after, before+slack,
		"goroutine count grew from %d to %d over %d server lifecycles", before, after, rounds)
}

// goroutinesAfterSettling waits up to within for the goroutine count to fall
// to want, and returns what it settled at. Teardown is asynchronous — a closed
// gRPC channel unwinds on its own schedule — so a single sample straight after
// Close reads a leak into an ordinary race.
func goroutinesAfterSettling(t *testing.T, want int, within time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		runtime.GC()
		n := runtime.NumGoroutine()
		if n <= want || time.Now().After(deadline) {
			return n
		}
		time.Sleep(20 * time.Millisecond)
	}
}
