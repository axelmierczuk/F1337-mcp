package tools

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/socks"
)

// What the manager owes the rest of this server: a bound on how many proxies
// one process holds, one proxy per sandbox, and nothing added once it is
// closed.
//
// All three were asserted by nothing. Removing the bound entirely, or the
// closed check, left every test in this repository green — the shape three
// audit rounds have now found on this branch, of a rule whose only witness is
// the line that states it.

// listeningProxy builds an activeProxy on a real loopback listener, with no
// accept loop behind it: the manager is what is under test, not the proxy.
func listeningProxy(t *testing.T, sandbox string) *activeProxy {
	t.Helper()

	server, err := socks.Listen(0, socks.Options{
		Connect: func(context.Context, net.Conn, socks.Destination, func() error) error { return nil },
	})
	require.NoError(t, err)

	_, cancel := context.WithCancel(context.Background())
	p := &activeProxy{sandbox: sandbox, server: server, createdAt: time.Now(), cancel: cancel}
	// Idempotent, so a proxy the manager already closed is not closed twice to
	// any effect, and one it refused is still released.
	t.Cleanup(p.close)
	return p
}

// The bound is a bound, not a number in a message.
//
// Eight proxies is eight local listeners and eight sandboxes' worth of network
// reach held by one MCP server, which is why there is a cap at all; the error
// it raises is also the only place a caller is told how to make room.
func TestSocksManager_BoundsHowManyProxiesOneServerHolds(t *testing.T) {
	m := newSocksManager(slog.New(slog.DiscardHandler))

	for i := range maxProxies {
		require.NoError(t, m.add(listeningProxy(t, "box-"+strconv.Itoa(i))))
	}

	err := m.add(listeningProxy(t, "one-too-many"))
	require.Error(t, err, "the %dth proxy must be refused", maxProxies+1)
	assert.Contains(t, err.Error(), "fleet_socks(stop=true)",
		"a caller told it is full has to be told how to make room")
	require.Len(t, m.list(), maxProxies, "a refused proxy must not be listed")

	// And a second proxy for a sandbox that already has one is the same
	// proxy, not a second listener on a second port.
	duplicate := m.add(listeningProxy(t, "box-0"))
	require.Error(t, duplicate)
	assert.Contains(t, duplicate.Error(), "already exists")

	// Stopping one makes room for the next, so the bound is on what is open
	// rather than on what has ever been opened.
	_, stopped := m.stop("box-0")
	require.True(t, stopped)
	require.NoError(t, m.add(listeningProxy(t, "room-made")))

	require.NoError(t, m.Close())
}

// A proxy must not be opened into a manager that has already been closed.
//
// Close drains the map and releases what was in it, so a proxy that arrives
// afterwards — a tool call racing the MCP server's shutdown — is a listener
// nothing will ever close, held by a process that believes it has stopped.
func TestSocksManager_RefusesToOpenAProxyOnceClosed(t *testing.T) {
	m := newSocksManager(slog.New(slog.DiscardHandler))
	require.NoError(t, m.Close())

	err := m.add(listeningProxy(t, "build-box"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shutting down")
	assert.Empty(t, m.list())
}
