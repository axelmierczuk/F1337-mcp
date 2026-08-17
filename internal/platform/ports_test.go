package platform_test

import (
	"net"
	"os"
	"runtime"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// TestListeningPorts_FindsOwnListener opens a real listener in this process
// and asks the platform reader to find it. Every platform takes a different
// route to the answer — /proc/net/tcp joined against /proc/<pid>/fd, lsof,
// GetExtendedTcpTable — and this is the one test that exercises whichever one
// is live.
func TestListeningPorts_FindsOwnListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	port := uint32(listener.Addr().(*net.TCPAddr).Port) //nolint:gosec // a TCP port fits in uint32

	ports, err := platform.ListeningPorts(os.Getpid())
	require.NoError(t, err)

	if len(ports) == 0 && runtime.GOOS == "darwin" {
		// Documented as best effort: the macOS reader needs lsof, which is
		// present on every stock install but not guaranteed on a stripped one.
		if _, err := os.Stat("/usr/sbin/lsof"); err != nil {
			t.Skip("lsof is not installed, so the macOS reader has nothing to read")
		}
	}
	require.Containsf(t, ports, port, "the listener on port %d should appear in %v", port, ports)
	require.True(t, slices.IsSorted(ports), "ports are documented as sorted: %v", ports)
}

func TestListeningPorts_ProcessWithNoListeners(t *testing.T) {
	t.Parallel()

	// A sleeping shell binds nothing. An empty result is the right answer, and
	// it must not be an error.
	ports, err := platform.ListeningPorts(sleeper(t))
	require.NoError(t, err)
	require.Empty(t, ports)
}

func TestListeningPorts_InvalidPID(t *testing.T) {
	t.Parallel()

	for _, pid := range []int{0, -1} {
		_, err := platform.ListeningPorts(pid)
		require.Errorf(t, err, "pid %d", pid)
	}
}
