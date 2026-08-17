package host_test

import (
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/agent/host"
	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// What internal/platform measures is its own business and its own tests. What
// this package still owns is the bound on how long GetHostInfo will wait for
// the answer, and these are the tests for that.

// hungFilesystem replaces the delegated capacity read with one that never
// returns until the test lets it, and tears the substitution down only once the
// probe goroutine has actually left it.
func hungFilesystem(t *testing.T) *atomic.Int32 {
	t.Helper()

	released := make(chan struct{})
	finished := make(chan struct{})
	var started atomic.Int32

	restoreTimeout := host.SetResourceProbeTimeoutForTest(100 * time.Millisecond)
	restoreRead := host.SetReadResourcesForTest(func(string) (platform.Resources, error) {
		started.Add(1)
		<-released
		close(finished)
		return platform.Resources{CPUCores: 1}, nil
	})
	t.Cleanup(func() {
		close(released)
		if started.Load() > 0 {
			<-finished
		}
		// The in-flight flag is cleared after the read returns, so wait for
		// that too before putting the real one back.
		host.WaitResourceProbeIdleForTest()
		restoreRead()
		restoreTimeout()
	})
	return &started
}

// Capacity is measured with statfs on Unix and GetDiskFreeSpaceEx on Windows,
// and both block in the kernel on an unresponsive mount, uninterruptibly, with
// no context to cancel and no deadline to set.
//
// Unbounded, an NFS server that stopped answering turns every fleet_info into
// an RPC that never returns and an OS thread that is never released.
func TestProbeResources_HungFilesystemDoesNotHangTheCall(t *testing.T) {
	started := hungFilesystem(t)

	start := time.Now()
	res, err := host.ProbeResourcesForTest(os.TempDir())
	elapsed := time.Since(start)

	require.EqualValues(t, 1, started.Load(), "the read must actually have been attempted")
	require.Error(t, err, "giving up is reported, not silently reported as an empty host")
	assert.Less(t, elapsed, 5*time.Second, "a mount that never answers must not hold the RPC open")
	assert.Zero(t, res.DiskTotalBytes, "a read that did not complete reports nothing, not a guess")
	assert.Zero(t, res.MemoryTotalBytes)
}

// And the cost of a dead mount is constant rather than one stranded thread per
// call: while a read is outstanding, the next caller is answered without
// starting a second one.
func TestProbeResources_HungFilesystemStrandsOneProbeAtMost(t *testing.T) {
	started := hungFilesystem(t)

	_, err := host.ProbeResourcesForTest(os.TempDir()) // leaves the one read stuck
	require.Error(t, err)

	start := time.Now()
	for range 5 {
		_, err := host.ProbeResourcesForTest(os.TempDir())
		assert.Error(t, err)
	}
	assert.Less(t, time.Since(start), 2*time.Second,
		"a caller arriving while a read is stuck must be answered, not queued behind it")
	require.EqualValues(t, 1, started.Load(),
		"one dead mount must strand one read, however many times it is asked about")
}

// The bound has to be long enough that an ordinary filesystem is never cut off
// and short enough to be a bound at all.
func TestResourceProbeTimeoutIsSane(t *testing.T) {
	assert.Positive(t, host.ResourceProbeTimeoutForTest())
	assert.LessOrEqual(t, host.ResourceProbeTimeoutForTest(), 10*time.Second)
}

// The ordinary path is unaffected: a real filesystem is measured and reported.
func TestProbeResources_ReportsARealHost(t *testing.T) {
	res, err := host.ProbeResourcesForTest(os.TempDir())
	require.NoError(t, err)
	assert.Positive(t, res.DiskTotalBytes)
	assert.LessOrEqual(t, res.DiskAvailableBytes, res.DiskTotalBytes)
	assert.Positive(t, res.MemoryTotalBytes)
	assert.GreaterOrEqual(t, res.CPUCores, uint32(1))
}
