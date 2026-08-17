package host_test

import (
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/agent/host"
)

// hungFilesystem replaces the platform's filesystem measurement with one that
// never returns until the test lets it, and tears the substitution down only
// once the probe goroutine has actually left it.
func hungFilesystem(t *testing.T) *atomic.Int32 {
	t.Helper()

	released := make(chan struct{})
	finished := make(chan struct{})
	var started atomic.Int32

	restoreTimeout := host.SetDiskProbeTimeoutForTest(100 * time.Millisecond)
	restoreUsage := host.SetDiskUsageForTest(func(string) (uint64, uint64) {
		started.Add(1)
		<-released
		close(finished)
		return 1, 1
	})
	t.Cleanup(func() {
		close(released)
		if started.Load() > 0 {
			<-finished
		}
		// The in-flight flag is cleared after the measurement returns, so wait
		// for that too before putting the real one back.
		host.WaitDiskProbeIdleForTest()
		restoreUsage()
		restoreTimeout()
	})
	return &started
}

// The disk measurement is the one call on the GetHostInfo path that can block
// forever: statfs and GetDiskFreeSpaceEx wait in the kernel on an unresponsive
// mount, uninterruptibly, with no context to cancel and no deadline to set.
//
// Unbounded, an NFS server that stopped answering turns every sandbox_info into
// an RPC that never returns and an OS thread that is never released.
func TestProbeResources_HungFilesystemDoesNotHangTheCall(t *testing.T) {
	started := hungFilesystem(t)

	start := time.Now()
	res := host.ProbeResources(os.TempDir())
	elapsed := time.Since(start)

	require.EqualValues(t, 1, started.Load(), "the measurement must actually have been attempted")
	assert.Less(t, elapsed, 5*time.Second, "a mount that never answers must not hold the RPC open")
	assert.Zero(t, res.DiskTotalBytes, "a measurement that did not complete reports nothing, not a guess")
	assert.Zero(t, res.DiskAvailableBytes)

	// Everything that does not touch the filesystem is still reported.
	assert.GreaterOrEqual(t, res.CPUCores, uint32(1))
}

// And the cost of a dead mount is constant rather than one stranded thread per
// call: while a measurement is outstanding, the next caller is answered without
// starting a second one.
func TestProbeResources_HungFilesystemStrandsOneProbeAtMost(t *testing.T) {
	started := hungFilesystem(t)

	host.ProbeResources(os.TempDir()) // leaves the one measurement stuck

	start := time.Now()
	for i := 0; i < 5; i++ {
		res := host.ProbeResources(os.TempDir())
		assert.Zero(t, res.DiskTotalBytes)
	}
	assert.Less(t, time.Since(start), 2*time.Second,
		"a caller arriving while a measurement is stuck must be answered, not queued behind it")
	require.EqualValues(t, 1, started.Load(),
		"one dead mount must strand one measurement, however many times it is asked about")
}

// The bound has to be long enough that an ordinary filesystem is never cut off
// and short enough to be a bound at all.
func TestDiskProbeTimeoutIsSane(t *testing.T) {
	assert.Positive(t, host.DiskProbeTimeoutForTest())
	assert.LessOrEqual(t, host.DiskProbeTimeoutForTest(), 10*time.Second)
}

// The ordinary path is unaffected: a filesystem that answers is reported.
func TestProbeResources_ReportsARealFilesystem(t *testing.T) {
	res := host.ProbeResources(os.TempDir())
	assert.Positive(t, res.DiskTotalBytes)
	assert.LessOrEqual(t, res.DiskAvailableBytes, res.DiskTotalBytes)
}
