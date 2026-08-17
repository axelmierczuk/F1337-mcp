package host

import (
	"os"
	"runtime"
	"sync/atomic"
	"time"
)

// Resources is what the host can actually offer, as opposed to what the
// hardware underneath it has.
//
// The distinction is the whole point of the type. runtime.NumCPU and the
// kernel's memory totals describe the machine; a container-confined agent that
// reports those gets scheduled work it cannot run, and the failure lands as an
// OOM kill halfway through a build rather than as a scheduling decision.
type Resources struct {
	CPUCores             uint32
	MemoryTotalBytes     uint64
	MemoryAvailableBytes uint64
	DiskTotalBytes       uint64
	DiskAvailableBytes   uint64
	LoadAverage1m        float64
}

// ProbeResources reports the host's capacity, measuring disk against
// diskPath.
//
// Every field is best-effort: a value that cannot be determined on this
// platform is left zero rather than guessed at. The one figure that is never
// left zero is CPUCores, which falls back to runtime.NumCPU — a floor, and
// stated as such.
func ProbeResources(diskPath string) Resources {
	res := platformResources(diskPath)
	if res.CPUCores == 0 {
		res.CPUCores = uint32(runtime.NumCPU()) //nolint:gosec // core count does not overflow uint32
	}
	return res
}

var (
	// diskProbeTimeout bounds the one measurement in this package that can
	// block indefinitely.
	diskProbeTimeout = 2 * time.Second
	// diskUsage is the platform's filesystem measurement, indirected so the
	// bound below can be tested against a probe that really does not return.
	diskUsage = disk
	// diskProbeRunning is set while a measurement is outstanding.
	diskProbeRunning atomic.Bool
)

// probeDisk measures the filesystem at path, giving up after diskProbeTimeout.
//
// statfs and GetDiskFreeSpaceEx block in the kernel, uninterruptibly, on an
// unresponsive mount — an NFS server that stopped answering, an autofs target
// that never appears. Nothing in Go cancels that: no context, no deadline, no
// signal. Left unbounded it is the one call on the GetHostInfo path that can
// never return, and every caller that hits it pins an OS thread there for the
// life of the daemon.
//
// So the wait is bounded, and at most one measurement is outstanding at a time.
// The bound alone would still let a polling control plane strand one thread per
// call; the second condition is what makes the cost of a dead mount constant
// rather than proportional to how often anyone asks.
//
// Giving up reports zero, which is what every other figure here does when it
// cannot be determined.
func probeDisk(path string) (total, available uint64) {
	if !diskProbeRunning.CompareAndSwap(false, true) {
		return 0, 0
	}
	done := make(chan [2]uint64, 1)
	go func() {
		t, a := diskUsage(path)
		diskProbeRunning.Store(false)
		done <- [2]uint64{t, a}
	}()

	timer := time.NewTimer(diskProbeTimeout)
	defer timer.Stop()
	select {
	case got := <-done:
		return got[0], got[1]
	case <-timer.C:
		return 0, 0
	}
}

// resourceDiskPath picks the filesystem whose free space is worth reporting:
// the first allowed root that exists, since that is where the caller's files
// will land. With no jail, the temp directory stands in for "wherever this
// agent writes".
func resourceDiskPath(allowedRoots []string) string {
	for _, root := range allowedRoots {
		if root == "" {
			continue
		}
		if _, err := os.Stat(root); err == nil {
			return root
		}
	}
	return os.TempDir()
}
