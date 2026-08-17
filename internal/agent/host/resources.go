package host

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/axelmierczuk/sandboxd-mcp/internal/platform"
)

// Capacity reporting is internal/platform's job, not this package's.
//
// It used to be both. This package grew its own cgroup, /proc, sysctl and
// Win32 readers because #16 had not landed when HostService was written, and
// kept them afterwards — two implementations of the same measurement, only one
// of which was audited. What this file keeps is the part that is genuinely
// HostService's: choosing which filesystem to measure, and bounding how long
// the measurement may take before an RPC gives up on it.

var (
	// resourceProbeTimeout bounds a capacity read.
	resourceProbeTimeout = 2 * time.Second
	// readResources is platform.ReadResources, indirected so the bound below
	// can be tested against a read that really does not return.
	readResources = platform.ReadResources
	// resourceProbeRunning is set while a read is outstanding.
	resourceProbeRunning atomic.Bool
)

// probeResources reports host capacity, giving up after resourceProbeTimeout.
//
// The bound is not decoration. Capacity is measured with statfs on Unix and
// GetDiskFreeSpaceEx on Windows, and both block in the kernel — uninterruptibly,
// with no context to cancel and no deadline to set — on an unresponsive mount:
// an NFS server that stopped answering, an autofs target that never appears.
// Unbounded it is the one call on the GetHostInfo path that can never return,
// and every caller that hits it strands an OS thread for the life of the daemon.
//
// So the wait is bounded, and at most one read is outstanding at a time. The
// bound alone would still let a polling control plane strand one thread per
// call; the second condition is what makes the cost of a dead mount constant
// rather than proportional to how often anyone asks.
//
// Giving up reports zeros, which is what the proto documents an undeterminable
// figure as, and an error the caller can log.
func probeResources(diskPath string) (platform.Resources, error) {
	if !resourceProbeRunning.CompareAndSwap(false, true) {
		return platform.Resources{}, fmt.Errorf("host: a capacity read of %s is already outstanding and has not returned", diskPath)
	}

	type result struct {
		res platform.Resources
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := readResources(diskPath)
		resourceProbeRunning.Store(false)
		done <- result{res, err}
	}()

	timer := time.NewTimer(resourceProbeTimeout)
	defer timer.Stop()
	select {
	case got := <-done:
		return got.res, got.err
	case <-timer.C:
		return platform.Resources{}, fmt.Errorf("host: reading capacity for %s did not return within %s", diskPath, resourceProbeTimeout)
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
