package host

import (
	"os"
	"runtime"
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
