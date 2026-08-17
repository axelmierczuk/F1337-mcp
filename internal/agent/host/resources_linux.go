package host

import (
	"math"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"
)

// procLoadavg is the kernel's load-average file. Linux-only, unlike the cgroup
// interfaces in cgroup.go: every other platform has its own source.
var procLoadavg = "/proc/loadavg"

func platformResources(diskPath string) Resources {
	res := Resources{
		CPUCores:      cpuCores(),
		LoadAverage1m: loadAverage1m(),
	}
	res.MemoryTotalBytes, res.MemoryAvailableBytes = memory()
	res.DiskTotalBytes, res.DiskAvailableBytes = probeDisk(diskPath)
	return res
}

// cpuCores returns the effective core count: the smaller of the machine's
// visible CPUs and any cgroup CPU quota in force.
//
// runtime.NumCPU is a floor, not the answer. A container limited to 0.5 CPU
// still sees every core on the host, and an agent that advertises them will be
// handed a parallel build that thrashes for the whole quota period.
func cpuCores() uint32 {
	cores := float64(runtime.NumCPU())
	if quota, ok := cgroupCPUQuota(); ok && quota < cores {
		cores = quota
	}
	// Round up: a 0.5-CPU quota is still a host that can run one thing at a
	// time, and reporting zero cores would read as "cannot run anything".
	rounded := math.Ceil(cores)
	if rounded < 1 {
		rounded = 1
	}
	return uint32(rounded)
}

// memory returns total and available bytes, clamped by any cgroup memory
// limit.
func memory() (total, available uint64) {
	total, available = readMeminfo()

	if limit, usage, ok := cgroupMemoryLimit(); ok {
		if limit < total || total == 0 {
			total = limit
		}
		// Headroom inside the cgroup is the limit minus what the cgroup is
		// already using, which is a tighter and more truthful bound than the
		// kernel's host-wide MemAvailable.
		var headroom uint64
		if limit > usage {
			headroom = limit - usage
		}
		if headroom < available || available == 0 {
			available = headroom
		}
	}
	return total, available
}

func disk(path string) (total, available uint64) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, 0
	}
	size := uint64(stat.Bsize) //nolint:gosec // block size is a small positive value
	return stat.Blocks * size, stat.Bavail * size
}

func loadAverage1m() float64 {
	fields, ok := readFields(procLoadavg)
	if !ok || len(fields) == 0 {
		return 0
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return value
}
