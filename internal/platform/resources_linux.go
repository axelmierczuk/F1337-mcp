package platform

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

func readResources(diskPath string) (Resources, error) {
	res := Resources{CPUCores: uint32(runtime.NumCPU())} //nolint:gosec // NumCPU is small and positive

	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		mem := parseMeminfo(data)
		res.MemoryTotalBytes = mem["MemTotal"]
		// MemAvailable is the kernel's own estimate of what can be allocated
		// without swapping. It accounts for reclaimable page cache, which
		// MemFree does not, and getting that wrong understates a busy host by
		// most of its memory.
		res.MemoryAvailableBytes = mem["MemAvailable"]
	}
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		if load, err := parseLoadAverage1m(data); err == nil {
			res.LoadAverage1m = load
		}
	}

	applyCgroupLimits(&res, readCgroupLimits(os.DirFS("/")))

	total, avail, diskErr := diskUsage(diskPath)
	if diskErr == nil {
		res.DiskTotalBytes, res.DiskAvailableBytes = total, avail
	}

	if res.MemoryTotalBytes == 0 && res.DiskTotalBytes == 0 {
		if diskErr != nil {
			return res, fmt.Errorf("platform: reading host resources: %w", diskErr)
		}
		return res, errors.New("platform: reading host resources: nothing could be read")
	}
	return res, nil
}

func diskUsage(diskPath string) (total, available uint64, err error) {
	if diskPath == "" {
		diskPath, err = os.Getwd()
		if err != nil {
			return 0, 0, fmt.Errorf("platform: locating the working directory: %w", err)
		}
	}
	var st unix.Statfs_t
	if err := unix.Statfs(diskPath, &st); err != nil {
		return 0, 0, fmt.Errorf("platform: statfs %q: %w", diskPath, err)
	}
	// Bavail, not Bfree: the difference is the root reserve, which the agent
	// does not run as root and cannot use.
	return st.Blocks * uint64(st.Bsize), st.Bavail * uint64(st.Bsize), nil //nolint:gosec // block size is positive
}
