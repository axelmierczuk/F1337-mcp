package host

import (
	"encoding/binary"
	"runtime"

	"golang.org/x/sys/unix"
)

func platformResources(diskPath string) Resources {
	res := Resources{
		CPUCores:      cpuCores(),
		LoadAverage1m: loadAverage1m(),
	}
	res.MemoryTotalBytes, res.MemoryAvailableBytes = memory()
	res.DiskTotalBytes, res.DiskAvailableBytes = probeDisk(diskPath)
	return res
}

// cpuCores prefers hw.logicalcpu, which reflects the cores this process may
// actually be scheduled on, over runtime.NumCPU.
func cpuCores() uint32 {
	if n, err := unix.SysctlUint32("hw.logicalcpu"); err == nil && n > 0 {
		return n
	}
	return uint32(runtime.NumCPU()) //nolint:gosec // core count does not overflow uint32
}

// memory reports the machine's installed memory and a deliberately
// conservative estimate of what is free.
//
// macOS has no MemAvailable equivalent. Free pages alone undercount — inactive
// and speculative pages are reclaimable too — so the figure reported here is a
// floor. Understating available memory costs a scheduling decision; overstating
// it costs a build.
func memory() (total, available uint64) {
	if n, err := unix.SysctlUint64("hw.memsize"); err == nil {
		total = n
	}

	pageSize := uint64(unix.Getpagesize()) //nolint:gosec // page size is positive
	var pages uint64
	for _, name := range []string{"vm.page_free_count", "vm.page_speculative_count"} {
		if n, err := unix.SysctlUint32(name); err == nil {
			pages += uint64(n)
		}
	}
	available = pages * pageSize
	if available > total {
		available = total
	}
	return total, available
}

func disk(path string) (total, available uint64) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, 0
	}
	size := uint64(stat.Bsize)
	return stat.Blocks * size, stat.Bavail * size
}

// loadAverage1m decodes the kernel's struct loadavg:
//
//	struct loadavg { fixed_t ldavg[3]; long fscale; };
//
// fixed_t is a 32-bit integer and fscale the divisor that turns it back into a
// fraction. The long that follows three int32s is 8-byte aligned on both
// arm64 and amd64, so it starts at offset 16, not 12.
func loadAverage1m() float64 {
	raw, err := unix.SysctlRaw("vm.loadavg")
	if err != nil || len(raw) < 24 {
		return 0
	}
	ldavg := binary.NativeEndian.Uint32(raw[0:4])
	fscale := binary.NativeEndian.Uint64(raw[16:24])
	if fscale == 0 {
		return 0
	}
	return float64(ldavg) / float64(fscale)
}
