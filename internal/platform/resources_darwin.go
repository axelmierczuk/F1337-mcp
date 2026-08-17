package platform

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

// vmStatTimeout bounds the subprocess so a wedged vm_stat cannot wedge a
// status call.
const vmStatTimeout = 3 * time.Second

// readResources reports macOS capacity.
//
// There is no cgroup equivalent to honour here: macOS has no container runtime
// the agent would be running under, so the machine's figures are the effective
// ones.
func readResources(diskPath string) (Resources, error) {
	res := Resources{CPUCores: uint32(runtime.NumCPU())} //nolint:gosec // NumCPU is small and positive

	if total, err := unix.SysctlUint64("hw.memsize"); err == nil {
		res.MemoryTotalBytes = total
	}
	res.MemoryAvailableBytes = availableMemory()
	if load, err := loadAverage1m(); err == nil {
		res.LoadAverage1m = load
	}

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

// availableMemory prefers vm_stat, which reports the reclaimable page classes,
// and falls back to the free and speculative page counters from sysctl when
// vm_stat is unavailable. The fallback is a large undercount; there is no
// cgo-free way to do better, and undercounting only costs the scheduler a
// sandbox it could have used.
func availableMemory() uint64 {
	if pages, pageSize, ok := runVMStat(); ok {
		return pages * pageSize
	}

	pageSize, err := unix.SysctlUint32("hw.pagesize")
	if err != nil || pageSize == 0 {
		return 0
	}
	var pages uint64
	for _, name := range []string{"vm.page_free_count", "vm.page_speculative_count", "vm.page_purgeable_count"} {
		if v, err := unix.SysctlUint32(name); err == nil {
			pages += uint64(v)
		}
	}
	return pages * uint64(pageSize)
}

func runVMStat() (pages, pageSize uint64, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), vmStatTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "/usr/bin/vm_stat").Output()
	if err != nil {
		return 0, 0, false
	}
	return vmStatAvailablePages(string(out))
}

// loadAverage1m reads the vm.loadavg sysctl.
//
// It returns a struct loadavg: three fixed-point u_int32_t averages followed
// by a long scale factor. The long forces 8-byte alignment, so fscale sits at
// offset 16 with four bytes of padding before it, and the struct is 24 bytes
// on both darwin ports Go supports. x/sys/unix has no type for it, so the
// offsets are spelled out rather than reinterpreted through unsafe.
func loadAverage1m() (float64, error) {
	const (
		ldavgOffset  = 0
		fscaleOffset = 16
		structSize   = 24
	)

	raw, err := unix.SysctlRaw("vm.loadavg")
	if err != nil {
		return 0, fmt.Errorf("platform: sysctl vm.loadavg: %w", err)
	}
	if len(raw) < structSize {
		return 0, fmt.Errorf("platform: sysctl vm.loadavg returned %d bytes, want %d", len(raw), structSize)
	}

	ldavg := binary.NativeEndian.Uint32(raw[ldavgOffset : ldavgOffset+4])
	fscale := binary.NativeEndian.Uint64(raw[fscaleOffset : fscaleOffset+8])
	if fscale == 0 {
		return 0, errors.New("platform: sysctl vm.loadavg reported a zero scale")
	}
	return float64(ldavg) / float64(fscale), nil
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
	return st.Blocks * uint64(st.Bsize), st.Bavail * uint64(st.Bsize), nil
}
