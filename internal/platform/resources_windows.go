package platform

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGlobalMemoryStatusEx = modkernel32.NewProc("GlobalMemoryStatusEx")

// memoryStatusEx is MEMORYSTATUSEX. x/sys/windows does not define it.
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// readResources reports Windows capacity.
//
// LoadAverage1m stays zero: Windows has no load average, and synthesising one
// from the processor queue length would give callers a number that looks like
// the Unix metric and does not behave like it.
func readResources(diskPath string) (Resources, error) {
	res := Resources{CPUCores: uint32(runtime.NumCPU())} //nolint:gosec // NumCPU is small and positive

	var status memoryStatusEx
	status.Length = uint32(unsafe.Sizeof(status))
	// status is written by the kernel, and LazyProc.Call is an ordinary Go
	// function: the argument-list rule that pins an unsafe.Pointer for the
	// duration of a call applies only to calls made directly to an assembly
	// implementation. Without KeepAlive the collector may reclaim status while
	// GlobalMemoryStatusEx is writing into it. See the same note in
	// group_windows.go and ports_windows.go.
	ret, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&status))) //nolint:gosec // G103: LazyProc.Call takes ...uintptr; the MEMORYSTATUSEX out-parameter has no other form
	runtime.KeepAlive(&status)
	if ret != 0 {
		res.MemoryTotalBytes = status.TotalPhys
		res.MemoryAvailableBytes = status.AvailPhys
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

func diskUsage(diskPath string) (total, available uint64, err error) {
	if diskPath == "" {
		diskPath, err = os.Getwd()
		if err != nil {
			return 0, 0, fmt.Errorf("platform: locating the working directory: %w", err)
		}
	}
	pathPtr, err := windows.UTF16PtrFromString(diskPath)
	if err != nil {
		return 0, 0, fmt.Errorf("platform: invalid path %q: %w", diskPath, err)
	}

	// freeToCaller, not totalFree: quotas can make them differ, and the
	// caller's allowance is the one that decides whether a build fits.
	var freeToCaller, totalBytes, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(pathPtr, &freeToCaller, &totalBytes, &totalFree); err != nil {
		return 0, 0, fmt.Errorf("platform: GetDiskFreeSpaceEx %q: %w", diskPath, err)
	}
	return totalBytes, freeToCaller, nil
}
