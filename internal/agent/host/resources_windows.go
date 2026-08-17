package host

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// memoryStatusEx mirrors the Win32 MEMORYSTATUSEX structure. The first field
// is the caller-set size of the struct, which GlobalMemoryStatusEx validates.
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

var (
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
)

func platformResources(diskPath string) Resources {
	res := Resources{
		// Windows exposes no load average. The proto documents the field as
		// present only where the platform reports one, so it stays zero rather
		// than being synthesised from something that does not mean the same
		// thing.
		CPUCores: uint32(runtime.NumCPU()), //nolint:gosec // core count does not overflow uint32
	}
	res.MemoryTotalBytes, res.MemoryAvailableBytes = memory()
	res.DiskTotalBytes, res.DiskAvailableBytes = disk(diskPath)
	return res
}

func memory() (total, available uint64) {
	status := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	ret, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&status)))
	if ret == 0 {
		return 0, 0
	}
	return status.TotalPhys, status.AvailPhys
}

func disk(path string) (total, available uint64) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0
	}
	var freeToCaller, totalBytes, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &freeToCaller, &totalBytes, &totalFree); err != nil {
		return 0, 0
	}
	// freeToCaller, not totalFree: a quota-limited account has less available
	// than the volume does, and it is the caller's writes that will fail.
	return totalBytes, freeToCaller
}
