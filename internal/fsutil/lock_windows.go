//go:build windows

package fsutil

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockRegionLow and lockRegionHigh cover the largest region LockFileEx
// accepts. The lock file itself is empty, and Windows permits locking a range
// past end-of-file, so locking everything is the simplest whole-file lock.
const (
	lockRegionLow  = ^uint32(0)
	lockRegionHigh = ^uint32(0)
)

// lockFile takes a blocking exclusive lock. Without LOCKFILE_FAIL_IMMEDIATELY
// alongside LOCKFILE_EXCLUSIVE_LOCK, LockFileEx waits until the lock is
// available, matching the flock behaviour on Unix. Windows releases the lock
// when the handle closes, including on process death.
func lockFile(f *os.File) error {
	return windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK,
		0,
		lockRegionLow,
		lockRegionHigh,
		new(windows.Overlapped),
	)
}

func unlockFile(f *os.File) error {
	return windows.UnlockFileEx(
		windows.Handle(f.Fd()),
		0,
		lockRegionLow,
		lockRegionHigh,
		new(windows.Overlapped),
	)
}
