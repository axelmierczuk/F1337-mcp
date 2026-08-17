package platform

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
)

// statProcess reads the creation FILETIME from GetProcessTimes: 100-nanosecond
// intervals since 1601-01-01 UTC, recorded at creation and never recomputed.
//
// PROCESS_QUERY_LIMITED_INFORMATION is enough for GetProcessTimes and, unlike
// PROCESS_QUERY_INFORMATION, is granted for processes at a higher integrity
// level. The supervisor only ever asks about its own children, but the
// re-adoption path asks about pids it no longer owns, and failing there with
// "access denied" would read as "gone" and orphan a live process.
func statProcess(pid int) (ProcessInfo, error) {
	if pid <= 0 {
		return ProcessInfo{}, fmt.Errorf("platform: invalid pid %d", pid)
	}

	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid)) //nolint:gosec // pid is positive, checked above
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return ProcessInfo{}, notFound(pid)
		}
		return ProcessInfo{}, fmt.Errorf("platform: opening pid %d: %w", pid, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return ProcessInfo{}, fmt.Errorf("platform: GetProcessTimes for pid %d: %w", pid, err)
	}

	raw := uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)
	return ProcessInfo{
		PID:       pid,
		StartTime: time.Unix(0, creation.Nanoseconds()),
		StartID:   fmt.Sprintf("windows:%d", raw),
	}, nil
}
