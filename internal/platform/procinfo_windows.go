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
		if processGone(err) {
			return ProcessInfo{}, notFound(pid)
		}
		return ProcessInfo{}, fmt.Errorf("platform: opening pid %d: %w", pid, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	creation, err := creationTime(h)
	if err != nil {
		return ProcessInfo{}, fmt.Errorf("platform: GetProcessTimes for pid %d: %w", pid, err)
	}

	return ProcessInfo{
		PID:       pid,
		StartTime: time.Unix(0, creation.Nanoseconds()),
		StartID:   startIDFrom(creation),
	}, nil
}

// creationTime reads a process's creation FILETIME through a handle already
// open on it.
//
// Taking a handle rather than a pid is the point: a handle names one process
// for its whole lifetime, so this cannot be answered by whatever holds the
// number now. PROCESS_QUERY_LIMITED_INFORMATION is enough, which is why both
// leaderAccess and adoptAccess can ask it.
func creationTime(h windows.Handle) (windows.Filetime, error) {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return windows.Filetime{}, err
	}
	return creation, nil
}

// startIDFrom encodes a creation FILETIME as the opaque StartID that
// [SameProcess] compares. It is the one place the encoding is written, so a
// value produced from a handle and one produced from a pid are comparable.
func startIDFrom(creation windows.Filetime) string {
	raw := uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)
	return fmt.Sprintf("windows:%d", raw)
}

// processGone reports whether an OpenProcess failure means the pid names no
// process, as opposed to naming one this agent is not allowed to open.
//
// The distinction is the one the supervisor's re-adoption logic turns on, and
// the whole reason ErrProcessNotFound exists rather than a bare OS error.
// ERROR_INVALID_PARAMETER is what Windows returns for a pid with nothing
// behind it; ERROR_NOT_FOUND appears for the same condition on some versions.
// ERROR_ACCESS_DENIED is the one that must never be folded in: it means the
// process is running and out of reach, and answering "gone" there makes a
// caller stop trying to stop something that is still going.
func processGone(err error) bool {
	return errors.Is(err, windows.ERROR_INVALID_PARAMETER) ||
		errors.Is(err, windows.ERROR_NOT_FOUND)
}
