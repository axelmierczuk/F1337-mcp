package platform

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// statProcess reads kern.proc.pid, whose kp_proc.p_starttime is a timeval
// recorded when the process was created and never recomputed. Unlike the Linux
// path there is no boot-time arithmetic and no clock-adjustment hazard: the
// value is exact and the wall-clock time and the start id encode the same
// thing.
func statProcess(pid int) (ProcessInfo, error) {
	if pid <= 0 {
		return ProcessInfo{}, fmt.Errorf("platform: invalid pid %d", pid)
	}

	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		// A pid with no process produces a zero-length result, which x/sys
		// reports as EIO rather than ESRCH. Confirm with a null signal rather
		// than guessing which of the two meant "gone".
		if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.EIO) {
			if unix.Kill(pid, 0) == unix.ESRCH {
				return ProcessInfo{}, notFound(pid)
			}
		}
		return ProcessInfo{}, fmt.Errorf("platform: sysctl kern.proc.pid %d: %w", pid, err)
	}
	if int(kp.Proc.P_pid) != pid {
		return ProcessInfo{}, notFound(pid)
	}

	tv := kp.Proc.P_starttime
	return ProcessInfo{
		PID:       pid,
		StartTime: time.Unix(tv.Sec, int64(tv.Usec)*1000),
		StartID:   fmt.Sprintf("darwin:%d.%06d", tv.Sec, tv.Usec),
	}, nil
}
