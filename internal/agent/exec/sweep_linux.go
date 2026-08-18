package exec

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// awaitExit blocks until the process has exited, and leaves it unreaped.
//
// waitid(2) with WNOWAIT is the whole trick: it reports the exit and leaves the
// child waitable, so os/exec's own Wait still collects the status and the
// zombie stays a member of its process group until it does. wait4(2), which is
// what syscall.Wait4 offers, rejects WNOWAIT outright on Linux — the flag is
// waitid's.
//
// EINTR is not an error here: the Go runtime preempts goroutines with signals,
// so a blocking syscall on a busy process is interrupted routinely.
//
// A pidfd would not do instead. It keeps the struct pid alive, not the pid
// number — free_pid drops the number from the namespace's idr as soon as the
// last task detaches, whatever file descriptors still reference it — so a
// pidfd-holding sweep would name exactly as stale a group id as this one used
// to. Linux 6.9's PIDFD_SIGNAL_PROCESS_GROUP would settle the question properly
// by signalling through the descriptor rather than through the number, but the
// agent ships to whatever kernel the host runs, and macOS has no equivalent at
// all; the ordering above is one mechanism for both.
func awaitExit(pid int) error {
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("waiting for pid %d to exit: %w", pid, err)
		}
		return nil
	}
}
