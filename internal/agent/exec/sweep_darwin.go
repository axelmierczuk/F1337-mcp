package exec

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// awaitExit blocks until the process has exited, and leaves it uncollected.
//
// Darwin has no usable waitid(2) from Go: x/sys/unix does not wrap it, and
// wait4(2) — which is what syscall.Wait4 offers — accepts WNOWAIT and then
// collects the child anyway, which takes the exit status away from os/exec's
// Wait and turns a fixed sweep into a command whose result is "wait: no child
// processes". That was measured on this platform, not assumed.
//
// kqueue's EVFILT_PROC reports the exit without collecting it, which is the
// observation this needs. Two things about it are easy to get wrong and both
// end in a sweep sent on no information at all:
//
//   - A failed registration is not reported through the syscall's own error.
//     kevent puts it in the event list with EV_ERROR set and the errno in Data,
//     and returns a count — so a caller that only checks for a non-nil error
//     reads "cannot watch this pid" as "it has exited".
//   - Registration fails with ESRCH for a process on its way out. EVFILT_PROC
//     attaches through proc_find, which refuses a process the kernel has
//     started tearing down as well as one that is already a zombie — and a
//     command that leaves a descendant behind, `sh -c 'sleep 100 &'`, is
//     usually one or the other by the time this runs.
//
// So ESRCH is not an answer on its own. It means the pid is not a findable
// running process, which is the same thing the kernel says about a pid that
// was never ours. The two are told apart by asking whether the pid is still
// recorded as a child of this process, rather than by arguing from the caller
// being careful: five defects in this repository so far have come from treating
// a pid as a durable name for a thing.
//
// Ownership, and deliberately not "is it a zombie". The two states differ by
// about a microsecond and the process table reports the first of them as
// running, so a check for SZOMB refuses its own leader whenever the kernel is
// midway through the exit — measured at roughly one run in two with this
// package under load, which is how it was found. Both states are equally good
// for the sweep: exit1 records the status and marks the process before anything
// else can observe it, so a SIGKILL arriving now cannot change what the command
// exited with, and the process stays a member of its own process group until
// somebody collects it, which is the only property the group id's safety rests
// on.
func awaitExit(pid int) error {
	kq, err := unix.Kqueue()
	if err != nil {
		return fmt.Errorf("kqueue: %w", err)
	}
	defer func() { _ = unix.Close(kq) }()

	watch := []unix.Kevent_t{{
		Ident:  uint64(pid), //nolint:gosec // a pid is positive and far inside 64 bits
		Filter: unix.EVFILT_PROC,
		Flags:  unix.EV_ADD | unix.EV_ONESHOT,
		Fflags: unix.NOTE_EXIT,
	}}
	var events [1]unix.Kevent_t
	for {
		n, err := unix.Kevent(kq, watch, events[:], nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("watching pid %d for exit: %w", pid, err)
		}
		if n == 0 {
			continue
		}
		if events[0].Flags&unix.EV_ERROR == 0 {
			return nil
		}
		//nolint:gosec // an errno is small and positive
		regErr := unix.Errno(events[0].Data)
		if errors.Is(regErr, unix.ESRCH) && isOurUncollectedChild(pid) {
			return nil
		}
		return fmt.Errorf("watching pid %d for exit: %w", pid, regErr)
	}
}

// isOurUncollectedChild reports whether pid is still recorded as a child of
// this process.
//
// Reached only when the kernel has already refused to treat pid as a running
// process, so "still a child" there means "on its way out or gone, and not yet
// collected" — the state that keeps its process group id reserved, and so the
// state the sweep needs it to be in.
//
// A process belonging to somebody else says nothing about a group this agent
// may signal, and neither does a pid with nothing behind it: a pid with no
// process produces a zero-length sysctl result, which x/sys reports as EIO.
func isOurUncollectedChild(pid int) bool {
	proc, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || proc == nil {
		return false
	}
	return int(proc.Proc.P_pid) == pid && int(proc.Eproc.Ppid) == os.Getpid()
}
