//go:build unix

package platform

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/aymanbagabas/go-pty"
)

// ProcessGroup is a Unix session and process group led by the supervised
// child. Signals are delivered to the negated group id, which is what reaches
// grandchildren: signalling the leader alone leaves `npm run dev`'s bundler
// running and holding the port.
type ProcessGroup struct {
	mu       sync.Mutex
	pid      int
	pgid     int
	isolated bool
	closed   bool
	// configured records that Configure was applied to the command this group
	// is about to adopt, and so that a session was actually asked for. Adopt
	// needs to know: "the child is not leading its own group" is a wait when
	// one was requested and a settled answer when one was not.
	configured bool
}

func newProcessGroup(_ GroupConfig) (*ProcessGroup, error) {
	// Nothing to allocate: the group is created by the child itself, in the
	// window between fork and exec, by the setsid() that Configure requests.
	return &ProcessGroup{}, nil
}

func openProcessGroup(pid int, _ string) (*ProcessGroup, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("platform: invalid pid %d", pid)
	}
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil, fmt.Errorf("platform: pid %d: %w", pid, ErrProcessNotFound)
		}
		return nil, fmt.Errorf("platform: reading process group of pid %d: %w", pid, err)
	}
	return &ProcessGroup{pid: pid, pgid: pgid, isolated: pgid == pid}, nil
}

// Configure requests a new session for the child, which also makes it the
// leader of a new process group with pgid == pid.
//
// Setsid alone, not Setsid plus Setpgid: the child calls setsid() first, and a
// setpgid() from a process that is already a session leader fails with EPERM,
// which aborts the exec. Setsid also detaches the child from the agent's
// controlling terminal, which is what a supervised background process wants —
// a PTY-attached command gets its own controlling terminal from the PTY layer.
func (g *ProcessGroup) Configure(attr *syscall.SysProcAttr) {
	attr.Setsid = true

	g.mu.Lock()
	defer g.mu.Unlock()
	g.configured = true
}

// ConfigureCommand applies Configure to cmd, allocating SysProcAttr if the
// caller has not already.
func (g *ProcessGroup) ConfigureCommand(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	g.Configure(cmd.SysProcAttr)
}

// ConfigurePTYCommand is ConfigureCommand for a go-pty command. go-pty sets
// Setsid and Setctty itself, so this only makes the intent explicit and keeps
// the call sequence identical between the two spawn paths.
func (g *ProcessGroup) ConfigurePTYCommand(cmd *pty.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	g.Configure(cmd.SysProcAttr)
}

// ConfigureInteractivePTYCommand is ConfigurePTYCommand for a session whose
// interrupts arrive through the terminal rather than from the agent.
//
// On Unix it is ConfigurePTYCommand: the child leads its own session with the
// pty as its controlling terminal, the line discipline turns a 0x03 byte into a
// SIGINT for whichever process group is in the foreground of that terminal, and
// the session's own group is what a kill reaches. All of that is what
// ConfigurePTYCommand already asks for.
//
// The two differ on Windows, where the console process group flag that makes an
// agent-sent CTRL_BREAK aimable is also what stops a Ctrl-C typed into the
// terminal being delivered at all. See the Windows file.
func (g *ProcessGroup) ConfigureInteractivePTYCommand(cmd *pty.Cmd) {
	g.ConfigurePTYCommand(cmd)
}

// adoptSettle bounds how long Adopt will wait for a session it asked for to
// become visible. It is a failsafe against a caller that configured a group and
// then started a command without it, never a margin the answer rests on: every
// other way out of adoptedGroup is the kernel answering. Reaching it costs one
// warning on a command that is already running, so it is set generously.
const adoptSettle = 2 * time.Second

// adoptedGroup reads pid's real process group from the kernel and keeps reading
// until the answer is settled. It returns the group the child is really in,
// whether that group is the child's own, and an error only for the settle case.
//
// Not a single sample, which is #82. Configure asks for the session through
// SysProcAttr.Setsid, and the child makes that call itself, between the fork and
// the exec — after the parent's fork has already returned. Go does not do the
// double-setpgid that would close that window, so a parent reading the pgid once
// immediately after Start can still catch the child in the group it was forked
// into. That reading is not wrong for an instant: Adopt records it for the life
// of the process, Signal then degrades to a bare pid and the post-exec sweep is
// skipped entirely, so a command's descendants outlive the call that started
// them. Which is the failure this package exists to prevent.
//
// So every ordinary way out of the loop is a fact the kernel reported:
//
//   - pgid == pid: the session exists, and nothing can take it away again —
//     not even the child exiting, since a group id belongs to its members
//     until the last of them is reaped.
//   - the pid is gone: nothing further can be learned from the kernel, and
//     nothing needs to be — see the branch itself.
//   - Configure was never applied: no session was ever asked for, so the child
//     is in the caller's own group and always will be.
//
// settle is the fourth, and the only one that is a duration. Reaching it means
// a session was requested and the child never entered one, which is reported
// rather than recorded in silence; see Adopt.
func adoptedGroup(pid int, configured bool, settle time.Duration,
	getpgid func(int) (int, error),
) (int, bool, error) {
	deadline := time.Now().Add(settle)
	for attempt := 0; ; attempt++ {
		pgid, err := getpgid(pid)
		if err != nil {
			// The child is gone, or gone as far as getpgid(2) is concerned: on
			// Darwin it answers ESRCH for a process that has exited and not yet
			// been reaped, while Linux answers with the group. A race with a
			// fast-exiting child is not an adoption failure either way, so the
			// question is only what to record about it.
			//
			// Which is answerable without the kernel. Configure asks for the
			// session through SysProcAttr.Setsid; setsid(2) in a freshly forked
			// child cannot fail, because a pid the kernel has just minted is not
			// already a process group leader, and had it failed anyway the child
			// would have reported the errno back through the fork pipe and Start
			// would have returned it rather than a running process. So a
			// configured command that started did lead its own session, and its
			// own pid is both the group to aim at and the truth about isolation.
			//
			// Recording false here instead is what made a short-lived leader on
			// macOS lose its post-exec sweep — the one thing that reaches the
			// `sh -c 'sleep 100 &'` grandchild it left behind.
			return pid, configured, nil //nolint:nilerr // a child that has already gone is not an adoption failure; see above
		}
		if pgid == pid {
			return pgid, true, nil
		}
		if !configured {
			return pgid, false, nil
		}
		if !time.Now().Before(deadline) {
			return pgid, false, fmt.Errorf(
				"platform: pid %d is still in process group %d after %s rather than leading its own: "+
					"a signal will reach it alone and its descendants will survive it",
				pid, pgid, settle)
		}
		// The child is between its fork and its setsid — a handful of
		// instructions on an idle host and a scheduling delay on a loaded one.
		// Yield first, because in the ordinary case that is the whole wait, and
		// only then start sleeping: a caller that configured a group its child
		// never enters would otherwise hold a core busy until the deadline.
		if attempt < 100 {
			runtime.Gosched()
			continue
		}
		time.Sleep(time.Millisecond)
	}
}

// Adopt records the started child. It reads the child's real process group id
// from the kernel rather than assuming Configure was applied, because assuming
// it is how a supervisor ends up sending SIGKILL to its own group.
//
// It returns an error when a session was configured and the child is not in one.
// The group is still recorded — the command is running and its pid is the one
// thing left to act on — but the caller is told, because the alternative is what
// #82 found: a group that quietly reaches one process instead of a tree, with
// nothing in the log to say so. That matches the Windows implementation, where a
// refused job assignment has always been an error with the pid still recorded.
func (g *ProcessGroup) Adopt(p *os.Process) error {
	if p == nil {
		return ErrNoProcess
	}

	g.mu.Lock()
	closed, configured := g.closed, g.configured
	g.mu.Unlock()
	if closed {
		return errors.New("platform: process group is closed")
	}

	// Outside the lock. This waits on the child, and holding the mutex across it
	// would block Signal and Isolated for as long as it takes.
	pgid, isolated, err := adoptedGroup(p.Pid, configured, adoptSettle, syscall.Getpgid)

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return errors.New("platform: process group is closed")
	}
	g.pid = p.Pid
	g.pgid = pgid
	g.isolated = isolated
	return err
}

// Isolated reports whether the child really leads its own group. When it is
// false, Signal reaches only the leader, and descendants must be assumed to
// survive.
func (g *ProcessGroup) Isolated() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.isolated
}

// PID returns the pid of the adopted child, or zero.
func (g *ProcessGroup) PID() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.pid
}

// GroupID returns the Unix process group id, or zero before Adopt. It has no
// Windows counterpart and exists for diagnostics and tests.
func (g *ProcessGroup) GroupID() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.pgid
}

// Signal delivers sig to every process in the group.
//
// Once the group is empty the kernel reports ESRCH, which is translated to
// ErrProcessNotFound. Anything else is passed back as it came, including EPERM:
// a group this process may not signal is a live group, and reporting it as
// "already gone" is the one answer that would stop a caller trying again.
//
// A group is empty only once its last member has been reaped, and what the
// kernel answers in between is not the same on every platform. Measured on a
// group holding nothing but an unreaped zombie leader: Linux reports the group
// from getpgid(2) and delivers the signal, while Darwin answers ESRCH from
// getpgid(2) and EPERM from kill(2) — there is a group, and nothing in it that
// can take a signal. Neither is worth depending on, and no caller here has to:
// every one of them signals a group that still holds a live process, or accepts
// ErrProcessNotFound as "already stopped".
//
// What is worth depending on is the other side of that rule: a group id belongs
// to its members until the last of them is reaped, so a group that has outlived
// its leader is still reachable, and a pgid that has been fully released is free
// for the kernel to hand to somebody else. Signalling one is signalling whatever
// holds it now. See ErrProcessNotFound and platform.SameProcess.
func (g *ProcessGroup) Signal(sig Signal) error {
	osSig, err := sig.OSSignal()
	if err != nil {
		return err
	}
	unixSig, ok := osSig.(syscall.Signal)
	if !ok {
		return ErrSignalUnsupported
	}

	g.mu.Lock()
	pid, pgid, isolated, closed := g.pid, g.pgid, g.isolated, g.closed
	g.mu.Unlock()

	if closed {
		return errors.New("platform: process group is closed")
	}
	if pid == 0 {
		return ErrNoProcess
	}

	target := pid
	if isolated {
		// Negative pid means "the process group with this id". This is the
		// whole reason the group exists.
		target = -pgid
	}
	if err := syscall.Kill(target, unixSig); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("platform: signalling group %d: %w", pgid, ErrProcessNotFound)
		}
		return fmt.Errorf("platform: signalling group %d with %s: %w", pgid, sig, err)
	}
	return nil
}

// Kill sends SIGKILL to the group. It is the escalation step of a graceful
// stop and cannot be caught or ignored.
func (g *ProcessGroup) Kill() error { return g.Signal(SignalKill) }

// Close releases the handle. On Unix it holds no OS resource, so this only
// marks the group unusable; the child is not signalled. Terminating the tree
// is always an explicit Kill.
func (g *ProcessGroup) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	return nil
}
