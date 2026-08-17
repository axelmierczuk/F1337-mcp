//go:build unix

package platform

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"

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

// Adopt records the started child. It reads the child's real process group id
// from the kernel rather than assuming Configure was applied, because assuming
// it is how a supervisor ends up sending SIGKILL to its own group.
func (g *ProcessGroup) Adopt(p *os.Process) error {
	if p == nil {
		return ErrNoProcess
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return errors.New("platform: process group is closed")
	}

	g.pid = p.Pid
	pgid, err := syscall.Getpgid(p.Pid)
	if err != nil {
		// The child may already have exited; its own pid is still the right
		// group to aim at, since Configure asked for pgid == pid.
		g.pgid = p.Pid
		g.isolated = false
		return nil //nolint:nilerr // a race with a fast-exiting child is not an adoption failure
	}
	g.pgid = pgid
	g.isolated = pgid == p.Pid
	return nil
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
// A process that has exited but not been reaped is still a group member, so
// this succeeds against a zombie. Once the group is empty the kernel reports
// ESRCH, which is translated to ErrProcessNotFound.
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
