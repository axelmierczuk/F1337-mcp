package shell

import (
	"log/slog"

	"github.com/aymanbagabas/go-pty"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// sweepAndCollect sweeps nothing on Windows and only collects, and that is the
// correct behaviour rather than a gap — the same conclusion ExecService
// reached.
//
// The session's group was created with KillOnClose, the agent holds the only
// handle to the job, and closing it — the last statement of run's deferred
// cleanup — terminates every process still inside. That is the job object doing
// exactly what the session asked it for, and an extra signal would add no
// guarantee to it.
//
// Nor is there an ordering to keep here. The Unix file sends its sweep between
// the leader exiting and Wait collecting it because a process group there is a
// number the kernel reclaims. A job object is not a number: it is a kernel
// object reached through a handle this group holds, and [platform.ProcessGroup]
// pins the leader with a handle of its own from Adopt until Close, so neither
// the job nor the leader's pid can come to name anything else while the group
// can still be asked to signal them. There is nothing for an unreaped zombie to
// hold open, and nothing that needs holding.
//
// So the wait is the wait, with no lock across it: Cmd.Wait here can block for
// as long as the session's leader takes to exit, and the teardown's own kill is
// what ends it.
func (l *leaderWait) sweepAndCollect(cmd *pty.Cmd, _ *platform.ProcessGroup, _ *slog.Logger) error {
	err := cmd.Wait()
	l.mu.Lock()
	l.collected = true
	l.mu.Unlock()
	return err
}

// mayStillSignal is always true on Windows. Called with the lock held.
//
// The teardown's kill is unconditional here and has to stay that way: closing a
// pseudo-console ends the processes attached to it, and a grandchild that never
// attached to one — anything the session started that is not a console
// application — has nothing else to end it before the job is closed.
// TerminateJobObject is what does, and skipping it because the leader happened
// to exit first is exactly how "closing the stream kills the whole tree" becomes
// a claim rather than a fact. It cost three rounds of PR #63 to establish that;
// see [Service.reap].
//
// Sending it after the leader has been collected is safe here for the reason
// sweepAndCollect gives: the group signals the job through its own handle and
// the leader through a handle it pinned at Adopt, so neither call can be
// redirected by a pid the wait has released.
func (l *leaderWait) mayStillSignal() bool { return true }
