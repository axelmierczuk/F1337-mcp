package shell

import (
	"log/slog"

	"github.com/aymanbagabas/go-pty"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// sweepAndCollect kills whatever is left of the session's process group and
// then collects its leader, in that order and through the group that owns both.
//
// The sweep is the same call, for the same reason, as ExecService's: a Unix
// process group holds no kernel object, so nothing has reached a process that
// outlived the shell, and an explicit signal to the group is the only thing
// that will. It goes out between the leader exiting and Wait collecting it, so
// the leader's own zombie is what makes the group id unmistakably the
// session's; [platform.AwaitExit] carries that argument, the measurements that
// disproved the other one and the pid-namespace run that reproduces it on
// demand.
//
// # Why the group performs the collection
//
// Two things signal a session's group: this sweep and the teardown's own kill
// in [Service.reap]. Writing them in the right order is not enough, because the
// teardown decides to signal on a timeout and the leader can exit while it is
// deciding — so the two are ordered against the collection rather than against
// each other, and the collection is what takes the lock.
//
// That lock used to be this package's. It is [platform.ProcessGroup]'s now, and
// the move is the point rather than tidying: the same two-party problem is in
// internal/agent/exec, where a timeout watcher signals the group that its own
// wait is about to collect, and a second copy of the rule agreeing with this
// one today is exactly what #54 spent an audit round collapsing. A group that
// has been collected refuses to signal anything, for every caller, without any
// of them having to remember.
//
// # What it costs
//
// A job the session left running dies when the session's command exits rather
// than after the drain that follows it — the same process, killed by the same
// signal, a quarter of a second earlier. What that gives up is the tail of that
// job's output, which was on its way to a session that has ended. The session's
// own farewell is unaffected: the leader wrote it before it exited and it is
// already in the terminal, which nothing here closes.
//
// # Windows
//
// One file for both platforms, because the difference is no longer here. There
// is no sweep on Windows and no ordering to keep: the session's group was
// created with KillOnClose, the agent holds the only handle to the job, and a
// job object is a kernel object reached through a handle rather than a number
// the kernel reclaims. Both are properties of the platform and both are stated
// in platform.ProcessGroup.Collect's Windows implementation, which is what this
// call reaches there.
func sweepAndCollect(cmd *pty.Cmd, group *platform.ProcessGroup, log *slog.Logger) error {
	// WARN, and not decoration: the sweep is the step that makes "a session
	// takes its process tree with it" true, so a failure here is a process
	// still running on the host after the session that started it has ended. A
	// group with nothing left in it is not one of those, and neither is a group
	// the handler has already released; SweepAndCollect reports neither.
	groupErr, waitErr := group.SweepAndCollect(cmd.Wait)
	if groupErr != nil {
		log.Warn("could not sweep the session's process group; a descendant may have outlived the session",
			"error", groupErr)
	}
	return waitErr
}
