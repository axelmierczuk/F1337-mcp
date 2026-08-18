//go:build !windows

package shell

import (
	"log/slog"

	"github.com/aymanbagabas/go-pty"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// sweepAndCollect kills whatever is left of the session's process group and
// then collects its leader, in that order and holding the lock that keeps them
// in it.
//
// The sweep is the same call, for the same reason, as ExecService's: a Unix
// process group holds no kernel object, so nothing has reached a process that
// outlived the shell, and an explicit signal to the group is the only thing
// that will.
//
// What changed is when it goes out. It used to be sent from run's deferred
// cleanup, after the wait had collected the leader, on the argument that
// reaching a specific pid again means wrapping the whole pid space in the
// microseconds between the two — which is true about pids and wrong about the
// window and about the event. [platform.AwaitExit] carries that argument, the
// measurements that disproved it and the pid-namespace run that reproduces it
// on demand. Here it goes out between the leader exiting and Wait collecting
// it, so the leader's own zombie is what makes the group id unmistakably the
// session's.
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
// It also means the group is usually empty by the time [Service.reap] would
// have killed it, which is why the teardown's kill now asks first. See
// [leaderWait.mayStillSignal].
func (l *leaderWait) sweepAndCollect(cmd *pty.Cmd, group *platform.ProcessGroup, log *slog.Logger) error {
	if err := platform.AwaitExit(cmd.Process.Pid); err != nil {
		// Sweeping now would mean SIGKILL to a group id whose ownership nothing
		// has established, which is the call this whole ordering exists to
		// avoid. Not sweeping leaves a descendant running on the host, which is
		// a broken guarantee — and the one worth choosing, because the
		// descendant is at least this agent's own.
		//
		// Collected without the lock, and it has to be: this is the one branch
		// on which the leader may still be running, so holding it across the
		// wait would block the teardown's kill — which is the thing that would
		// end the leader.
		log.Warn("could not establish that the session's process group is still its own, so it was not swept; a descendant may have outlived the session",
			"error", err)
		err := cmd.Wait()
		l.mu.Lock()
		l.collected = true
		l.mu.Unlock()
		return err
	}

	// Past here the leader has exited and nothing has collected it, so the
	// lock can be held across the collection as well as the sweep: Wait has
	// nothing left to wait for, and no other signaller can slip between them.
	l.mu.Lock()
	defer l.mu.Unlock()

	if group.Isolated() {
		// WARN, and not decoration: this is the step that makes "a session
		// takes its process tree with it" true, so a failure here is a process
		// still running on the host after the session that started it has
		// ended. A group with nothing left in it is not one of those; see
		// platform.ProcessGroup.Sweep.
		l.signal(group.Sweep, log, "could not sweep the session's process group; a descendant may have outlived it")
	}
	err := cmd.Wait()
	l.collected = true
	return err
}

// mayStillSignal reports whether a signal to the session's group would still
// reach the session's own tree. Called with the lock held.
//
// Once the leader has been collected the answer is no, and it is not a
// question of confidence: the group either still holds a member, in which case
// the sweep above has already gone out to it, or it does not, in which case its
// id is free and names whatever the kernel has since given it to. Either way
// the teardown has nothing left to send and every reason not to send it.
func (l *leaderWait) mayStillSignal() bool { return !l.collected }
