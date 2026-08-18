//go:build unix

package exec

import (
	"errors"
	"log/slog"
	osexec "os/exec"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// waitForCommand reaps a finished command, sweeping its process group first.
//
// The sweep is the SIGKILL that kills whatever is left of the command's tree. A
// Unix process group holds no kernel object, so nothing has reached a
// grandchild that outlived its parent — `sh -c 'sleep 100 &'` leaves one
// behind — and an explicit signal to the group is the only thing that will.
//
// # The order is the whole of it
//
// kill(-pgid) names a number, and that number is a pid. The kernel keeps it
// reserved for exactly as long as some process is still attached to it: the
// leader, alive or an unreaped zombie, or any surviving member of its group.
// Once the last of those is gone the id is free, and the next process group to
// be given it belongs to somebody else.
//
// So the sweep goes out between the leader exiting and Wait collecting it. The
// leader's own zombie is what makes that safe — a group with an unreaped member
// cannot have its id reused, so the group this signals is always the one the
// command led.
//
// It used to be sent from run's deferred cleanup, after Wait had reaped, on the
// argument that reaching a specific pid again means wrapping the whole pid space
// in the microseconds between the two statements. Every step of that is true and
// the conclusion was not, in two ways #91 records:
//
//   - The window is not microseconds. Wait does not return until the output
//     copiers do, and a grandchild that inherited the pipes holds them for the
//     whole of Cmd.WaitDelay — seconds, in precisely the case the sweep exists
//     for.
//   - The wrap happens. #82's identical call answered EPERM four times in 2400
//     runs on a loaded 12-core host, which is a signal that reached a process
//     owned by somebody else, and instrumenting it caught the id being handed
//     out again to a new session leader.
//
// Reproduced deterministically in a pid namespace, where ns_last_pid places the
// next pid exactly: reap the leader of an emptied group, hand its id to an
// unrelated session leader, make the call this used to make — the bystander
// dies of SIGKILL. The same run shows the kernel refusing to hand out that id at
// all while the zombie is still there.
//
// Note what that says about the old ordering. Any surviving descendant pins the
// group id too, so the id could only be stale once the group had emptied: the
// call was misdirectable exactly when it had nothing to do, and killed a
// stranger's tree in exchange for nothing.
//
// # What it costs
//
// A grandchild now dies when the command does rather than at the end of
// Cmd.WaitDelay. That is the same descendant, killed by the same signal, a
// drain earlier — and it is what the package promises: a grandchild that
// outlived its parent must not outlive the RPC. What it gives up is the tail of
// that grandchild's output, which was on its way to a caller the agent had
// already committed to killing it out from under. WaitDelay still bounds the
// wait for a descendant the sweep cannot reach, which is one that left the
// group.
//
// An empty group answers ESRCH, which is the ordinary answer here and not a
// failure.
func waitForCommand(cmd *osexec.Cmd, group *platform.ProcessGroup, log *slog.Logger) error {
	if !group.Isolated() {
		// The group has degraded to "signal this one pid", and there is
		// nothing left to sweep anyway: a leader that never got its own group
		// had no group for its descendants to be in.
		//
		// This used to be load-bearing and is now only a syscall saved.
		// ProcessGroup.Signal aims a degraded group at the leader's pid rather
		// than at a group id, and after the reap that pid could belong to
		// anything — so skipping it was the only thing keeping a stranger's
		// process out of range. Sending before the reap makes even that call
		// safe, because the pid it names is the one the zombie is holding.
		return cmd.Wait()
	}

	if err := awaitExit(cmd.Process.Pid); err != nil {
		// Sweeping now would mean SIGKILL to a group id whose ownership
		// nothing has established, which is the call this whole ordering
		// exists to avoid. Not sweeping leaves a descendant running on the
		// host, which is a broken guarantee — and the one worth choosing,
		// because the descendant is at least this agent's own.
		log.Warn("could not establish that the command's process group is still its own, so it was not swept; a descendant may have outlived the call",
			"error", err)
		return cmd.Wait()
	}

	// WARN, and not decoration: this is the step that makes "exec takes its
	// process tree with it" true, so a failure here is a descendant still
	// running on the host after the RPC that started it has returned. At DEBUG
	// — which is not the level a daemon runs at — a broken guarantee would be
	// invisible exactly where it matters.
	if err := group.Kill(); err != nil && !errors.Is(err, platform.ErrProcessNotFound) {
		log.Warn("could not sweep the process group after exec; a descendant may have outlived the call",
			"error", err)
	}
	return cmd.Wait()
}
