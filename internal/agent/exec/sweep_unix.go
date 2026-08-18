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
// It goes out between the leader exiting and Wait collecting it, because the
// leader's own zombie is what keeps the group id the command's own. That
// argument, the measurements behind it and what the old ordering cost are in
// [platform.AwaitExit], which is where the ordering now lives so that
// internal/agent/shell keeps the same one rather than a third copy of it.
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
// A group with nothing left in it is the ordinary answer here and not a
// failure; [platform.ProcessGroup.Sweep] is what makes both platforms say that
// the same way.
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

	if err := platform.AwaitExit(cmd.Process.Pid); err != nil {
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
	//
	// ErrGroupClosed is not one either: run releases the group on its way out,
	// and the path where it gives up on a stalled stream leaves it while this
	// wait is still watching for the leader. A sweep that arrives afterwards
	// finds a group the call has given up, and the kill that ended the command
	// went out before the release.
	err := group.Sweep()
	if err != nil && !errors.Is(err, platform.ErrProcessNotFound) && !errors.Is(err, platform.ErrGroupClosed) {
		log.Warn("could not sweep the process group after exec; a descendant may have outlived the call",
			"error", err)
	}
	return cmd.Wait()
}
