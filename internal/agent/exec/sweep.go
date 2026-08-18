package exec

import (
	"log/slog"
	osexec "os/exec"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// waitForCommand reaps a finished command through its process group, sweeping
// whatever the command left behind on the way.
//
// # Why the group performs the collection
//
// The sweep is the SIGKILL that kills whatever is left of the command's tree. A
// Unix process group holds no kernel object, so nothing has reached a
// grandchild that outlived its parent — `sh -c 'sleep 100 &'` leaves one behind
// — and an explicit signal to the group is the only thing that will.
//
// It is only safe to send between the leader exiting and Wait collecting it,
// because the leader's own zombie is what keeps the group id the command's own.
// That much was #91, and this file used to write those two calls in that order
// and stop there. Writing them in an order is not enough: the *watcher* signals
// the same group, from another goroutine, and decides to on a timer — so the
// order that matters is not between two lines here but between every signal
// this package sends and the one collection that releases the id.
//
// Which is why the collection goes through [platform.ProcessGroup.SweepAndCollect]
// rather than around it. The group takes its own lock across the sweep and the
// release, and refuses to signal anything afterwards, so the watcher's kill is
// either aimed at a group an uncollected leader is still holding or refused
// outright. There is no third case and no window between them. That is #105,
// and it is the same fix for internal/agent/shell, which calls the same method.
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
// # Windows
//
// One file for both platforms now, because the difference is no longer here.
// Windows sweeps nothing — the group was created with KillOnClose, the agent
// holds the only handle to the job, and closing it is what terminates every
// process still inside — and it has no ordering to keep either, because a job
// object is a kernel object reached through a handle rather than a number the
// kernel reclaims. Both of those are properties of the platform, and both are
// stated where they belong, in platform.ProcessGroup.Collect's Windows
// implementation. This call reads the same on either.
func waitForCommand(cmd *osexec.Cmd, group *platform.ProcessGroup, log *slog.Logger) error {
	// WARN, and not decoration: the sweep is the step that makes "exec takes
	// its process tree with it" true, so a failure here is a descendant still
	// running on the host after the RPC that started it has returned. At DEBUG
	// — which is not the level a daemon runs at — a broken guarantee would be
	// invisible exactly where it matters.
	//
	// A group with nothing left in it is not one of those, and neither is a
	// group the handler has already released: run releases it on its way out
	// while this wait may still be watching for the leader. Both are ordinary
	// answers, and SweepAndCollect reports neither.
	groupErr, waitErr := group.SweepAndCollect(cmd.Wait)
	if groupErr != nil {
		log.Warn("could not sweep the command's process group; a descendant may have outlived the call",
			"error", groupErr)
	}
	return waitErr
}
