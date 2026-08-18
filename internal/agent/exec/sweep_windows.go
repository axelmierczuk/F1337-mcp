package exec

import (
	"log/slog"
	osexec "os/exec"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// waitForCommand reaps a finished command, and sweeps nothing.
//
// Deliberately so: the group was created with KillOnClose, the agent holds the
// only handle to the job, and closing it — the last statement of run's deferred
// cleanup — terminates every process still inside. That is the job object doing
// exactly what exec asked it for, and an extra signal would add no guarantee to
// it.
//
// Nor is there an ordering to keep. The Unix file sends its sweep between the
// leader exiting and Wait collecting it because a process group there is a
// number the kernel reclaims, and an unreaped leader is what keeps the number
// the command's own. Windows has nothing to pin because it has nothing to
// reclaim: a job object is a kernel object reached through a handle, and
// [platform.ProcessGroup] holds a handle to the leader as well, from Adopt
// until Close, so neither the job nor the leader's pid can come to name
// anything else while the group can still be asked to signal them.
//
// That last part is newer than this file. It used to say a signal here would
// take a guarantee away, because platform's terminate killed the job and then
// the leader by pid, after Wait had released os/exec's handle — and Windows
// hands pids back out from a free list rather than in increasing order. The
// group's own handle is what closed that, and terminate works from it now; see
// terminateLeader. What remains true is the first half, which is the reason
// this function does nothing.
//
// Cmd.WaitDelay is what bounds a wait that a descendant holding the output
// pipes would otherwise stretch.
func waitForCommand(cmd *osexec.Cmd, _ *platform.ProcessGroup, _ *slog.Logger) error {
	return cmd.Wait()
}
