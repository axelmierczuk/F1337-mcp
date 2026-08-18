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
// exactly what exec asked it for.
//
// Signalling as well would not add a guarantee, and it would take one away.
// platform's terminate kills the job and then, separately, the leader by pid.
// By that point Wait has reaped the leader and released its handle, and Windows
// hands pids back out from a free list rather than in increasing order — so
// that second call can name a process started by something else in the
// meantime.
//
// Unix has the same hazard and no job object to fall back on, which is why the
// Unix file sends its sweep between the leader exiting and Wait collecting it:
// an unreaped leader pins its group id. Windows has nothing to pin because it
// has nothing to send, and Cmd.WaitDelay is what bounds a wait that a
// descendant holding the output pipes would otherwise stretch.
func waitForCommand(cmd *osexec.Cmd, _ *platform.ProcessGroup, _ *slog.Logger) error {
	return cmd.Wait()
}
