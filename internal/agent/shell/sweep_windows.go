package shell

import "github.com/axelmierczuk/fleet-mcp/internal/platform"

// sweepGroup has nothing to do on Windows, and that is the correct behaviour
// rather than a gap — the same conclusion ExecService reached, and this
// repository has already shipped the bug that argues for it.
//
// The session's group was created with KillOnClose, the agent holds the only
// handle to the job, and closing it — the next statement at the call site —
// terminates every process still inside. Signalling as well would add no
// guarantee and would take one away: platform's terminate kills the job and
// then, separately, the leader by pid, and by this point the wait has released
// the leader's handle. Windows hands pids back out from a free list rather than
// in increasing order, so that second call can name a process started by
// something else in the meantime — which is how a group kill once terminated an
// entirely unrelated process. Pid is not identity.
func sweepGroup(*platform.ProcessGroup) error { return nil }
