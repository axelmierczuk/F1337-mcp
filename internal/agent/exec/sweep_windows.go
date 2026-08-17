package exec

import "github.com/axelmierczuk/sandboxd-mcp/internal/platform"

// sweepGroup kills whatever is left of a finished command's process group.
//
// Nothing to do here, and deliberately so: the group was created with
// KillOnClose, the agent holds the only handle to the job, and closing it — the
// next statement at the call site — terminates every process still inside.
// That is the job object doing exactly what exec asked it for.
//
// Signalling as well would not add a guarantee, and it would take one away.
// platform's terminate kills the job and then, separately, the leader by pid.
// By this point Wait has reaped the leader and released its handle, and Windows
// hands pids back out from a free list rather than in increasing order — so
// that second call can name a process started by something else in the
// meantime. On Unix the equivalent needs the pid space to wrap in the same
// microseconds, which is why that side still signals; here the free list makes
// it a real if unlikely way to terminate an innocent process, and there is
// nothing to gain by taking the chance.
func sweepGroup(*platform.ProcessGroup) error { return nil }
