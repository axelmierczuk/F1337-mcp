//go:build !windows

package shell

import "github.com/axelmierczuk/fleet-mcp/internal/platform"

// sweepGroup kills whatever is left of a finished session's process group.
//
// The same call, for the same reason, as ExecService's: a Unix process group
// holds no kernel object, so nothing has reached a process that outlived the
// shell, and an explicit signal to the group is the only thing that will. It
// runs after the session's leader has been reaped, so the group id it names is
// a pid the kernel may have reissued — a theoretical hazard here rather than a
// practical one, since pids are handed out in increasing order and reaching a
// specific one again means wrapping the whole pid space in the microseconds
// between the wait and this call.
//
// An empty group answers ESRCH, which the caller ignores.
func sweepGroup(g *platform.ProcessGroup) error { return g.Kill() }
