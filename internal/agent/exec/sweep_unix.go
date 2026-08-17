//go:build !windows

package exec

import "github.com/axelmierczuk/sandboxd-mcp/internal/platform"

// sweepGroup kills whatever is left of a finished command's process group.
//
// A Unix process group holds no kernel object, so nothing has reached a
// grandchild that outlived its parent — `sh -c 'sleep 100 &'` leaves one behind
// — and an explicit signal to the group is the only thing that will.
//
// It is sent after Wait has reaped the leader, so the group id it names is a
// pid the kernel may have handed to something else. On Unix that is a
// theoretical rather than a practical hazard: the new process would have to
// receive that exact pid and then make itself a process-group leader with it,
// and pids are handed out in increasing order, so reaching a specific one again
// means wrapping the whole pid space between Wait returning and the next
// statement. An empty group answers ESRCH, which the caller ignores.
func sweepGroup(g *platform.ProcessGroup) error { return g.Kill() }
