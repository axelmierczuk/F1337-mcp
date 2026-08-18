package exec

import (
	"fmt"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// zombieState is SZOMB from <sys/proc.h>: exited, and awaiting collection by
// its parent. x/sys does not export the p_stat values.
//
// Only the fixture below reads it. awaitExit deliberately does not: a process
// the kernel has started tearing down is not SZOMB yet and is exactly as
// uncollectable, and a check for this value refuses its own leader about half
// the time under load.
const zombieState = 5

// A zombie belonging to somebody else is not an exit this agent knows about.
//
// awaitExit reads ESRCH from a kqueue registration as "it is on its way out",
// because EVFILT_PROC attaches through proc_find and proc_find refuses a
// process that is exiting or exited. That reading is only sound for a child
// this process has not collected: for anything else ESRCH means the pid was
// never ours to watch, and answering "exited" to it hands waitForCommand a
// green light to SIGKILL a process group nothing has established the ownership
// of. Which is #91, one level down.
//
// The fixture is a grandchild whose own parent will not reap it: the spawn
// helper waits without waiting on its child, so killing that child leaves a
// zombie that belongs to the helper and not to this process. A zombie rather
// than a running process because a running one is watchable, and the branch
// under test is only reached once the kernel has refused.
func TestAwaitExit_AZombieBelongingToSomebodyElseIsNotAnExit(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "unreaped.pid")
	group, cmd := isolatedChild(t, "spawn", pidFile)
	t.Cleanup(func() { _ = group.Kill() })
	_, grandchild := readPIDs(t, pidFile)

	require.NoError(t, syscall.Kill(grandchild, syscall.SIGKILL))
	requireZombie(t, grandchild)

	require.Error(t, awaitExit(grandchild),
		"a zombie this process is not the parent of was reported as an exit, so a sweep would go out on a group id nobody has established the ownership of")
	require.False(t, isOurUncollectedChild(grandchild))

	// And the same call on this process's own child does report the exit, so
	// the assertion above is about whose zombie it is rather than about
	// awaitExit refusing everything.
	require.NoError(t, group.Kill())
	require.NoError(t, awaitExit(cmd.Process.Pid))
	require.True(t, isOurUncollectedChild(cmd.Process.Pid))
	_ = cmd.Wait()
}

// isOurUncollectedChild answers about ownership, and not about how far along
// the exit is.
//
// The distinction is not academic. awaitExit only asks once the kernel has
// refused to treat the pid as a running process, and the process table does not
// agree with that refusal instantly: proc_find rejects a process the moment the
// exit starts, while p_stat says SRUN until the teardown is finished. A check
// that also insisted on SZOMB therefore refused its own leader for the width of
// that gap — which is a real interval, not a theoretical one, and it declined
// to sweep about one run in two with this package under load.
//
// A plainly running child is the deterministic way to state it: the process
// table reports it as running, and the answer is still yes, because the
// question is whose process it is.
func TestIsOurUncollectedChild_DoesNotDependOnHowFarTheExitHasGot(t *testing.T) {
	_, cmd := isolatedChild(t)

	proc, err := unix.SysctlKinfoProc("kern.proc.pid", cmd.Process.Pid)
	require.NoError(t, err)
	require.NotEqual(t, int8(zombieState), proc.Proc.P_stat,
		"the fixture sleeps for ten minutes; if it is already a zombie this test is not about a running process")

	require.True(t, isOurUncollectedChild(cmd.Process.Pid),
		"a child of this process was disowned for not having finished exiting, so the sweep it belongs to is skipped for as long as the kernel takes over the teardown")
}

// requireZombie waits for a process to become an uncollected zombie, which is a
// state and not a duration: the kill above is asynchronous and the process has
// to be scheduled to die.
func requireZombie(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		proc, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
		if err == nil && proc != nil && proc.Proc.P_stat == zombieState {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pid %d never became a zombie; its parent collected it, and the fixture is not the shape this test needs: %v", pid, fmt.Sprint(err))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
