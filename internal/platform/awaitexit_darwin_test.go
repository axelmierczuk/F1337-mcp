package platform

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
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
// never ours to watch, and answering "exited" to it hands a caller a green
// light to SIGKILL a process group nothing has established the ownership of.
// Which is #91, one level down.
//
// The fixture is a grandchild whose own parent will not reap it — see
// unreapedGrandchild. A zombie rather than a running process because a running
// one is watchable, and the branch under test is only reached once the kernel
// has refused.
func TestAwaitExit_AZombieBelongingToSomebodyElseIsNotAnExit(t *testing.T) {
	group, cmd, grandchild := unreapedGrandchild(t)

	require.NoError(t, unix.Kill(grandchild, unix.SIGKILL))
	requireZombie(t, grandchild)

	require.Error(t, AwaitExit(grandchild),
		"a zombie this process is not the parent of was reported as an exit, so a sweep would go out on a group id nobody has established the ownership of")
	require.False(t, isOurUncollectedChild(grandchild))

	// And the same call on this process's own child does report the exit, so
	// the assertion above is about whose zombie it is rather than about
	// awaitExit refusing everything.
	require.NoError(t, group.Kill())
	require.NoError(t, AwaitExit(cmd.Process.Pid))
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
// to sweep about one run in two under load.
//
// A plainly running child is the deterministic way to state it: the process
// table reports it as running, and the answer is still yes, because the
// question is whose process it is.
func TestIsOurUncollectedChild_DoesNotDependOnHowFarTheExitHasGot(t *testing.T) {
	_, cmd := isolatedLeader(t, "exec sleep 600")

	proc, err := unix.SysctlKinfoProc("kern.proc.pid", cmd.Process.Pid)
	require.NoError(t, err)
	require.NotEqual(t, int8(zombieState), proc.Proc.P_stat,
		"the fixture sleeps for ten minutes; if it is already a zombie this test is not about a running process")

	require.True(t, isOurUncollectedChild(cmd.Process.Pid),
		"a child of this process was disowned for not having finished exiting, so the sweep it belongs to is skipped for as long as the kernel takes over the teardown")
}

// Sweep translates the one answer Kill gives that a sweep must not read as a
// failure.
//
// This is the platform the translation exists for, and the only one where it
// is observable: a group holding nothing but its leader's uncollected zombie
// is refused with EPERM here and delivered to on Linux. Kill reports it as it
// came, which is right for a supervisor escalating a stop — a group it may not
// signal is a live group. Sweep is the caller that has just watched the leader
// exit, so for it the same errno means the command left nothing behind, and
// reporting a failure put a WARN into every successful exec on this platform.
//
// Both calls are made, in that order, so this cannot pass by Sweep and Kill
// being the same function.
func TestSweep_TranslatesWhatKillSaysAboutAGroupWithNothingInIt(t *testing.T) {
	group, cmd := isolatedLeader(t, "exit 0")
	require.NoError(t, AwaitExit(cmd.Process.Pid))

	killErr := group.Kill()
	require.ErrorIs(t, killErr, unix.EPERM,
		"Darwin no longer refuses a signal to a group holding only a zombie, so Sweep's translation is answering a question the kernel has stopped asking")
	require.NotErrorIs(t, killErr, ErrProcessNotFound)

	require.ErrorIs(t, group.Sweep(), ErrProcessNotFound,
		"the sweep reported a group with nothing left in it as a failure, which its caller logs as a descendant still running on the host")
	require.NoError(t, cmd.Wait())
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
			t.Fatalf("pid %d never became a zombie; its parent collected it, and the fixture is not the shape this test needs: %v", pid, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// unreapedGrandchild starts a leader that spawns a background child and then
// execs, so that nothing will ever collect what it spawned.
//
// The exec is the trick and it is not decoration: a shell reaps its own
// background jobs, so a fixture that left one running would be a fixture whose
// zombie disappears. Replacing the shell's image with sleep(1) keeps the pid,
// keeps the parent-child relationship, and removes the only thing that would
// have waited.
func unreapedGrandchild(t *testing.T) (*ProcessGroup, *exec.Cmd, int) {
	t.Helper()

	pidFile := t.TempDir() + "/pids"
	group, cmd := isolatedLeader(t,
		"sleep 600 & echo $$ $! > "+pidFile+"; exec sleep 600")
	_, grandchild := readPIDFile(t, pidFile)
	return group, cmd, grandchild
}

func readPIDFile(t *testing.T, path string) (first, second int) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			fields := strings.Fields(string(data))
			if len(fields) == 2 {
				a, err1 := strconv.Atoi(fields[0])
				b, err2 := strconv.Atoi(fields[1])
				if err1 == nil && err2 == nil {
					return a, b
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the fixture never wrote its pids to %s", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
