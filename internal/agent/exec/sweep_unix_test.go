//go:build unix

package exec

import (
	"io"
	"log/slog"
	"os"
	osexec "os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// noSuchPID is past every pid this can run on — Linux caps pid_max at 2^22 and
// Darwin at 99999 — so awaitExit cannot establish anything about it, whichever
// call it makes.
const noSuchPID = 1 << 30

// awaitExit reports the exit and leaves the status for os/exec to collect.
//
// That second half is the whole safety argument of the sweep: an unreaped
// leader is still a member of its own process group, so the kernel cannot hand
// that group id to anything else, and the SIGKILL the sweep sends can only
// reach the tree the command led. A wait that collected the status instead
// would release the id at exactly the moment the sweep is about to name it —
// and it would take the command's exit status away from the caller as well,
// which is what the assertions below fail on.
//
// syscall.Wait4 with WNOWAIT is that mutation, and it is not a hypothetical:
// Darwin accepts the flag and reaps anyway, which is why that platform watches
// for the exit through kqueue instead.
func TestAwaitExit_ReportsTheExitWithoutCollectingIt(t *testing.T) {
	cmd := osexec.Command(mustExecutable(t), "9") //nolint:gosec // the test binary re-executing itself
	cmd.Env = append(os.Environ(), helperEnvFor("exit"))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	require.NoError(t, cmd.Start())

	require.NoError(t, awaitExit(cmd.Process.Pid))

	// Still there to be collected, and still carrying what the command did.
	require.Error(t, cmd.Wait(), "the command exited 9, so Wait must report it")
	require.NotNil(t, cmd.ProcessState,
		"awaitExit collected the child itself: os/exec has no status left to report, and the group id was released before the sweep names it")
	require.Equal(t, 9, cmd.ProcessState.ExitCode())
}

// A command that has already exited has still exited.
//
// The sweep exists for `sh -c 'sleep 100 &'`, which is a zombie by the time
// anything looks at it, so this is the ordinary case rather than a corner. It
// is a corner for the kernel interface underneath: Darwin's EVFILT_PROC
// attaches through proc_find, which skips zombies, so registering a watch on
// one fails with ESRCH — and an implementation that took that at face value
// would report "cannot watch this pid" as an error, decline to sweep, and leave
// the descendant running on the host every single time.
//
// stdout reaching EOF is what establishes the exit before awaitExit is called:
// os/exec closes the parent's copy of the write end after Start, so the only
// holder left is the command itself.
func TestAwaitExit_ACommandThatHasAlreadyExitedIsStillAnExit(t *testing.T) {
	cmd := osexec.Command(mustExecutable(t), "done") //nolint:gosec // the test binary re-executing itself
	cmd.Env = append(os.Environ(), helperEnvFor("echo"))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	written, err := io.ReadAll(stdout)
	require.NoError(t, err)
	require.Equal(t, "done", string(written),
		"the command did not run to completion, so what follows is not about a process that had already exited")

	require.NoError(t, awaitExit(cmd.Process.Pid),
		"the command had exited, and a wait for its exit reported a failure instead")
	require.NoError(t, cmd.Wait())
	require.Equal(t, 0, cmd.ProcessState.ExitCode())
}

// A pid awaitExit cannot watch is an error, not an exit.
//
// The distinction is the fail-safe's entire input. On Darwin a failed kqueue
// registration is not reported through the syscall's own error at all: kevent
// puts it in the event list with EV_ERROR set and returns a count, so an
// implementation that only checks for a non-nil error reads "cannot watch this
// pid" as "it has exited" — and sweeps a group it has established nothing
// about, which is #91 with an extra step.
func TestAwaitExit_APidItCannotWatchIsAnError(t *testing.T) {
	require.Error(t, awaitExit(noSuchPID))
}

// waitForCommand sweeps the group and still returns the command's own status.
//
// Both halves matter and neither implies the other. A sweep that never fires
// leaves the descendant running; one that fires before the leader has exited
// kills the command instead of what it left behind, and the status says so.
func TestWaitForCommand_SweepsTheGroupAndReturnsTheStatus(t *testing.T) {
	group, cmd, descendant := commandWithADescendant(t)
	logs := &strings.Builder{}

	require.NoError(t, waitForCommand(cmd, group, testLogger(logs)),
		"the command exited 0 of its own accord")
	require.NotNil(t, cmd.ProcessState)
	require.Equal(t, 0, cmd.ProcessState.ExitCode())
	_, signalled := terminatingSignal(cmd.ProcessState)
	require.False(t, signalled,
		"the command was killed rather than left to exit, so the sweep went out before the leader had exited")

	// Nothing was skipped and nothing failed on the way. Asserted before the
	// descendant is looked for, because either of these explains a survivor and
	// "the pid is still there" does not say which.
	require.NotContains(t, logs.String(), "so it was not swept")
	require.NotContains(t, logs.String(), "could not sweep the process group")
	requireProcessGone(t, descendant)
}

// A sweep whose ground could not be established is not sent at all.
//
// awaitExit is what establishes it, and it can fail. Sending anyway would mean
// SIGKILL to a group id whose ownership nothing has checked, which is the exact
// call #91 is about; not sending it leaves a descendant running, which is a
// broken guarantee and logged as one. The second is the one worth choosing:
// the descendant is at least this agent's own.
//
// The failure is arranged by handing waitForCommand a leader this process is
// not the parent of, which is what awaitExit's two implementations both refuse.
// There is no seam here and no fake: it is the product function, taking the
// branch it takes on a real error.
func TestWaitForCommand_DoesNotSweepAGroupItCouldNotGround(t *testing.T) {
	group, child := isolatedChild(t)
	logs := &strings.Builder{}

	stranger, err := os.FindProcess(noSuchPID)
	require.NoError(t, err)
	cmd := &osexec.Cmd{Path: mustExecutable(t)}
	cmd.Process = stranger

	require.Error(t, waitForCommand(cmd, group, testLogger(logs)),
		"there is no such process to wait for, so Wait has nothing to report either")

	// What the child ends up dying of is the recorded fact, and the only one
	// that settles it: a process that has been sent SIGKILL is not
	// distinguishable from a running one by asking whether its pid exists — the
	// answer is yes either way until somebody reaps the zombie. So this kills
	// it deliberately, with a different signal, and reads back which arrived. A
	// sweep that went out first is already pending and wins.
	require.NoError(t, child.Process.Signal(syscall.SIGTERM))
	_ = child.Wait()
	require.NotNil(t, child.ProcessState)
	sig, signalled := terminatingSignal(child.ProcessState)
	require.True(t, signalled)
	require.Equal(t, "SIGTERM", sig,
		"the child died of a SIGKILL: the group was swept even though nothing had established that it was still the command's")

	require.Contains(t, logs.String(), "so it was not swept; a descendant may have outlived the call",
		"the guarantee was dropped silently: a descendant is still running on the host and nothing in the daemon's log says so")
}

// isolatedChild starts a long-lived helper leading its own process group, the
// way run starts a command. mode defaults to a helper that just sleeps.
func isolatedChild(t *testing.T, mode ...string) (*platform.ProcessGroup, *osexec.Cmd) {
	t.Helper()

	group, err := platform.NewProcessGroup(platform.GroupConfig{KillOnClose: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = group.Close() })

	helper, arg := "sleep", "600"
	if len(mode) > 0 {
		helper, arg = mode[0], mode[1]
	}
	cmd := osexec.Command(mustExecutable(t), arg) //nolint:gosec // the test binary re-executing itself
	cmd.Env = append(os.Environ(), helperEnvFor(helper))
	group.ConfigureCommand(cmd)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = group.Kill()
		_ = cmd.Wait()
	})
	require.NoError(t, group.Adopt(cmd.Process))
	require.True(t, group.Isolated(),
		"the child does not lead its own group, so there is nothing here for a sweep to be right or wrong about")

	return group, cmd
}

// commandWithADescendant starts the shape the sweep exists for: a leader that
// exits leaving a descendant of its own in the group, with the descendant's pid
// read back from the file it wrote rather than from anything the agent reports.
func commandWithADescendant(t *testing.T) (*platform.ProcessGroup, *osexec.Cmd, int) {
	t.Helper()

	group, err := platform.NewProcessGroup(platform.GroupConfig{KillOnClose: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = group.Close() })

	pidFile := t.TempDir() + "/descendant.pid"
	cmd := osexec.Command(mustExecutable(t), pidFile) //nolint:gosec // the test binary re-executing itself
	cmd.Env = append(os.Environ(), helperEnvFor("spawn-exit"))
	group.ConfigureCommand(cmd)
	require.NoError(t, cmd.Start())
	require.NoError(t, group.Adopt(cmd.Process))
	require.True(t, group.Isolated(),
		"the command does not lead its own group, so its descendant was never in one to sweep")

	_, descendant := readPIDs(t, pidFile)
	t.Cleanup(func() { _ = group.Kill() })
	return group, cmd, descendant
}

func testLogger(into *strings.Builder) *slog.Logger {
	return slog.New(slog.NewTextHandler(into, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func mustExecutable(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	require.NoError(t, err)
	return self
}
