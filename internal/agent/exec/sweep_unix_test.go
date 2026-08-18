//go:build unix

package exec

import (
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
// Darwin at 99999 — so platform.AwaitExit cannot establish anything about it,
// whichever call it makes.
const noSuchPID = 1 << 30

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
	require.NotContains(t, logs.String(), "without being swept")
	require.NotContains(t, logs.String(), "could not sweep the command's process group")
	requireProcessGone(t, descendant)
}

// A command that left nothing behind is swept in silence.
//
// Which is most commands, and the reason it is asserted: the sweep signals a
// group whose only member is the leader's own uncollected zombie, and Darwin
// answers EPERM to that — "there is a group and nothing in it that can take a
// signal". Reported as a failure it put a WARN saying a descendant may have
// outlived the call into every successful exec on that platform, which is how
// a diagnostic stops being read. platform.ProcessGroup.Sweep is what makes
// both platforms say "nothing left" the same way.
func TestWaitForCommand_ACommandThatLeftNothingBehindLogsNothing(t *testing.T) {
	group, cmd := isolatedChild(t, "exit", "0")
	logs := &strings.Builder{}

	require.NoError(t, waitForCommand(cmd, group, testLogger(logs)))
	require.Equal(t, 0, cmd.ProcessState.ExitCode())
	require.Empty(t, logs.String(),
		"a command that left no descendant reported a broken guarantee; the sweep's ordinary answer is being read as a failure")
}

// A sweep whose ground could not be established is not sent at all.
//
// platform.AwaitExit is what establishes it, and it can fail. Sending anyway
// would mean SIGKILL to a group id whose ownership nothing has checked, which
// is the exact call #91 is about; not sending it leaves a descendant running,
// which is a broken guarantee and logged as one. The second is the one worth
// choosing: the descendant is at least this agent's own.
//
// The failure is arranged by giving the group a leader this process is not the
// parent of, which is what AwaitExit's two implementations both refuse. There
// is no seam here and no fake: it is the product function, taking the branch it
// takes on a real error.
//
// What a sweep sent anyway would have *reached* is asserted where an id can be
// pointed at something on purpose: platform's
// TestCollect_AnExitItCouldNotEstablishGivesUpTheIDWithoutSweepingIt puts a
// stranger's live session on the id and requires it to survive. Here the
// assertion is the daemon's own report, which is the half this package owns.
func TestWaitForCommand_DoesNotSweepAGroupItCouldNotGround(t *testing.T) {
	group, err := platform.NewProcessGroup(platform.GroupConfig{KillOnClose: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = group.Close() })

	// Configured, so the group believes a session was asked for: a pid that is
	// already gone reads as "the child led its own session and exited", which
	// is the state a fast leader is really in and the one that leaves this
	// group with an id it thinks it can sweep.
	var attr syscall.SysProcAttr
	group.Configure(&attr)

	stranger, err := os.FindProcess(noSuchPID)
	require.NoError(t, err)
	require.NoError(t, group.Adopt(stranger))
	require.True(t, group.Isolated(),
		"the group does not think it has an id of its own, so there is nothing here for the check to refuse")

	logs := &strings.Builder{}
	cmd := &osexec.Cmd{Path: mustExecutable(t), Process: stranger}
	require.Error(t, waitForCommand(cmd, group, testLogger(logs)),
		"there is no such process to wait for, so Wait has nothing to report either")

	require.Contains(t, logs.String(), "could not sweep the command's process group; a descendant may have outlived the call",
		"the guarantee was dropped silently: a descendant is still running on the host and nothing in the daemon's log says so")
	require.Contains(t, logs.String(), "without being swept",
		"the log says the sweep failed rather than that it was never sent, which are different things to whoever reads it")
}

// isolatedChild starts a helper leading its own process group, the way run
// starts a command.
func isolatedChild(t *testing.T, mode, arg string) (*platform.ProcessGroup, *osexec.Cmd) {
	t.Helper()

	group, err := platform.NewProcessGroup(platform.GroupConfig{KillOnClose: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = group.Close() })

	cmd := osexec.Command(mustExecutable(t), arg) //nolint:gosec // the test binary re-executing itself
	cmd.Env = append(os.Environ(), helperEnvFor(mode))
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
