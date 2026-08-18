//go:build !windows

package shell

import (
	"os"
	"strconv"
	"syscall"
	"testing"

	"github.com/aymanbagabas/go-pty"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// noSuchPID is past every pid this can run on — Linux caps pid_max at 2^22 and
// Darwin at 99999 — so platform.AwaitExit cannot establish anything about it,
// whichever call it makes.
const noSuchPID = 1 << 30

// The wait sweeps what the session's command left behind, and does not touch
// the command.
//
// Both halves matter and neither implies the other. A sweep that never fires
// leaves the job running on the host; one that fires before the leader has
// exited kills the session itself rather than what it left, and the exit status
// is where that shows up — which is why the status is asserted before anything
// is asserted about the pid.
func TestSweepAndCollect_TakesTheTreeWithTheCommandThatLeftIt(t *testing.T) {
	group, cmd, printed := sessionCommand(t, "orphan")
	logs := &syncBuffer{}

	require.NoError(t, <-startLeaderWait(cmd, group, testLogger(logs)).waited,
		"the session's command exited 0 of its own accord")
	require.NotNil(t, cmd.ProcessState)
	require.Equal(t, 0, cmd.ProcessState.ExitCode())
	_, signalled := terminatingSignal(cmd.ProcessState)
	require.False(t, signalled,
		"the session's command was killed rather than left to exit, so the sweep went out before the leader had exited")

	// Asserted before the job is looked for, because either of these explains a
	// survivor and "the pid is still there" does not say which.
	require.NotContains(t, logs.String(), "so it was not swept")
	require.NotContains(t, logs.String(), "could not sweep")

	var orphan int
	waitFor(t, "the session's command to name the job it is leaving behind", func() (bool, string) {
		pids := parsePIDs(t, printed.String())
		if len(pids) == 1 {
			orphan = pids[0]
			return true, ""
		}
		return false, "the terminal printed: " + printed.String()
	})
	waitFor(t, "pid "+strconv.Itoa(orphan)+" to be gone", func() (bool, string) {
		if !processRunning(orphan) {
			return true, ""
		}
		return false, "pid " + strconv.Itoa(orphan) + " outlived the session that started it: the wait did not sweep the group"
	})
}

// A session that left nothing behind is swept in silence.
//
// Which is the ordinary ending — a user who types `exit` at a prompt with no
// jobs running leaves exactly an emptied group — and the reason it is asserted
// rather than assumed: the sweep signals a group whose only member is the
// leader's own uncollected zombie, and Darwin answers EPERM to that. Reported
// as a failure it puts a WARN saying a job may have outlived the session into
// every ordinary macOS session, which is how a diagnostic stops being read.
// platform.ProcessGroup.Sweep is what makes both platforms say "nothing left"
// the same way.
func TestSweepAndCollect_ASessionThatLeftNothingBehindLogsNothing(t *testing.T) {
	group, cmd, _ := sessionCommand(t, "exit", "0")
	logs := &syncBuffer{}

	require.NoError(t, <-startLeaderWait(cmd, group, testLogger(logs)).waited)
	require.Equal(t, 0, cmd.ProcessState.ExitCode())
	require.Empty(t, logs.String(),
		"a session that left no job behind reported a broken guarantee; the sweep's ordinary answer is being read as a failure")
}

// A sweep whose ground could not be established is not sent at all.
//
// platform.AwaitExit is what establishes it, and it can fail. Sending anyway
// would mean SIGKILL to a group id whose ownership nothing has checked, which
// is the exact call this issue is about; not sending it leaves a job running,
// which is a broken guarantee and logged as one. The second is the one worth
// choosing: the job is at least this agent's own.
//
// The failure is arranged by handing the wait a leader this process is not the
// parent of, which is what AwaitExit's two implementations both refuse. There
// is no seam here and no fake terminal: the group and the process in it are
// real, and it is the product function taking the branch it takes on a real
// error.
func TestSweepAndCollect_DoesNotSweepAGroupItCouldNotGround(t *testing.T) {
	group, child, _ := sessionCommand(t, "sleep")
	logs := &syncBuffer{}

	stranger, err := os.FindProcess(noSuchPID)
	require.NoError(t, err)
	wait := startLeaderWait(&pty.Cmd{Path: child.Path, Process: stranger}, group, testLogger(logs))
	require.Error(t, <-wait.waited,
		"there is no such process to wait for, so the wait has nothing to report either")

	requireDiedOfSIGTERM(t, child,
		"the session's own process died of a SIGKILL: the group was swept even though nothing had established that it was still the session's")

	require.Contains(t, logs.String(), "so it was not swept; a descendant may have outlived the session",
		"the guarantee was dropped silently: a process is still running on the host and nothing in the daemon's log says so")
}

// The teardown's kill is what ends a session that is still running.
//
// The guard below refuses a signal once the group id has been released, and a
// guard that refused everything would look exactly as green. So this is the
// other side of it: with the leader still running there is nothing to refuse,
// and the kill is what the session dies of.
func TestKillGroup_EndsASessionWhoseLeaderIsStillRunning(t *testing.T) {
	group, cmd, _ := sessionCommand(t, "sleep")
	logs := &syncBuffer{}

	wait := startLeaderWait(cmd, group, testLogger(logs))
	wait.killGroup(group, testLogger(logs))

	require.Error(t, <-wait.waited, "the session was killed, so its wait reports a signal rather than a status")
	sig, signalled := terminatingSignal(cmd.ProcessState)
	require.True(t, signalled)
	require.Equal(t, "SIGKILL", sig)
}

// And it is not sent at all once the wait has collected the leader.
//
// That is the whole of #96 on the teardown path. Service.reap sends its kill
// after a select on the wait, so the branch it takes when the hangup did end
// the session is the branch on which the leader has already been collected —
// and on Unix a process group id whose last member has been collected is a
// number the kernel has taken back and may already have given to somebody
// else's session leader. The group is swept by then in any case, from the wait
// itself, so there is nothing this call can add and a whole process group it
// could take away.
//
// So the group the kill is aimed at is a live one that the wait has nothing to
// do with, standing in for the session that now holds the number. Its own
// group could not stand in for it: that one has been emptied, so a signal to it
// reaches nothing and "it went out" would be unobservable. What settles it is
// what the stand-in dies of — see below, and see the Windows file, which is
// this fixture with the opposite expectation.
func TestKillGroup_DoesNotSignalAGroupIDTheWaitHasReleased(t *testing.T) {
	group, cmd, _ := sessionCommand(t, "exit", "0")
	wait := startLeaderWait(cmd, group, testLogger(&syncBuffer{}))
	require.NoError(t, <-wait.waited)

	aimedAt, bystander, _ := sessionCommand(t, "sleep")
	wait.killGroup(aimedAt, testLogger(&syncBuffer{}))
	requireDiedOfSIGTERM(t, bystander,
		"the teardown signalled a process group after its own id had been released; on a developer's machine that is whatever session holds the number now")
}

// And the teardown an operator's session actually goes through is what asks.
//
// The test above is about killGroup, and killGroup on its own proves nothing
// about the daemon: the shape this repository has shipped most often is a fix
// asserted by calling the repaired function, with nothing asserting that the
// path a caller takes reaches it. [Service.reap] is that path — it is what an
// idle timeout and a hung-up caller both run — and its kill used to be a
// group.Kill() written one line below a select on the wait, which is exactly
// the branch where the leader has already been collected.
//
// The wait's channel is deliberately left unread: a value already sitting in it
// is what puts reap on that branch, which is the one this is about.
func TestReap_DoesNotSignalAGroupIDTheWaitHasReleased(t *testing.T) {
	group, cmd, _ := sessionCommand(t, "exit", "0")
	wait := startLeaderWait(cmd, group, testLogger(&syncBuffer{}))
	waitFor(t, "the wait to have collected the session's leader", func() (bool, string) {
		if len(wait.waited) == 1 {
			return true, ""
		}
		return false, "the wait has not finished with the session's command yet"
	})

	aimedAt, bystander, _ := sessionCommand(t, "sleep")

	terminal, err := platform.OpenPTY()
	require.NoError(t, err)
	svc := &Service{log: testLogger(&syncBuffer{})}
	sess := &session{svc: svc, tty: newSessionTerminal(terminal, testLogger(&syncBuffer{}))}

	require.True(t, svc.reap(sess, aimedAt, wait),
		"the wait had already reported, so the teardown must say the session was reaped")
	requireDiedOfSIGTERM(t, bystander,
		"the teardown signalled the group itself rather than through the wait, which is the only thing that knows whether the id is still the session's")
}

// requireDiedOfSIGTERM kills a process the test expects to have been left
// alone, and reads back which signal arrived.
//
// It is the only thing that settles it. A process that has been sent SIGKILL is
// not distinguishable from a running one by asking whether its pid exists — the
// answer is yes either way until somebody reaps the zombie — so this kills it
// deliberately, with a different signal. A kill that went out first is already
// pending and wins.
func requireDiedOfSIGTERM(t *testing.T, cmd *pty.Cmd, whatItMeans string) {
	t.Helper()

	require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))
	_ = cmd.Wait()
	require.NotNil(t, cmd.ProcessState)
	sig, signalled := terminatingSignal(cmd.ProcessState)
	require.True(t, signalled)
	require.Equal(t, "SIGTERM", sig, whatItMeans)
}
