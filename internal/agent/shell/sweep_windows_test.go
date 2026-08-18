package shell

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// The teardown's kill still goes out after the wait has collected the leader,
// and that is deliberate rather than an oversight the Unix guard has not
// reached yet.
//
// Nothing here is named by a number the kernel reclaims: the group signals the
// job through the handle it created and the leader through a handle it pinned
// at Adopt, so neither call can be redirected by a pid the wait released.
// Skipping it would cost the guarantee instead — closing a pseudo-console ends
// the processes attached to it, and a grandchild that never attached to one has
// nothing else to end it before the job is closed. That took three rounds of
// PR #63 to establish, so it is asserted here rather than left to be
// rediscovered by whoever ports the Unix guard across.
//
// A closed group is how the decision is read back: it is the one state in which
// ProcessGroup.Signal reports something at all, so a log with the warning in it
// means the call went out. The state that matters is the collection above it,
// and the real wait is what put the group in it.
func TestKillGroup_StillSignalsAfterTheWaitHasCollectedTheLeader(t *testing.T) {
	group, cmd, _ := sessionCommand(t, "exit", "0")
	logs := &syncBuffer{}

	wait := startLeaderWait(cmd, group, testLogger(logs))
	require.NoError(t, <-wait.waited)

	require.NoError(t, group.Close())
	after := &syncBuffer{}
	wait.killGroup(group, testLogger(after))
	require.Contains(t, after.String(), "could not kill the session's process group",
		"the teardown declined to terminate the job because the leader had been collected; on Windows that is the only thing that reaches a grandchild which never attached to the console")
}

// A session that left nothing behind is torn down in silence.
//
// The Unix file asserts the same thing about its sweep, which is the call that
// had to learn to read an emptied group's answer. There is no sweep here — the
// job object is what takes the tree down, at Close — so this is the assertion
// that the absence stays an absence rather than growing a diagnostic nobody
// can act on.
func TestSweepAndCollect_ASessionThatLeftNothingBehindLogsNothing(t *testing.T) {
	group, cmd, _ := sessionCommand(t, "exit", "0")
	logs := &syncBuffer{}

	require.NoError(t, <-startLeaderWait(cmd, group, testLogger(logs)).waited)
	require.Equal(t, 0, cmd.ProcessState.ExitCode())
	require.Empty(t, logs.String())
}

// The wait sweeps nothing here, and the job object is what a job the session
// left behind goes down with.
//
// It is the Unix file's first test with the mechanism swapped, and it is worth
// stating rather than leaving implied: sweeping as well would add no guarantee
// to a job created with KillOnClose that the agent holds the only handle to,
// and the guarantee it would be adding to is this one. A reader who ports the
// Unix sweep across should find out from here that the tree was already
// covered.
//
// The wait is what proves the sweep is absent — after it, the session's command
// has been collected and nothing has signalled anything, and the job is still
// running. Closing the group is the whole teardown on this platform.
func TestSweepAndCollect_TheJobObjectIsWhatTakesTheTreeWithIt(t *testing.T) {
	group, cmd, printed := sessionCommand(t, "orphan")
	logs := &syncBuffer{}

	require.NoError(t, <-startLeaderWait(cmd, group, testLogger(logs)).waited,
		"the session's command exited 0 of its own accord")
	require.Empty(t, logs.String())

	var orphan int
	waitFor(t, "the session's command to name the job it is leaving behind", func() (bool, string) {
		pids := parsePIDs(t, printed.String())
		if len(pids) == 1 {
			orphan = pids[0]
			return true, ""
		}
		return false, "the terminal printed: " + printed.String()
	})
	require.True(t, processRunning(orphan),
		"the job was already gone before the group was closed, so what follows is not about the job object")

	require.NoError(t, group.Close())
	waitFor(t, "pid "+strconv.Itoa(orphan)+" to be gone", func() (bool, string) {
		if !processRunning(orphan) {
			return true, ""
		}
		return false, "pid " + strconv.Itoa(orphan) + " outlived the session that started it: closing a KillOnClose job did not take the tree down"
	})
}
