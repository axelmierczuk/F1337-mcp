package platform

import (
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// TestTerminate_UnassignedLeaderIsNotReportedAsKilled pins which of the two
// answers terminate gives back.
//
// TerminateJobObject succeeds against a job that holds nothing, so when the
// child was never assigned — Adopt failed, which is what happens when the
// agent is itself inside a job that forbids nesting — the job's success says
// nothing about the process the caller asked about. Dropping the leader's
// error there reports a live, unreachable process as killed, and the
// supervisor stops trying to stop it.
//
// It is an internal test because the state it needs, a group holding a job
// handle whose child was never assigned to it, cannot be produced through the
// exported API on demand: it requires AssignProcessToJobObject to fail, which
// no CI runner can be made to do reliably.
func TestTerminate_UnassignedLeaderIsNotReportedAsKilled(t *testing.T) {
	t.Parallel()

	job, err := windows.CreateJobObject(nil, nil)
	require.NoError(t, err)
	defer func() { _ = windows.CloseHandle(job) }()

	pid := reapedPID(t)

	// Assigned: the job going down is the guarantee, and the leader having
	// already exited is the ordinary case, not a failure.
	require.NoError(t, terminate(job, pid, true),
		"a successful job termination is the answer when the process was in the job")

	// Not assigned: the job held nothing, so the leader is the only thing that
	// was acted on and its answer is the caller's.
	require.ErrorIs(t, terminate(job, pid, false), ErrProcessNotFound,
		"an empty job proves nothing about a process that was never assigned to it")
}

// TestTerminate_NoJobReportsTheLeader covers the degraded path, where there is
// no job handle at all and the leader has always been the only answer.
func TestTerminate_NoJobReportsTheLeader(t *testing.T) {
	t.Parallel()

	require.ErrorIs(t, terminate(0, reapedPID(t), false), ErrProcessNotFound)
	require.ErrorIs(t, terminate(0, reapedPID(t), true), ErrProcessNotFound,
		"with no job there is nothing for the assigned flag to excuse")
}

// reapedPID returns a pid whose process has exited and been waited on, so
// Windows has released the process object and OpenProcess on it fails with
// ERROR_INVALID_PARAMETER rather than succeeding against a dead handle.
func reapedPID(t *testing.T) uint32 {
	t.Helper()

	cmd := exec.Command("cmd", "/c", "exit 0")
	require.NoError(t, cmd.Start())
	pid := cmd.Process.Pid
	_ = cmd.Wait()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !ProcessExists(pid) {
			return uint32(pid) //nolint:gosec // a Windows pid is positive
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Skipf("pid %d is still reported as existing after it was reaped", pid)
	return 0
}
