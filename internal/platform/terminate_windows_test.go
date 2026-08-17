package platform

import (
	"fmt"
	"os/exec"
	"testing"

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

	leader := reapedLeader(t)

	// Assigned: the job going down is the guarantee, and the leader having
	// already exited is the ordinary case, not a failure.
	require.NoError(t, terminate(job, leader, true),
		"a successful job termination is the answer when the process was in the job")

	// Not assigned: the job held nothing, so the leader is the only thing that
	// was acted on and its answer is the caller's.
	require.ErrorIs(t, terminate(job, leader, false), ErrProcessNotFound,
		"an empty job proves nothing about a process that was never assigned to it")
}

// TestTerminate_NoJobReportsTheLeader covers the degraded path, where there is
// no job handle at all and the leader has always been the only answer.
func TestTerminate_NoJobReportsTheLeader(t *testing.T) {
	t.Parallel()

	require.ErrorIs(t, terminate(0, reapedLeader(t), false), ErrProcessNotFound)
	require.ErrorIs(t, terminate(0, reapedLeader(t), true), ErrProcessNotFound,
		"with no job there is nothing for the assigned flag to excuse")
}

// TestTerminate_UnpinnedLeaderIsNeverResolvedByPid is the rule that keeps this
// package from being the thing that kills someone else's process.
//
// A group with no leader handle has a number and no evidence that the number
// still means what it meant. The old code resolved it anyway, with an
// OpenProcess at kill time, and would terminate whatever answered. This
// requires the reason to come back instead — and requires the process that
// happens to hold that pid to still be running afterwards, which is the part
// that would have failed.
func TestTerminate_UnpinnedLeaderIsNeverResolvedByPid(t *testing.T) {
	t.Parallel()

	// A live process this group never adopted, standing in for whoever holds a
	// recycled pid.
	cmd := exec.Command("cmd", "/c", "ping -n 60 127.0.0.1 > NUL")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	pid := uint32(cmd.Process.Pid) //nolint:gosec // a Windows pid is positive

	unpinned := leaderRef{pid: pid, err: fmt.Errorf("platform: pid %d: %w", pid, ErrProcessNotFound)}
	require.ErrorIs(t, terminate(0, unpinned, false), ErrProcessNotFound,
		"a group that never pinned its leader must report why, not act on the number")
	require.True(t, ProcessExists(int(pid)),
		"pid %d belongs to a process this group never adopted and must be untouched", pid)
}

// reapedLeader returns the leader a group is left holding after its child has
// exited and been waited on: a live handle to a dead process.
//
// That is the state these tests are about, and the state that used to be
// unrepresentable. A group that kept only the pid had, at this moment, a number
// on the kernel's free list — which is why the helper this replaces had to
// spend five seconds waiting for the pid to disappear before it could hand it
// to a call that terminates things.
func reapedLeader(t *testing.T) leaderRef {
	t.Helper()

	cmd := exec.Command("cmd", "/c", "exit 0")
	require.NoError(t, cmd.Start())
	pid := uint32(cmd.Process.Pid) //nolint:gosec // a Windows pid is positive

	// Opened before Wait, exactly as Adopt does, so the pid cannot have become
	// someone else's by the time the handle is taken.
	h, err := openLeader(pid, leaderAccess)
	require.NoError(t, err)
	t.Cleanup(func() { _ = windows.CloseHandle(h) })

	_ = cmd.Wait()
	return leaderRef{handle: h, pid: pid}
}
