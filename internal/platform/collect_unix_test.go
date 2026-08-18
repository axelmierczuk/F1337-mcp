//go:build unix

package platform_test

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// TestCollect_ReleasesTheIDBeforeItCollectsTheLeader is the ordering, asserted
// from inside the collection.
//
// A group id is a pid, and collecting the leader of an emptied group is what
// hands that number back to the kernel. So the group has to stop signalling it
// before the collection rather than after: "after" leaves a window between
// wait4 returning and any flag being set, and a window is what #91, #96 and
// #105 all were. The wait here is held open on purpose, which turns the
// question "did the mark come first" into something a test can ask rather than
// something a reader has to trust.
//
// It is os/exec's own ordering — pidWait marks the process done before wait4
// whenever waitid could tell it the wait will not block — and this is the same
// claim about this package.
func TestCollect_ReleasesTheIDBeforeItCollectsTheLeader(t *testing.T) {
	t.Parallel()

	group, err := platform.NewProcessGroup(platform.GroupConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = group.Close() })

	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	group.ConfigureCommand(cmd)
	require.NoError(t, cmd.Start())
	require.NoError(t, group.Adopt(cmd.Process))
	require.True(t, group.Isolated())

	inside, release := make(chan struct{}), make(chan struct{})
	waited := make(chan error, 1)
	go func() {
		_, waitErr := group.Collect(func() error {
			close(inside)
			<-release
			return cmd.Wait()
		})
		waited <- waitErr
	}()

	<-inside
	require.ErrorIs(t, group.Kill(), platform.ErrGroupReleased,
		"the group was still signalling its id with the collection already under way; "+
			"a signal that passes here is one the kernel may deliver after the id has been handed on")

	close(release)
	require.NoError(t, <-waited, "the collection is still the caller's and its answer is unchanged")
}

// TestSweepAndCollect_KillsWhatTheLeaderLeftAndStillReportsItsStatus is the
// call the agents make, end to end: a command that exits leaving a descendant
// in its group.
//
// Both halves matter and neither implies the other. A sweep that never fires
// leaves the descendant running on the host; one that fires before the leader
// has exited kills the command itself, and the exit status is where that shows
// up — which is why the status is asserted before anything is asserted about
// the descendant.
func TestSweepAndCollect_KillsWhatTheLeaderLeftAndStillReportsItsStatus(t *testing.T) {
	t.Parallel()

	group, err := platform.NewProcessGroup(platform.GroupConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = group.Close() })

	pidFile := filepath.Join(t.TempDir(), "pids")
	readEnd, writeEnd, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = readEnd.Close() })

	// The descendant outlives the leader and inherits fd 3, so the pipe reaches
	// EOF only once it is gone. A pid check could not tell a killed descendant
	// from an unreaped zombie of one.
	cmd := exec.Command("/bin/sh", "-c", `sleep 300 & echo "$$ $!" > `+pidFile+`; exit 0`)
	cmd.ExtraFiles = []*os.File{writeEnd}
	group.ConfigureCommand(cmd)
	require.NoError(t, cmd.Start())
	require.NoError(t, group.Adopt(cmd.Process))
	require.NoError(t, writeEnd.Close())

	groupErr, waitErr := group.SweepAndCollect(cmd.Wait)
	require.NoError(t, groupErr, "the sweep reported a broken guarantee")
	require.NoError(t, waitErr)
	require.NotNil(t, cmd.ProcessState)
	require.Equal(t, 0, cmd.ProcessState.ExitCode())
	status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	require.True(t, ok)
	require.False(t, status.Signaled(),
		"the command was killed rather than left to exit, so the sweep went out before the leader had exited")

	require.NoError(t, readEnd.SetReadDeadline(time.Now().Add(10*time.Second)))
	_, err = readEnd.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF,
		"something the command left behind is still holding the inherited pipe: the group was not swept")
}

// TestSignalLeader_ReachesTheLeaderAndNothingElseInTheGroup is the call the
// supervisor makes for a caller that explicitly asked not to signal the tree.
//
// The descendant surviving is the assertion. Without it, a SignalLeader that
// quietly signalled the whole group would pass every other check here — and
// signalling a group a caller asked not to signal is how a stop that was meant
// to leave a database running takes it down.
func TestSignalLeader_ReachesTheLeaderAndNothingElseInTheGroup(t *testing.T) {
	t.Parallel()

	group, err := platform.NewProcessGroup(platform.GroupConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = group.Close() })

	readEnd, writeEnd, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = readEnd.Close() })

	// The descendant is waited for rather than assumed: signalling before the
	// shell has forked it kills a leader with nothing behind it, and the pipe
	// then reaches EOF for the one reason this test must not accept.
	started := filepath.Join(t.TempDir(), "started")
	cmd := exec.Command("/bin/sh", "-c", `sleep 300 & echo "$!" > `+started+`; wait`)
	cmd.ExtraFiles = []*os.File{writeEnd}
	group.ConfigureCommand(cmd)
	require.NoError(t, cmd.Start())
	require.NoError(t, group.Adopt(cmd.Process))
	require.NoError(t, writeEnd.Close())
	requireFileWritten(t, started)

	require.NoError(t, group.SignalLeader(platform.SignalKill))
	_ = cmd.Wait()
	require.NotNil(t, cmd.ProcessState)
	status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	require.True(t, ok)
	require.True(t, status.Signaled())
	require.Equal(t, syscall.SIGKILL, status.Signal())

	require.NoError(t, readEnd.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err = readEnd.Read(make([]byte, 1))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded,
		"the descendant went with the leader: a caller that asked to signal one process signalled the group")

	// And the group is what reaches it, so nothing is left running on the host
	// by a test that was only ever about the leader.
	require.NoError(t, group.Kill())
}

// requireFileWritten waits for a child to announce itself, so a test signals a
// tree that exists rather than one it assumed had been built by now.
func requireFileWritten(t *testing.T, path string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil && len(data) > 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the child never wrote %s", path)
}
