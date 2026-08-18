//go:build unix

package platform

import (
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// These are about what a signal reaches, which is the only question a process
// group id raises and the one an exported test cannot ask.
//
// A group that has released its id names a number the kernel has taken back,
// and what makes that dangerous is that the number belongs to somebody else by
// then. Reproducing that honestly means putting a process on the released id,
// which needs control of pid allocation — a pid namespace and
// /proc/sys/kernel/ns_last_pid; internal/agent/exec has that reproduction, and
// it is opt-in because it needs a namespace to run in.
//
// What is portable is the other half of the same statement: point a group at an
// id somebody else is holding and ask whether it signals it. A stranger's live
// process group standing in for the stranger the kernel would have handed the
// id to is the same call with the same target, arranged rather than waited for.
// The fields are set directly because that is what a released group is — the
// alternative is a fixture that can only assert an error value, and an error
// value is what a guard that returns early without one would still produce.
//
// The exported half is in collect_unix_test.go, which drives the same states
// through Collect against real children.

// strangerPID is past every pid either kernel can hand out, so a group holding
// it can never be grounded: Linux caps pid_max at 2^22 and Darwin at 99999.
const strangerPID = 1 << 30

// startSessionLeader starts a process leading a session and process group of
// its own, so its pid is also a group id — which is what makes it a stand-in
// for whoever the kernel gives a released id to next.
func startSessionLeader(t *testing.T) *exec.Cmd {
	t.Helper()

	cmd := exec.Command("/bin/sh", "-c", "sleep 300")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	// Its own group, or it is not standing in for anything: a process still in
	// the test binary's group would be reached by a signal aimed anywhere near
	// it, and the assertions below would mean nothing.
	waitFor(t, "the stand-in to lead its own process group", func() bool {
		pgid, err := syscall.Getpgid(cmd.Process.Pid)
		return err == nil && pgid == cmd.Process.Pid
	})
	return cmd
}

// requireDiedOfSIGTERM kills a process the test expects to have been left
// alone, and reads back which signal arrived.
//
// It is the only thing that settles it. A process that has been sent SIGKILL is
// not distinguishable from a running one by asking whether its pid exists — the
// answer is yes either way until somebody reaps the zombie — so this kills it
// deliberately, with a different signal. A kill that went out first is already
// pending and wins.
func requireDiedOfSIGTERM(t *testing.T, cmd *exec.Cmd, whatItMeans string) {
	t.Helper()

	require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))
	_ = cmd.Wait()
	require.NotNil(t, cmd.ProcessState)
	status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	require.True(t, ok)
	require.True(t, status.Signaled(), whatItMeans)
	require.Equal(t, syscall.SIGTERM, status.Signal(), whatItMeans)
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestSignal_ReleasedGroupDoesNotSignalTheIDItNamed is the whole of it: a group
// whose leader has been collected does not deliver a signal to the id it used
// to hold.
//
// Both halves are here because either alone is worthless. A guard that refused
// every signal would pass the second half and take the agent's ability to kill
// anything with it, so the first half aims the same call at the same kind of
// target from a group that still holds its id, and requires the target to die.
func TestSignal_ReleasedGroupDoesNotSignalTheIDItNamed(t *testing.T) {
	// Still holding it: the call reaches the group the id names.
	doomed := startSessionLeader(t)
	held := &ProcessGroup{
		pid: doomed.Process.Pid, pgid: doomed.Process.Pid,
		isolated: true, configured: true, pin: pinGroup,
	}
	require.NoError(t, held.Kill())
	_ = doomed.Wait()
	require.NotNil(t, doomed.ProcessState)
	status, ok := doomed.ProcessState.Sys().(syscall.WaitStatus)
	require.True(t, ok)
	require.True(t, status.Signaled())
	require.Equal(t, syscall.SIGKILL, status.Signal(),
		"the fixture cannot kill through a group id at all, so what follows would prove nothing")

	// Released: the same call, the same shape of target, and nothing sent.
	bystander := startSessionLeader(t)
	released := &ProcessGroup{
		pid: bystander.Process.Pid, pgid: bystander.Process.Pid,
		isolated: true, configured: true, pin: pinNone,
	}
	require.ErrorIs(t, released.Kill(), ErrGroupReleased)
	require.ErrorIs(t, released.Signal(SignalTerm), ErrGroupReleased)
	require.ErrorIs(t, released.Sweep(), ErrGroupReleased)
	require.ErrorIs(t, released.SignalLeader(SignalKill), ErrGroupReleased)
	requireDiedOfSIGTERM(t, bystander,
		"a group signalled the id its own collection gave back to the kernel; on a developer's machine that is their editor or their build")
}

// TestCollect_AnExitItCouldNotEstablishGivesUpTheIDWithoutSweepingIt is the
// branch where the ordering cannot be kept, and what it does instead.
//
// AwaitExit is what establishes that the leader has exited and is still
// uncollected, which is what makes the group id unmistakably this group's. When
// it fails there is nothing to sweep *with*: sending anyway is a SIGKILL to a
// whole process group on no information, and this is that call, with a
// stranger's live session on the id to say so.
//
// So the group gives the id up instead — before the collection rather than
// after it, because the collection is the one thing it cannot order anything
// against — and reports it, because a descendant may now outlive the call that
// started it and nothing else will say so.
func TestCollect_AnExitItCouldNotEstablishGivesUpTheIDWithoutSweepingIt(t *testing.T) {
	bystander := startSessionLeader(t)
	g := &ProcessGroup{
		pid: strangerPID, pgid: bystander.Process.Pid,
		isolated: true, configured: true, pin: pinGroup,
	}

	groupErr, waitErr := g.SweepAndCollect(func() error { return nil })
	require.Error(t, groupErr)
	require.ErrorContains(t, groupErr, "without being swept",
		"the report has to say the sweep was never sent; 'the sweep failed' is a different thing to whoever reads it")
	require.NoError(t, waitErr, "the collection is not what failed")

	requireDiedOfSIGTERM(t, bystander,
		"the group was swept on an exit nothing had established: that is a SIGKILL to whatever holds the id, which is what the check exists to prevent")
}

// TestCollect_AnUngroundedGroupCanStillReachItsLeader is the other side of it,
// and the reason the degrade is to the leader rather than to nothing.
//
// A session that cannot be swept still has to be killable: the exec watcher's
// timeout and the shell's idle teardown both have to end a command that is
// still running, and a guard that refused them would trade a misdirected signal
// for a process nobody can stop. So the leader stays reachable — through the
// os.Process the group was adopted with, which names the process rather than
// its number — until the collection completes.
func TestCollect_AnUngroundedGroupCanStillReachItsLeader(t *testing.T) {
	leader := startSessionLeader(t)
	bystander := startSessionLeader(t)

	// The group's id names the stranger and its leader is a process this test
	// owns: signalling the group would kill the stranger, signalling the leader
	// kills the leader, and which of them dies is the answer.
	g := &ProcessGroup{
		pid: strangerPID, pgid: bystander.Process.Pid,
		proc: leader.Process, isolated: true, configured: true, pin: pinGroup,
	}

	// The collection is held open while the kill below goes out, which is the
	// state this is about: the exit could not be established, so the group has
	// given up its id and has not finished collecting.
	release, collected := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(collected)
		_, _ = g.Collect(func() error { <-release; return nil })
	}()
	t.Cleanup(func() {
		close(release)
		<-collected
	})

	waitFor(t, "the group to give up its id", func() bool {
		g.mu.Lock()
		defer g.mu.Unlock()
		return g.pin == pinLeader
	})

	require.NoError(t, g.Kill(), "the leader is running, so the kill has somewhere to go")
	_ = leader.Wait()
	require.NotNil(t, leader.ProcessState)
	status, ok := leader.ProcessState.Sys().(syscall.WaitStatus)
	require.True(t, ok)
	require.True(t, status.Signaled())
	require.Equal(t, syscall.SIGKILL, status.Signal(),
		"a group that cannot be swept is not a group that cannot be stopped; its leader is still named by a handle")

	requireDiedOfSIGTERM(t, bystander,
		"the kill went to the group id rather than to the leader, which is the id this group had already given up")
}
