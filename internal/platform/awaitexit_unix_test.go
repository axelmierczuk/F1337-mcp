//go:build unix

package platform

import (
	"errors"
	"io"
	"os/exec"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// noSuchPID is past every pid this can run on — Linux caps pid_max at 2^22 and
// Darwin at 99999 — so awaitExit cannot establish anything about it, whichever
// call it makes.
const noSuchPID = 1 << 30

// AwaitExit reports the exit and leaves the status for os/exec to collect.
//
// That second half is the whole safety argument of the sweep: an unreaped
// leader is still a member of its own process group, so the kernel cannot hand
// that group id to anything else, and the SIGKILL a sweep sends can only reach
// the tree the command led. A wait that collected the status instead would
// release the id at exactly the moment the sweep is about to name it — and it
// would take the command's exit status away from the caller as well, which is
// what the assertions below fail on.
//
// syscall.Wait4 with WNOWAIT is that mutation, and it is not a hypothetical:
// Darwin accepts the flag and reaps anyway, which is why that platform watches
// for the exit through kqueue instead.
func TestAwaitExit_ReportsTheExitWithoutCollectingIt(t *testing.T) {
	_, cmd := isolatedLeader(t, "exit 9")

	require.NoError(t, AwaitExit(cmd.Process.Pid))

	// Still there to be collected, and still carrying what the command did.
	require.Error(t, cmd.Wait(), "the command exited 9, so Wait must report it")
	require.NotNil(t, cmd.ProcessState,
		"AwaitExit collected the child itself: os/exec has no status left to report, and the group id was released before the sweep names it")
	require.Equal(t, 9, cmd.ProcessState.ExitCode())
}

// The group id is still the leader's own after AwaitExit, and is not after the
// collection.
//
// This is the property everything else rests on, stated as the kernel's own
// answer rather than as an argument about it. A group whose only member is the
// leader's uncollected zombie is a group the kernel still knows: signal 0 to
// it is delivered on Linux and refused with EPERM on Darwin — "there is a
// group, and nothing in it that can take a signal" — and neither of those is
// ESRCH. Collect the leader and both platforms answer ESRCH, because the id
// has gone back to the kernel and names nothing at all; the next process group
// to be given it belongs to somebody else.
//
// So a sweep sent in the first state reaches the tree the command led, and one
// sent in the second reaches whatever holds that id now. Signal 0 rather than
// SIGKILL deliberately: the point is which process group the kernel finds, and
// this test has no business killing whatever it finds.
func TestAwaitExit_LeavesTheGroupIDTheLeadersOwn(t *testing.T) {
	group, cmd := isolatedLeader(t, "exit 0")
	pgid := group.GroupID()
	require.Equal(t, cmd.Process.Pid, pgid, "the leader does not lead its own group")

	require.NoError(t, AwaitExit(cmd.Process.Pid))
	require.False(t, errors.Is(syscall.Kill(-pgid, 0), syscall.ESRCH),
		"the kernel has already released group %d while its leader is an uncollected zombie; "+
			"the ordering the sweep rests on does not hold on this platform", pgid)

	require.NoError(t, cmd.Wait())
	require.ErrorIs(t, syscall.Kill(-pgid, 0), syscall.ESRCH,
		"group %d still answers after its last member was collected, so this test is not looking at the released id it means to", pgid)
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
// stdout reaching EOF is what establishes the exit before AwaitExit is called:
// os/exec closes the parent's copy of the write end after Start, so the only
// holder left is the command itself.
func TestAwaitExit_ACommandThatHasAlreadyExitedIsStillAnExit(t *testing.T) {
	group, err := NewProcessGroup(GroupConfig{KillOnClose: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = group.Close() })

	cmd := exec.Command("/bin/sh", "-c", "printf done")
	group.ConfigureCommand(cmd)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	written, err := io.ReadAll(stdout)
	require.NoError(t, err)
	require.Equal(t, "done", string(written),
		"the command did not run to completion, so what follows is not about a process that had already exited")

	require.NoError(t, AwaitExit(cmd.Process.Pid),
		"the command had exited, and a wait for its exit reported a failure instead")
	require.NoError(t, cmd.Wait())
	require.Equal(t, 0, cmd.ProcessState.ExitCode())
}

// A pid AwaitExit cannot watch is an error, not an exit.
//
// The distinction is the fail-safe's entire input. On Darwin a failed kqueue
// registration is not reported through the syscall's own error at all: kevent
// puts it in the event list with EV_ERROR set and returns a count, so an
// implementation that only checks for a non-nil error reads "cannot watch this
// pid" as "it has exited" — and its caller sweeps a group it has established
// nothing about, which is #91 with an extra step.
func TestAwaitExit_APidItCannotWatchIsAnError(t *testing.T) {
	require.Error(t, AwaitExit(noSuchPID))
}

// Sweep does not report a group with nothing left in it as a failure.
//
// It is the ordinary ending — most commands leave nothing behind, and a shell
// session that ends at a prompt with no jobs is exactly that — and the two
// platforms word it differently. Darwin refuses the signal with EPERM because
// the leader's zombie cannot receive one; Linux delivers it and says nothing.
// Passed back as it came, EPERM cost every successful exec on macOS a WARN
// saying a descendant may have outlived the call. See the Darwin test beside
// this one, which is where the translation is actually observable.
func TestSweep_AGroupWithNothingLeftInItIsNotAFailure(t *testing.T) {
	group, cmd := isolatedLeader(t, "exit 0")

	require.NoError(t, AwaitExit(cmd.Process.Pid))
	err := group.Sweep()
	require.True(t, err == nil || errors.Is(err, ErrProcessNotFound),
		"a group holding nothing but its leader's zombie reported %v; its caller logs that as a descendant left running on the host", err)
	require.NoError(t, cmd.Wait())
}

// Sweep still reports a group it genuinely could not signal.
//
// The translation above is narrow on purpose: it is about a group that has
// nothing left to receive a signal, not about a group this process may not
// reach. A closed group is the case that is testable without another uid — the
// caller is asking about something it has already given up — and it must not
// come back as "there was nothing to stop".
func TestSweep_AGroupItCannotSignalIsStillAFailure(t *testing.T) {
	group, cmd := isolatedLeader(t, "exit 0")
	require.NoError(t, AwaitExit(cmd.Process.Pid))
	require.NoError(t, cmd.Wait())

	require.NoError(t, group.Close())
	err := group.Sweep()
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrProcessNotFound,
		"a group that could not be signalled at all was reported as one that had nothing left in it")
}

// isolatedLeader starts /bin/sh leading a session of its own, the way both
// agent spawn paths start a command.
//
// The shell rather than a compiled helper because these tests are about what
// the kernel says, and /bin/sh is on both platforms this file builds for.
func isolatedLeader(t *testing.T, script string) (*ProcessGroup, *exec.Cmd) {
	t.Helper()

	group, err := NewProcessGroup(GroupConfig{KillOnClose: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = group.Close() })

	cmd := exec.Command("/bin/sh", "-c", script)
	group.ConfigureCommand(cmd)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = group.Kill()
		_ = cmd.Wait()
	})
	require.NoError(t, group.Adopt(cmd.Process))
	require.True(t, group.Isolated(),
		"the child does not lead its own group, so there is no group id here to be right or wrong about")

	return group, cmd
}
