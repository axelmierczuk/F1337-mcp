//go:build unix

package platform

import (
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// These cover adoptedGroup, which is the read Adopt makes of the child's real
// process group. The kernel's answer is stubbed here because the window the
// loop exists to close — between the parent's fork returning and the child's
// setsid running — cannot be opened on demand from a test: it is opened by the
// host being busy, which is how #82 was found rather than how it can be
// reproduced. The stub reproduces it exactly, once, every time.
//
// The exported half is in group_unix_test.go, where the same behaviour is
// driven through Adopt against real children. Both are needed: this one says
// the loop is right, that one says the loop is what Adopt runs.

// TestAdoptedGroup_WaitsForTheSessionTheChildHasNotMadeYet is #82's second
// defect. A parent that samples the pgid once can catch the child still in the
// group it was forked into, and Adopt would then record isolated = false for
// the life of a process that does lead its own group.
func TestAdoptedGroup_WaitsForTheSessionTheChildHasNotMadeYet(t *testing.T) {
	t.Parallel()

	const child, forkedInto = 4242, 900
	reads := 0
	pgid, isolated, err := adoptedGroup(child, true, time.Minute, func(pid int) (int, error) {
		require.Equal(t, child, pid)
		reads++
		if reads < 5 {
			return forkedInto, nil
		}
		return child, nil
	})

	require.NoError(t, err)
	require.True(t, isolated, "the kernel did report the child leading its own group, on the fifth read")
	require.Equal(t, child, pgid)
	require.Equal(t, 5, reads, "a single sample is the defect; the answer has to be read until it settles")
}

// TestAdoptedGroup_DoesNotWaitForAGroupNobodyAskedFor is the other side of it.
// A caller that skips ConfigureCommand gets a child in its own group, which is
// a supported thing to do and a settled answer on the first read — waiting for
// it to change would stall every such spawn for the full failsafe.
func TestAdoptedGroup_DoesNotWaitForAGroupNobodyAskedFor(t *testing.T) {
	t.Parallel()

	const child, callersGroup = 4242, 900
	reads := 0
	pgid, isolated, err := adoptedGroup(child, false, 50*time.Millisecond, func(int) (int, error) {
		reads++
		return callersGroup, nil
	})

	require.NoError(t, err, "an unconfigured child is not an adoption failure")
	require.False(t, isolated)
	require.Equal(t, callersGroup, pgid)
	require.Equal(t, 1, reads, "nothing was asked for, so there is nothing to wait for")
}

// TestAdoptedGroup_StopsWhenTheChildIsGone keeps a fast-exiting child from
// being charged the failsafe, and keeps it from being recorded as a child that
// never got its group.
//
// This is the other half of #82's second defect, and the half the issue does
// not name. Darwin's getpgid(2) answers ESRCH for a process that has exited and
// not been reaped, so a leader that beats Adopt to the finish — which
// `sh -c "echo ..."` regularly does — was recorded as unisolated on macOS and
// as isolated on Linux, for the same command. It is not a question the kernel
// has to answer: setsid(2) in a freshly forked child cannot fail, and a failure
// would have failed Start, so a configured command that started led its own
// session whatever getpgid(2) will say about it afterwards.
func TestAdoptedGroup_StopsWhenTheChildIsGone(t *testing.T) {
	t.Parallel()

	const child = 4242
	reads := 0
	pgid, isolated, err := adoptedGroup(child, true, 50*time.Millisecond, func(int) (int, error) {
		reads++
		return 0, syscall.ESRCH
	})

	require.NoError(t, err, "a race with a fast-exiting child is not an adoption failure")
	require.True(t, isolated,
		"Configure asked for the session and Start succeeded, so the child had one; "+
			"recording false here is what costs a fast-exiting leader its post-exec sweep")
	require.Equal(t, child, pgid, "its own pid is the group Configure asked for")
	require.Equal(t, 1, reads)
}

// TestAdoptedGroup_AGoneChildNobodyConfiguredIsNotIsolated is the control for
// it: without Configure there was no session to lose, and the pid is the only
// thing left that could be signalled.
func TestAdoptedGroup_AGoneChildNobodyConfiguredIsNotIsolated(t *testing.T) {
	t.Parallel()

	const child = 4242
	pgid, isolated, err := adoptedGroup(child, false, 50*time.Millisecond, func(int) (int, error) {
		return 0, syscall.ESRCH
	})

	require.NoError(t, err)
	require.False(t, isolated, "nothing asked for a group, so claiming one would aim a kill at a group that is not ours")
	require.Equal(t, child, pgid)
}

// TestAdoptedGroup_ReportsAGroupThatNeverTook is what #82 asked for whatever
// else was decided: when the group did not materialise, say so. Silence here is
// what makes the degraded case undetectable from outside — ExecService's
// "command is running outside its process group" warning is gated on this
// error, and the supervisor writes the same thing into the process's own log.
//
// The stub never lets the child reach its own group, so the deadline is reached
// on purpose rather than by chance. It is short here because the wait is not
// what is under test; adoptSettle is what Adopt actually uses.
func TestAdoptedGroup_ReportsAGroupThatNeverTook(t *testing.T) {
	t.Parallel()

	const child, forkedInto = 4242, 900
	pgid, isolated, err := adoptedGroup(child, true, 50*time.Millisecond, func(int) (int, error) {
		return forkedInto, nil
	})

	require.Error(t, err)
	require.ErrorContains(t, err, "4242")
	require.ErrorContains(t, err, "900")
	require.False(t, isolated)
	require.Equal(t, forkedInto, pgid,
		"the group it is really in is still what a caller has to act on, error or not")
}
