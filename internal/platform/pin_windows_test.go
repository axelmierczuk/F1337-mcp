package platform

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// These cover pinLeader, which is what the re-adoption path uses instead of
// openLeader. Adopt does not need it: os/exec is holding a handle there, so the
// pid it hands over cannot have been reissued. OpenProcessGroup has no such
// help — nothing holds the pid between StatProcess reading it and OpenProcess
// resolving it — so the handle it gets back has to be checked before the group
// is allowed to terminate anything through it.

// TestPinLeader_RefusesAPidThatNoLongerNamesTheSameProcess is the rule that
// keeps the re-adoption path from inheriting the bug the kill path just lost.
//
// A pid that Windows took back off the free list inside that window resolves to
// an uninvolved process. Opening it is not yet harmful; keeping it is, because
// from that moment the group holds a PROCESS_TERMINATE handle to a stranger and
// every later Kill goes to it — with no pid resolution left anywhere for an
// audit to notice. So the pin is checked against the identity StatProcess saw,
// and a mismatch gives the handle back.
func TestPinLeader_RefusesAPidThatNoLongerNamesTheSameProcess(t *testing.T) {
	t.Parallel()

	// A live process standing in for whoever received a recycled pid. Nothing
	// in this test adopted it, and it must be running when the test ends.
	cmd := exec.Command("cmd", "/c", "ping -n 60 127.0.0.1 > NUL")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	pid := uint32(cmd.Process.Pid) //nolint:gosec // a Windows pid is positive

	// A start identity no live process can have: the FILETIME epoch, 1601.
	// This is the value the caller would be holding if the pid had been
	// reissued between the stat and the open.
	h, err := pinLeader(pid, "windows:0")
	require.ErrorIs(t, err, ErrProcessNotFound,
		"a pid whose start identity has changed is the process the caller asked about being gone")
	require.Zero(t, h, "a refused pin must not leave a handle behind")
	require.True(t, ProcessExists(int(pid)),
		"pid %d belongs to a process this group never adopted and must be untouched", pid)
}

// TestPinLeader_AcceptsTheProcessItStatted is the other half: the check must
// not refuse the ordinary case, or re-adoption after an agent restart stops
// working and every supervised process on the host becomes unsignallable.
func TestPinLeader_AcceptsTheProcessItStatted(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("cmd", "/c", "ping -n 60 127.0.0.1 > NUL")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	pid := cmd.Process.Pid

	info, err := StatProcess(pid)
	require.NoError(t, err)

	h, err := pinLeader(uint32(pid), info.StartID) //nolint:gosec // a Windows pid is positive
	require.NoError(t, err)
	require.NotZero(t, h)
	t.Cleanup(func() { _ = windows.CloseHandle(h) })

	// The handle is the one the group would go on to work from, so it has to
	// answer for the process that was statted and not merely be non-zero.
	creation, err := creationTime(h)
	require.NoError(t, err)
	require.Equal(t, info.StartID, startIDFrom(creation))
}

// TestPinLeader_ReportsAPidThatNamesNothing keeps the two failure modes apart.
// A pid with nothing behind it is ErrProcessNotFound, which callers read as
// "already exited"; anything else must not be folded into that, because
// reporting a running-but-unreachable process as gone is what makes a
// supervisor stop trying to stop it. See processGone.
func TestPinLeader_ReportsAPidThatNamesNothing(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("cmd", "/c", "exit 0")
	require.NoError(t, cmd.Start())
	pid := uint32(cmd.Process.Pid) //nolint:gosec // a Windows pid is positive
	_ = cmd.Wait()

	// Not asserting on the exact moment the pid is released — that is the
	// kernel's business — only that whatever comes back is never a handle.
	h, err := pinLeader(pid, "windows:0")
	require.Error(t, err)
	require.Zero(t, h)
}
