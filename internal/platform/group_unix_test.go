//go:build unix

package platform_test

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aymanbagabas/go-pty"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// processTree is a supervised shell that has spawned a grandchild of its own.
type processTree struct {
	group      *platform.ProcessGroup
	leader     int
	grandchild int
	// reaped closes once the leader has exited and been waited on.
	reaped <-chan struct{}
	// alive is the read end of a pipe whose write end every process in the
	// tree inherited. It reaches EOF only when the last of them is gone.
	//
	// This is the assertion that actually holds everywhere. Checking pids does
	// not: a killed process that nobody waits on stays a zombie and keeps
	// answering kill(pid, 0) forever, and an orphan is reparented to pid 1,
	// which is only guaranteed to reap when it is a real init. Under `go test`
	// in a container pid 1 is the go tool, so the grandchild of this tree sits
	// at state Z indefinitely — dead, but indistinguishable from running if
	// you ask by pid. A held file descriptor cannot be faked by a zombie.
	alive *os.File
}

// startTree spawns a shell that spawns a grandchild.
//
// The shell writes its own pid and the grandchild's to a file and then waits
// forever. Reading the pids from the child rather than guessing them is what
// makes the "no survivors" assertion mean something: a test that only checks
// the leader proves exactly the thing this code exists to disprove.
func startTree(t *testing.T) processTree {
	t.Helper()

	dir := t.TempDir()
	pidFile := filepath.Join(dir, "pids")
	script := `
sleep 300 &
grandchild=$!
echo "$$ $grandchild" > ` + pidFile + `
wait
`

	group, err := platform.NewProcessGroup(platform.GroupConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = group.Close() })

	readEnd, writeEnd, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = readEnd.Close() })

	cmd := exec.Command("/bin/sh", "-c", script)
	// The shell gets this as fd 3 and `sleep` inherits it across the exec, so
	// both ends of the tree hold it.
	cmd.ExtraFiles = []*os.File{writeEnd}
	group.ConfigureCommand(cmd)
	require.NoError(t, cmd.Start())
	// Drop the parent's copy, or the pipe never reaches EOF.
	require.NoError(t, writeEnd.Close())

	reaped := make(chan struct{})
	go func() {
		_, _ = cmd.Process.Wait()
		close(reaped)
	}()
	t.Cleanup(func() {
		_ = group.Kill()
		<-reaped
	})

	require.NoError(t, group.Adopt(cmd.Process))
	require.True(t, group.Isolated(), "the child must lead its own process group")
	require.Equal(t, cmd.Process.Pid, group.GroupID(), "setsid makes the child its own group leader")

	leader, grandchild := readPIDs(t, pidFile)
	require.NotEqual(t, leader, grandchild)
	require.Equal(t, cmd.Process.Pid, leader)
	requireAlive(t, grandchild)

	return processTree{
		group:      group,
		leader:     leader,
		grandchild: grandchild,
		reaped:     reaped,
		alive:      readEnd,
	}
}

// requireReaped waits for the leader to exit and be waited on, so its pid is
// released rather than held by a zombie.
func requireReaped(t *testing.T, tree processTree, within time.Duration) {
	t.Helper()
	select {
	case <-tree.reaped:
	case <-time.After(within):
		t.Fatalf("leader pid %d did not exit within %s", tree.leader, within)
	}
}

// waitForTreeExit blocks until every process in the tree has released the
// inherited pipe, and reports io.EOF when they have or
// os.ErrDeadlineExceeded when something is still holding it.
func waitForTreeExit(t *testing.T, tree processTree, within time.Duration) error {
	t.Helper()

	require.NoError(t, tree.alive.SetReadDeadline(time.Now().Add(within)))
	_, err := tree.alive.Read(make([]byte, 1))
	return err
}

func readPIDs(t *testing.T, path string) (first, second int) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			fields := strings.Fields(string(data))
			if len(fields) == 2 {
				first, err1 := strconv.Atoi(fields[0])
				second, err2 := strconv.Atoi(fields[1])
				if err1 == nil && err2 == nil {
					return first, second
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("child never wrote its pids to %s", path)
	return 0, 0
}

// requireAlive uses signal 0, which checks for the process's existence without
// delivering anything.
func requireAlive(t *testing.T, pid int) {
	t.Helper()
	require.NoError(t, syscall.Kill(pid, 0), "pid %d should be alive", pid)
}

// processIsGone reports whether pid no longer runs anything.
//
// A killed but unreaped process is a zombie, and a pid is exactly what a
// zombie keeps, so kill(pid, 0) still succeeds for one. Whether that happens
// depends on who inherits the orphan: macOS hands it to launchd, which reaps,
// while `go test` inside a container is pid 1 and does not. Treating a zombie
// as alive is therefore a test that passes on one runner and fails on another
// while the code under test is behaving identically on both.
func processIsGone(pid int) bool {
	if err := syscall.Kill(pid, 0); err != nil {
		return true
	}
	return isZombie(pid)
}

func isZombie(pid int) bool {
	if runtime.GOOS != "linux" {
		return false
	}
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return true
	}
	// Field 3 is the state, and it follows the parenthesised command name.
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return false
	}
	fields := strings.Fields(string(data)[end+1:])
	return len(fields) > 0 && fields[0] == "Z"
}

func requireGoneWithin(t *testing.T, pid int, within time.Duration) {
	t.Helper()

	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if processIsGone(pid) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pid %d still running after %s", pid, within)
}

// TestProcessGroup_KillKillsGrandchildren is the acceptance test for #16 on
// Unix: killing the group must reach a process the agent never spawned
// directly.
func TestProcessGroup_KillKillsGrandchildren(t *testing.T) {
	tree := startTree(t)

	require.NoError(t, tree.group.Kill())

	requireReaped(t, tree, 10*time.Second)
	require.ErrorIs(t, waitForTreeExit(t, tree, 10*time.Second), io.EOF,
		"something in the tree is still holding the inherited pipe")
	requireGoneWithin(t, tree.grandchild, 10*time.Second)
}

// TestProcessGroup_SignalOnlyLeaderLeavesOrphans is the control for the test
// above. Without it, a Kill that happened to work for an unrelated reason —
// the grandchild dying with its parent's terminal, say — would look like
// proof that the group mechanism works.
func TestProcessGroup_SignalOnlyLeaderLeavesOrphans(t *testing.T) {
	tree := startTree(t)

	require.NoError(t, syscall.Kill(tree.leader, syscall.SIGKILL))
	requireReaped(t, tree, 10*time.Second)

	// The grandchild is reparented and keeps running: the pipe stays open and
	// the pid stays runnable. This is the failure mode process groups exist to
	// prevent, and it is what the test above proves does not happen.
	require.ErrorIs(t, waitForTreeExit(t, tree, 2*time.Second), os.ErrDeadlineExceeded,
		"the orphaned grandchild should still be holding the pipe")
	require.False(t, processIsGone(tree.grandchild))

	_ = syscall.Kill(tree.grandchild, syscall.SIGKILL)
}

func TestProcessGroup_TermReachesAHandler(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	marker := filepath.Join(dir, "handled")
	script := `trap 'echo handled > ` + marker + `; exit 0' TERM
while true; do sleep 0.05; done`

	group, err := platform.NewProcessGroup(platform.GroupConfig{})
	require.NoError(t, err)
	defer group.Close()

	cmd := exec.Command("/bin/sh", "-c", script)
	group.ConfigureCommand(cmd)
	require.NoError(t, cmd.Start())
	require.NoError(t, group.Adopt(cmd.Process))

	// Give the shell time to install the trap before signalling it.
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, group.Signal(platform.SignalTerm))

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = group.Kill()
		t.Fatal("the process did not exit after SIGTERM")
	}

	_, err = os.Stat(marker)
	require.NoError(t, err, "the TERM handler should have run")
}

// unallocatablePID is larger than any pid either kernel can hand out: Linux
// caps pid_max at 2^22 and Darwin at 99999. Every syscall below that takes it
// therefore answers ESRCH, on every run, on any host.
//
// A pid that *cannot* exist, rather than one that merely does not exist right
// now, and the difference is #82. A reaped pid is released, and the kernel is
// free to give it to somebody else — see
// TestProcessGroup_SignalAfterExitReachesWhatOutlivedTheLeader for what that
// did to the test this replaced. There is no pid that nothing will ever occupy,
// so the assertion moves to a number outside the space instead.
const unallocatablePID = 1 << 30

// TestProcessGroup_UnisolatedSignalReportsTheLeader states the cross-platform
// rule the Windows implementation was corrected to match: when the group
// mechanism did not take, the leader is the only thing that was ever acted on,
// so the leader's answer is the caller's.
//
// Unix gets this for free, because an unisolated group signals a bare pid and
// kill(2)'s errno is passed straight back. Windows did not: its job object
// terminates successfully whether or not anything is inside it, so a group
// whose Adopt failed reported a live, unreached process as killed. Pinning the
// rule here as well as there keeps the two from drifting apart again, on the
// two runners where it is cheapest to check.
//
// It carries what #14 needs from a group that is gone, too, because the state
// is the same one: a clean error, not a panic, and not a signal delivered to
// whatever inherited the pid. That last claim is the one the test this replaced
// could not actually make. It reaped a real child and signalled the pgid that
// released, so "nothing was delivered" held only while nothing else on the host
// had been handed that id — an assertion about the machine rather than about
// this package. Aiming at a pid the kernel cannot allocate makes it true by
// construction, and it is the shape the Windows half of this rule already uses:
// Adopt is handed a bare os.Process rather than a child that was started and
// reaped.
func TestProcessGroup_UnisolatedSignalReportsTheLeader(t *testing.T) {
	t.Parallel()

	group, err := platform.NewProcessGroup(platform.GroupConfig{})
	require.NoError(t, err)
	defer group.Close()

	// ConfigureCommand deliberately not called, so no session was ever asked
	// for and Adopt must record what it found rather than wait for one.
	require.NoError(t, group.Adopt(&os.Process{Pid: unallocatablePID}),
		"a pid the kernel does not know is the fast-exiting-child case, not an adoption failure")
	require.False(t, group.Isolated())
	require.Equal(t, unallocatablePID, group.PID())

	require.NotPanics(t, func() {
		err = group.Signal(platform.SignalTerm)
	}, "#14 depends on this being an error rather than a crash")
	require.ErrorIs(t, err, platform.ErrProcessNotFound,
		"the leader is gone and nothing else was ever in this group, so this must not read as success")
	require.ErrorIs(t, group.Kill(), platform.ErrProcessNotFound,
		"the escalation step answers the same way, or a stop loop cannot tell that it is finished")
}

// TestProcessGroup_SignalAfterExitReachesWhatOutlivedTheLeader is the half of
// the exit case that can be asserted at all, and it also records why the other
// half is not written here — so that it does not come back, because it was
// here, and it was #82.
//
// The tempting shape is to spawn a child, reap it, and assert that signalling
// its group reports ErrProcessNotFound. It fails under load in well under a
// tenth of a second — EPERM, not ESRCH — because reaping the leader releases
// the group id and the kernel had already handed it to something else by the
// time the signal went out. That is not a margin anyone can widen: it is the
// pid-as-identity hazard this repository has been bitten by four times, sitting
// inside a test that asserts the product does not make that assumption. Worse
// than flaky, the same call delivers the signal when the new occupant happens
// to be signallable.
//
// What is a fact is the rule underneath it: a group id belongs to its members
// until the last of them has been reaped, so a group that has outlived its
// leader is still there and still reachable. That is the state ExecService's
// watcher and the supervisor's stop path signal from, and the live descendant
// is also what makes the id un-recyclable for the length of this test.
func TestProcessGroup_SignalAfterExitReachesWhatOutlivedTheLeader(t *testing.T) {
	tree := startTree(t)

	// Kill the leader alone and reap it. Its group id survives, because the
	// grandchild it left behind is still in that group.
	require.NoError(t, syscall.Kill(tree.leader, syscall.SIGKILL))
	requireReaped(t, tree, 10*time.Second)
	require.Equal(t, tree.leader, tree.group.GroupID())

	// The signal still lands, on a leader that no longer exists.
	require.NoError(t, tree.group.Signal(platform.SignalTerm),
		"the group outlived its leader, so signalling it must not read as a group that is gone")
	require.ErrorIs(t, waitForTreeExit(t, tree, 10*time.Second), io.EOF,
		"the descendant that kept the group alive should have taken the signal")
}

// TestProcessGroup_AdoptKeepsTheGroupOfAChildThatBeatItToTheExit is the same
// defect as TestPTY_WithProcessGroup, in the form that actually reproduces on
// macOS, and it needs no load at all to show.
//
// Darwin's getpgid(2) answers ESRCH for a process that has exited and has not
// been reaped; Linux answers with the group. Adopt read that failure as "the
// group did not take" and recorded isolated = false — so the same command was
// isolated on one platform and not on the other, and on macOS a leader that
// exits quickly lost the post-exec sweep that is the only thing reaching the
// grandchild it left behind.
//
// The child here is held to exactly that state — exited, not reaped — by the
// pipe rather than by a sleep, so it is the state on both platforms and on
// every run.
func TestProcessGroup_AdoptKeepsTheGroupOfAChildThatBeatItToTheExit(t *testing.T) {
	t.Parallel()

	group, err := platform.NewProcessGroup(platform.GroupConfig{})
	require.NoError(t, err)
	defer group.Close()

	readEnd, writeEnd, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = readEnd.Close() })

	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	cmd.ExtraFiles = []*os.File{writeEnd}
	group.ConfigureCommand(cmd)
	require.NoError(t, cmd.Start())
	require.NoError(t, writeEnd.Close())
	t.Cleanup(func() { _ = cmd.Wait() })

	// EOF on the inherited pipe is the child being gone. Nothing has reaped it,
	// so its pid is still its own and this is not the recycling hazard.
	require.NoError(t, readEnd.SetReadDeadline(time.Now().Add(30*time.Second)))
	_, err = readEnd.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF, "the child should have exited and closed the pipe")

	require.NoError(t, group.Adopt(cmd.Process))
	require.True(t, group.Isolated(),
		"the child was configured for its own session and Start succeeded, so it had one; "+
			"whether getpgid still answers for it is a platform detail, not the answer")
	require.Equal(t, cmd.Process.Pid, group.GroupID())
}

// TestProcessGroup_AdoptReportsAGroupThatNeverTook is the second half of #82,
// through the API a caller uses.
//
// Adopt used to return nil whatever it found, so a child that was configured
// for its own session and did not get one was recorded as unisolated and never
// mentioned again. What follows from that is silent: Signal degrades to the
// bare leader pid, the post-exec sweep is skipped because it is gated on
// Isolated, and a command's descendants outlive the RPC with nothing in the log
// to say the guarantee did not hold. All three call sites already log a warning
// when Adopt fails — this is what makes them fire.
//
// The session is requested and then taken away again before Start, which is the
// state a lost race leaves behind and the only way to reach it on purpose.
func TestProcessGroup_AdoptReportsAGroupThatNeverTook(t *testing.T) {
	t.Parallel()

	group, err := platform.NewProcessGroup(platform.GroupConfig{})
	require.NoError(t, err)
	defer group.Close()

	cmd := exec.Command("/bin/sh", "-c", "sleep 30")
	group.ConfigureCommand(cmd)
	cmd.SysProcAttr.Setsid = false
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	err = group.Adopt(cmd.Process)
	require.Error(t, err, "a session was configured and the child is not in one; saying nothing is the defect")
	require.ErrorContains(t, err, strconv.Itoa(cmd.Process.Pid))
	require.False(t, group.Isolated())
	require.Equal(t, cmd.Process.Pid, group.PID(),
		"the command is running and its pid is the one thing left to act on, so it is still recorded")
	requireAlive(t, cmd.Process.Pid)
}

func TestProcessGroup_SignalBeforeAdopt(t *testing.T) {
	t.Parallel()

	group, err := platform.NewProcessGroup(platform.GroupConfig{})
	require.NoError(t, err)
	defer group.Close()

	require.ErrorIs(t, group.Signal(platform.SignalTerm), platform.ErrNoProcess)
	require.Zero(t, group.PID())
	require.False(t, group.Isolated())
}

func TestProcessGroup_UnconfiguredCommandIsNotIsolated(t *testing.T) {
	t.Parallel()

	group, err := platform.NewProcessGroup(platform.GroupConfig{})
	require.NoError(t, err)
	defer group.Close()

	// ConfigureCommand deliberately not called. Adopt must notice, because
	// signalling the negated group id here would signal the test binary's own
	// group.
	cmd := exec.Command("/bin/sh", "-c", "sleep 5")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	require.NoError(t, group.Adopt(cmd.Process))
	require.False(t, group.Isolated(), "an unconfigured child shares the agent's group")
	require.NotEqual(t, cmd.Process.Pid, group.GroupID())
}

func TestOpenProcessGroup(t *testing.T) {
	t.Parallel()

	group, err := platform.NewProcessGroup(platform.GroupConfig{})
	require.NoError(t, err)
	defer group.Close()

	cmd := exec.Command("/bin/sh", "-c", "sleep 30")
	group.ConfigureCommand(cmd)
	require.NoError(t, cmd.Start())
	reaped := make(chan struct{})
	go func() {
		_, _ = cmd.Process.Wait()
		close(reaped)
	}()
	t.Cleanup(func() {
		_ = group.Kill()
		<-reaped
	})
	require.NoError(t, group.Adopt(cmd.Process))

	// The re-adoption path: a fresh handle to a process this run did not
	// spawn, built from the pid alone.
	reopened, err := platform.OpenProcessGroup(cmd.Process.Pid, "")
	require.NoError(t, err)
	defer reopened.Close()

	require.Equal(t, cmd.Process.Pid, reopened.PID())
	require.True(t, reopened.Isolated())
	require.Equal(t, group.GroupID(), reopened.GroupID())

	require.NoError(t, reopened.Kill())
	select {
	case <-reaped:
	case <-time.After(10 * time.Second):
		t.Fatal("the re-adopted process did not exit")
	}
}

func TestOpenProcessGroup_MissingProcess(t *testing.T) {
	t.Parallel()

	_, err := platform.OpenProcessGroup(deadPID(t), "")
	require.ErrorIs(t, err, platform.ErrProcessNotFound)
}

func TestProcessGroup_ClosedGroupRefusesSignals(t *testing.T) {
	t.Parallel()

	group, err := platform.NewProcessGroup(platform.GroupConfig{})
	require.NoError(t, err)

	cmd := exec.Command("/bin/sh", "-c", "sleep 30")
	group.ConfigureCommand(cmd)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	require.NoError(t, group.Adopt(cmd.Process))

	require.NoError(t, group.Close())
	require.Error(t, group.Signal(platform.SignalTerm))

	// Close on Unix must not kill anything: a supervised process is meant to
	// outlive the agent, and Close is what the agent does on the way out.
	requireAlive(t, cmd.Process.Pid)
}

// TestConfigureInteractivePTYCommand_StillLeadsItsOwnSession pins the Unix
// half of the split `fleetctl shell` needs.
//
// The two configurations differ only on Windows, where the console process
// group flag that makes an agent-sent CTRL_BREAK aimable is the same flag that
// stops a typed Ctrl-C being delivered at all. On Unix there is nothing to give
// up: the child leads its own session with the pty as its controlling terminal,
// the line discipline turns 0x03 into a SIGINT for the foreground group, and
// the session's group is what a kill reaches. This asserts the interactive form
// still asks for all of that, so a future Windows-shaped change to it cannot
// quietly cost a Unix session its process group — which is what "closing the
// stream kills the whole tree" rests on.
func TestConfigureInteractivePTYCommand_StillLeadsItsOwnSession(t *testing.T) {
	t.Parallel()

	group, err := platform.NewProcessGroup(platform.GroupConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = group.Close() })

	cmd := &pty.Cmd{Path: "/bin/sh", Args: []string{"/bin/sh"}}
	group.ConfigureInteractivePTYCommand(cmd)

	require.NotNil(t, cmd.SysProcAttr)
	require.True(t, cmd.SysProcAttr.Setsid,
		"an interactive session's command must still lead its own session, or nothing can kill its tree")
}
