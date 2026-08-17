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

func TestProcessGroup_SignalAfterExit(t *testing.T) {
	t.Parallel()

	group, err := platform.NewProcessGroup(platform.GroupConfig{})
	require.NoError(t, err)
	defer group.Close()

	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	group.ConfigureCommand(cmd)
	require.NoError(t, cmd.Start())
	require.NoError(t, group.Adopt(cmd.Process))
	require.NoError(t, cmd.Wait())

	// Once the group is empty the kernel has nothing to signal. A clean error
	// is required here — #14 depends on this not being a panic and not being
	// a signal delivered to whatever inherited the pid.
	err = group.Signal(platform.SignalTerm)
	require.ErrorIs(t, err, platform.ErrProcessNotFound)
}

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
func TestProcessGroup_UnisolatedSignalReportsTheLeader(t *testing.T) {
	t.Parallel()

	group, err := platform.NewProcessGroup(platform.GroupConfig{})
	require.NoError(t, err)
	defer group.Close()

	// ConfigureCommand deliberately not called, so the child never leaves the
	// test binary's own group and Adopt leaves Isolated false.
	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	require.NoError(t, cmd.Start())
	require.NoError(t, group.Adopt(cmd.Process))
	require.False(t, group.Isolated())
	require.NoError(t, cmd.Wait())

	require.ErrorIs(t, group.Signal(platform.SignalTerm), platform.ErrProcessNotFound,
		"the leader is gone and nothing else was ever in this group, so this must not read as success")
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
