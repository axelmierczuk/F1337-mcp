package platform_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/platform"
)

// These run only on the Windows runner. They are written to be read by someone
// debugging a CI failure on a machine they do not have, so each one states
// what it is proving rather than leaving it to the assertion.

// startWindowsTree spawns PowerShell, which spawns a grandchild and reports
// both pids. Terminating node.exe alone leaving its children running is the
// exact failure the job object exists to prevent, so the test has to know a
// grandchild's pid to be worth anything.
func startWindowsTree(t *testing.T, cfg platform.GroupConfig) (group *platform.ProcessGroup, leader, grandchild int, reaped <-chan struct{}) {
	t.Helper()

	pidFile := filepath.Join(t.TempDir(), "pids.txt")
	script := "$child = Start-Process -PassThru -WindowStyle Hidden -FilePath ping.exe " +
		"-ArgumentList '-n','300','127.0.0.1'; " +
		"Set-Content -LiteralPath '" + pidFile + "' -Value \"$PID $($child.Id)\"; " +
		"Start-Sleep -Seconds 300"

	group, err := platform.NewProcessGroup(cfg)
	require.NoError(t, err)

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	group.ConfigureCommand(cmd)
	require.NoError(t, cmd.Start())

	done := make(chan struct{})
	go func() {
		_, _ = cmd.Process.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		_ = group.Kill()
		_ = group.Close()
		<-done
	})

	require.NoError(t, group.Adopt(cmd.Process))
	require.True(t, group.Isolated(), "the child must be inside the job object")
	require.Equal(t, cmd.Process.Pid, group.PID())

	leader, grandchild = readWindowsPIDs(t, pidFile)
	require.Equal(t, cmd.Process.Pid, leader)
	require.NotEqual(t, leader, grandchild)
	require.True(t, platform.ProcessExists(grandchild), "the grandchild should be running")

	return group, leader, grandchild, done
}

func readWindowsPIDs(t *testing.T, path string) (first, second int) {
	t.Helper()

	// PowerShell startup is slow and CI runners are slower.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil {
			fields := strings.Fields(string(data))
			if len(fields) == 2 {
				a, err1 := strconv.Atoi(fields[0])
				b, err2 := strconv.Atoi(fields[1])
				if err1 == nil && err2 == nil {
					return a, b
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("PowerShell never wrote its pids to %s", path)
	return 0, 0
}

// requireGoneWithin waits for a pid to stop existing.
//
// Only valid for a process this test holds no handle to. Windows keeps the
// process object, and with it the pid, until every handle closes, so a
// process the test itself started through os/exec keeps existing until Wait
// runs no matter how thoroughly it has been terminated. For those, wait on
// the channel from sleeperWithExit first.
func requireGoneWithin(t *testing.T, pid int, within time.Duration) {
	t.Helper()

	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if !platform.ProcessExists(pid) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("pid %d still exists after %s", pid, within)
}

// TestJobObject_KillKillsTheTree is the acceptance test for #16 on Windows.
func TestJobObject_KillKillsTheTree(t *testing.T) {
	group, leader, grandchild, reaped := startWindowsTree(t, platform.GroupConfig{})

	require.NoError(t, group.Kill())

	select {
	case <-reaped:
	case <-time.After(30 * time.Second):
		t.Fatalf("leader pid %d did not exit", leader)
	}
	requireGoneWithin(t, grandchild, 30*time.Second)
}

// TestJobObject_KillOnCloseKillsTheTree covers the flag one-shot exec relies
// on: closing the last handle to the job takes the tree with it, so an RPC
// cannot leak a grandchild by returning early.
func TestJobObject_KillOnCloseKillsTheTree(t *testing.T) {
	group, leader, grandchild, reaped := startWindowsTree(t, platform.GroupConfig{KillOnClose: true})

	require.NoError(t, group.Close())

	select {
	case <-reaped:
	case <-time.After(30 * time.Second):
		t.Fatalf("leader pid %d did not exit when the job handle closed", leader)
	}
	requireGoneWithin(t, grandchild, 30*time.Second)
}

// TestJobObject_ReopenByName covers the re-adoption path: after a daemon
// restart there is no job handle left in memory, only the name that was
// persisted with the process record.
func TestJobObject_ReopenByName(t *testing.T) {
	name := "sandboxd-test-" + strconv.Itoa(os.Getpid()) + "-" + t.Name()
	_, leader, grandchild, reaped := startWindowsTree(t, platform.GroupConfig{Name: name})

	reopened, err := platform.OpenProcessGroup(leader, name)
	require.NoError(t, err)
	defer reopened.Close()
	require.True(t, reopened.Isolated(), "the reopened handle should point at the same job")
	require.Equal(t, leader, reopened.PID())

	require.NoError(t, reopened.Kill())

	select {
	case <-reaped:
	case <-time.After(30 * time.Second):
		t.Fatalf("leader pid %d did not exit", leader)
	}
	requireGoneWithin(t, grandchild, 30*time.Second)
}

// TestJobObject_ReopenWithUnknownNameDegrades checks the documented fallback:
// a name that no longer resolves leaves a handle that controls the leader
// alone, rather than an error that would strand the process entirely.
func TestJobObject_ReopenWithUnknownNameDegrades(t *testing.T) {
	pid, exited := sleeperWithExit(t)

	reopened, err := platform.OpenProcessGroup(pid, "sandboxd-test-no-such-job-"+strconv.Itoa(os.Getpid()))
	require.NoError(t, err)
	defer reopened.Close()

	require.False(t, reopened.Isolated(), "no job means no tree guarantee, and the caller must be able to see that")
	require.Equal(t, pid, reopened.PID())
	require.NoError(t, reopened.Kill())

	// Wait for the handle os/exec holds to be released before asking whether
	// the pid is gone; until then Windows keeps the process object, and
	// OpenProcess on it still succeeds.
	select {
	case <-exited:
	case <-time.After(30 * time.Second):
		t.Fatalf("pid %d did not exit after Kill", pid)
	}
	requireGoneWithin(t, pid, 30*time.Second)
}

func TestSignal_UnsupportedOnWindows(t *testing.T) {
	t.Parallel()

	group, err := platform.NewProcessGroup(platform.GroupConfig{})
	require.NoError(t, err)
	defer group.Close()

	cmd := exec.Command("cmd", "/c", "ping -n 60 127.0.0.1 > NUL")
	group.ConfigureCommand(cmd)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = group.Kill()
		_, _ = cmd.Process.Wait()
	})
	require.NoError(t, group.Adopt(cmd.Process))

	for _, sig := range []platform.Signal{platform.SignalHup, platform.SignalUSR1, platform.SignalUSR2} {
		require.ErrorIsf(t, group.Signal(sig), platform.ErrSignalUnsupported, "signal %s", sig)
	}
}

func TestOpenProcessGroup_MissingProcessWindows(t *testing.T) {
	t.Parallel()

	_, err := platform.OpenProcessGroup(deadPID(t), "")
	require.ErrorIs(t, err, platform.ErrProcessNotFound)
}

// TestJobObject_ClosedGroupRefusesSignals is the Windows half of the rule the
// Unix suite already pins: a closed group signals nothing, and closing a group
// created without KillOnClose leaves the process running, because a supervised
// process is meant to outlive the agent and Close is what the agent does on
// the way out.
func TestJobObject_ClosedGroupRefusesSignals(t *testing.T) {
	group, err := platform.NewProcessGroup(platform.GroupConfig{})
	require.NoError(t, err)

	pid, _ := sleeperInGroup(t, group)
	require.NoError(t, group.Close())
	require.Error(t, group.Signal(platform.SignalTerm))
	require.Error(t, group.Kill())
	require.True(t, platform.ProcessExists(pid), "Close without KillOnClose must not kill anything")
}

// TestJobObject_KillRacingClose covers the job handle's lifetime.
//
// Kill and Close are both public, and `defer g.Close()` next to a Kill from a
// timeout goroutine is the ordinary way to drive this type. Reading g.job out
// from under the lock and using it afterwards lets Close release the handle
// mid-Kill; Windows reissues handle values as soon as they are free, so the
// stale value can name an unrelated object by the time TerminateJobObject
// reaches it.
//
// The interleaving cannot be forced, so this is a stress test rather than a
// deterministic one: what it pins is the invariant that survives any
// interleaving. Every outcome must be either success or the closed-group
// error. An invalid-handle error from TerminateJobObject can only come from a
// handle that Close had already released, which is precisely the defect.
func TestJobObject_KillRacingClose(t *testing.T) {
	for i := range 40 {
		group, err := platform.NewProcessGroup(platform.GroupConfig{})
		require.NoError(t, err)

		pid, exited := sleeperInGroup(t, group)

		var wg sync.WaitGroup
		results := make(chan error, 2)
		wg.Add(2)
		go func() { defer wg.Done(); results <- group.Kill() }()
		go func() { defer wg.Done(); results <- group.Close() }()
		wg.Wait()
		close(results)

		for err := range results {
			if err == nil || strings.Contains(err.Error(), "process group is closed") {
				continue
			}
			t.Fatalf("iteration %d: Kill racing Close returned %v; the only legitimate "+
				"outcomes are success and the closed-group error, so an error from the "+
				"job object here means the handle was used after Close released it", i, err)
		}

		// Close may have won the race, in which case nothing killed the child.
		_ = group.Close()
		terminatePID(pid)
		select {
		case <-exited:
		case <-time.After(30 * time.Second):
			t.Fatalf("iteration %d: pid %d never exited", i, pid)
		}
	}
}

// sleeperInGroup starts a child inside group and returns its pid plus a
// channel that closes once os/exec has waited on it. The wait matters on
// Windows: the pid stays valid until the last handle to the process closes.
func sleeperInGroup(t *testing.T, group *platform.ProcessGroup) (pid int, exited <-chan struct{}) {
	t.Helper()

	cmd := exec.Command("cmd", "/c", "ping -n 60 127.0.0.1 > NUL")
	group.ConfigureCommand(cmd)
	require.NoError(t, cmd.Start())

	reaped := make(chan struct{})
	go func() {
		_, _ = cmd.Process.Wait()
		close(reaped)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-reaped
	})

	require.NoError(t, group.Adopt(cmd.Process))
	return cmd.Process.Pid, reaped
}

// terminatePID kills a pid outright, without going through ProcessGroup, so a
// test can clean up after a group that may already be closed. It is best
// effort: the process may have been killed by the group a moment earlier.
func terminatePID(pid int) {
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Kill()
	}
}
