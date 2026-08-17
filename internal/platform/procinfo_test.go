package platform_test

import (
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/platform"
)

// sleeper starts a process that stays alive until the test ends, and returns
// its pid.
func sleeper(t *testing.T) int {
	t.Helper()
	pid, _ := sleeperWithExit(t)
	return pid
}

// sleeperWithExit is sleeper plus a channel that closes once the process has
// been waited on.
//
// Any assertion that a process is *gone* needs that wait. A pid is not
// released while something still holds the process: on Unix an unreaped child
// is a zombie, and on Windows the process object outlives termination until
// the last handle closes — os/exec holds one until Wait returns. Either way a
// killed process keeps answering "I exist", and a test that skips the wait is
// asserting against a pid that cannot yet have been released.
//
// The Windows side runs ping.exe directly rather than through `cmd /c`, which
// would be two processes and would leave the ping running after the cleanup
// killed the pid this returns. os/exec points a nil Stdout at NUL, so nothing
// is lost with the redirection.
func sleeperWithExit(t *testing.T) (pid int, exited <-chan struct{}) {
	t.Helper()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping.exe", "-n", "60", "127.0.0.1")
	} else {
		cmd = exec.Command("/bin/sh", "-c", "sleep 60")
	}
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
	return cmd.Process.Pid, reaped
}

// deadPID returns a pid that existed and no longer does.
//
// Reaping the child first is what makes it safe: an unwaited child is a zombie
// and still holds its pid, which would make "this process is gone" tests pass
// for the wrong reason.
func deadPID(t *testing.T) int {
	t.Helper()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "exit 0")
	} else {
		cmd = exec.Command("/bin/sh", "-c", "exit 0")
	}
	require.NoError(t, cmd.Start())
	pid := cmd.Process.Pid
	_ = cmd.Wait()

	// Windows keeps the pid reserved while any handle to the process is open;
	// os/exec releases its handle in Wait. Give the kernel a moment either way.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !platform.ProcessExists(pid) {
			return pid
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Skipf("pid %d is still reported as existing after it was reaped", pid)
	return 0
}

func TestStatProcess_Self(t *testing.T) {
	t.Parallel()

	info, err := platform.StatProcess(os.Getpid())
	require.NoError(t, err)
	require.Equal(t, os.Getpid(), info.PID)
	require.NotEmpty(t, info.StartID)
	require.False(t, info.StartTime.IsZero())
	require.WithinRange(t, info.StartTime, time.Now().Add(-time.Hour), time.Now().Add(2*time.Second),
		"the test binary started moments ago; a value outside this window means the platform read is wrong")
}

// TestStatProcess_StableAcrossReads covers the acceptance criterion directly.
// A start identity that moves between reads is worse than none, because the
// supervisor would orphan healthy processes at random.
func TestStatProcess_StableAcrossReads(t *testing.T) {
	t.Parallel()

	first, err := platform.StatProcess(os.Getpid())
	require.NoError(t, err)

	for i := range 50 {
		again, err := platform.StatProcess(os.Getpid())
		require.NoError(t, err)
		require.Equalf(t, first.StartID, again.StartID, "start id changed on read %d", i)
		require.Equalf(t, first.StartTime, again.StartTime, "start time changed on read %d", i)
		if i%10 == 0 {
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func TestStatProcess_OtherProcess(t *testing.T) {
	t.Parallel()

	pid := sleeper(t)
	info, err := platform.StatProcess(pid)
	require.NoError(t, err)
	require.Equal(t, pid, info.PID)
	require.NotEmpty(t, info.StartID)
}

func TestStatProcess_NotFound(t *testing.T) {
	t.Parallel()

	_, err := platform.StatProcess(deadPID(t))
	require.ErrorIs(t, err, platform.ErrProcessNotFound)
}

func TestStatProcess_InvalidPID(t *testing.T) {
	t.Parallel()

	for _, pid := range []int{0, -1, -12345} {
		_, err := platform.StatProcess(pid)
		require.Errorf(t, err, "pid %d", pid)
	}
}

func TestProcessExists(t *testing.T) {
	t.Parallel()

	require.True(t, platform.ProcessExists(os.Getpid()))
	require.False(t, platform.ProcessExists(deadPID(t)))
}

// TestStartTime_OrdersTwoProcesses checks the reads are not merely stable but
// correct. A parser that returned a fixed number, or read the wrong field of
// /proc/<pid>/stat, would pass every stability test and fail this one.
func TestStartTime_OrdersTwoProcesses(t *testing.T) {
	t.Parallel()

	const gap = 1200 * time.Millisecond

	firstPID := sleeper(t)
	first, err := platform.StatProcess(firstPID)
	require.NoError(t, err)

	time.Sleep(gap)

	secondPID := sleeper(t)
	second, err := platform.StatProcess(secondPID)
	require.NoError(t, err)

	require.True(t, second.StartTime.After(first.StartTime),
		"the later process must report the later start time: %s vs %s", first.StartTime, second.StartTime)

	// The boot-time offset the Linux read adds cancels out in the difference,
	// so this is a direct check on the resolution of the underlying value.
	// Bounds are loose because CI schedulers are not.
	delta := second.StartTime.Sub(first.StartTime)
	require.Greater(t, delta, gap/2, "measured gap %s, expected around %s", delta, gap)
	require.Less(t, delta, 30*time.Second, "measured gap %s, expected around %s", delta, gap)
}

// TestSameProcess_RejectsAStaleRecord is the pid-reuse property #15 depends
// on, in the form #15's own acceptance criterion describes: a record whose pid
// now belongs to an unrelated process must not match.
//
// The reuse is fabricated rather than provoked. Forcing the kernel to hand out
// a specific pid again means cycling the entire pid space — over four million
// spawns on a default Linux — which no test can do, and provoking it by luck
// would make the suite non-deterministic. What is exercised here is the same
// comparison the supervisor makes: a persisted start identity against the
// process that holds that pid now.
func TestSameProcess_RejectsAStaleRecord(t *testing.T) {
	t.Parallel()

	firstPID := sleeper(t)
	first, err := platform.StatProcess(firstPID)
	require.NoError(t, err)

	// Linux records start time in 10ms clock ticks, so two processes started
	// in the same tick share a value. Separating them guarantees the identities
	// differ. Real pid reuse cannot land inside one tick — the pid space would
	// have to be cycled in ten milliseconds — so this sleep buys determinism,
	// not correctness.
	time.Sleep(60 * time.Millisecond)

	secondPID := sleeper(t)
	second, err := platform.StatProcess(secondPID)
	require.NoError(t, err)

	require.NotEqual(t, first.StartID, second.StartID,
		"two processes started 60ms apart must have distinguishable start identities")

	// The supervisor's question, asked about the wrong process.
	require.False(t, platform.SameProcess(secondPID, first.StartID),
		"a record from another process must not match; this is what stops the agent signalling something it does not own")
	require.True(t, platform.SameProcess(secondPID, second.StartID))
}

func TestSameProcess_FailsClosed(t *testing.T) {
	t.Parallel()

	self, err := platform.StatProcess(os.Getpid())
	require.NoError(t, err)

	require.True(t, platform.SameProcess(os.Getpid(), self.StartID))
	require.False(t, platform.SameProcess(os.Getpid(), ""), "an empty record never matches")
	require.False(t, platform.SameProcess(os.Getpid(), "nonsense"))
	require.False(t, platform.SameProcess(deadPID(t), self.StartID), "a dead pid never matches")
	require.False(t, platform.SameProcess(-1, self.StartID))
}
