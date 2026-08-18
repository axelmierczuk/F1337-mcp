//go:build linux

package exec

import (
	"bufio"
	"context"
	"os"
	osexec "os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// This is the reproduction, and it is the only place in this repository where
// "the kernel gave the released id to somebody else" is arranged rather than
// argued about.
//
// Everywhere else the hazard is asserted from the side that can be asserted
// portably: a group is pointed at an id something else is holding, and required
// not to signal it. That is the same call with the same target, but it is not
// the same event — the event is a pid being handed out again, and reproducing
// it needs control of pid allocation. A pid namespace gives that:
// /proc/sys/kernel/ns_last_pid decides which number the next fork gets, and a
// namespace with a hundred processes in it has the number free.
//
// Opt-in, because it needs a namespace of its own and CAP_SYS_ADMIN to write
// that file:
//
//	make test-pidreuse
//
// which is:
//
//	docker run --rm --privileged -v "$PWD:/src" -w /src golang:1.25 \
//	  go test -count=1 -v -run PIDReuse ./internal/agent/exec/
//
// #91 and #96 were reproduced this way and the runs are quoted in
// platform.AwaitExit. This is #105's: the exec timeout watcher signalling a
// group id that the call's own wait had already given back.

// pidNSReuseEnv opts in to the reproduction.
const pidNSReuseEnv = "FLEET_PIDNS_REUSE"

// nsLastPID is the knob. The kernel allocates the next pid from it.
const nsLastPID = "/proc/sys/kernel/ns_last_pid"

// TestPIDReuse_TheTimeoutWatcherDoesNotSignalTheProcessThatTookTheID runs the
// watcher against a group whose id a stranger now holds, and requires the
// stranger to survive.
//
// The steps are #105 in order:
//
//  1. A command leads its own session and exits. Its group is empty.
//  2. Its wait collects it, which is what hands the group id back — the same
//     call run's wait goroutine makes, through the same function.
//  3. The kernel gives that id to an unrelated session leader.
//  4. The watcher times out and signals the group, which is what it does for
//     any command it believes is still running — and it does believe it, because
//     done is closed only after the wait has returned, and os/exec's Wait does
//     not return until the output copiers do.
//
// Before the fix, step 4 delivered SIGTERM and then SIGKILL to the stranger's
// whole process group, and reported success. The recorded fact is what the
// stranger dies of: it declines SIGTERM, so a SIGKILL in its status is the
// watcher's, and this test's own SIGTERM at the end is the one it should have.
func TestPIDReuse_TheTimeoutWatcherDoesNotSignalTheProcessThatTookTheID(t *testing.T) {
	if os.Getenv(pidNSReuseEnv) != "1" {
		t.Skipf("set %s=1 inside a pid namespace with CAP_SYS_ADMIN to run this; see the file comment or `make test-pidreuse`", pidNSReuseEnv)
	}
	if err := os.WriteFile(nsLastPID, []byte("0"), 0o600); err != nil {
		t.Fatalf("%s is not writable, so pid allocation cannot be steered and nothing here would be reproduced: %v", nsLastPID, err)
	}

	group, cmd := isolatedChild(t, "exit", "0")
	pgid := group.GroupID()
	require.Equal(t, cmd.Process.Pid, pgid, "the command does not lead its own group, so there is no id here to lose")

	// The collection, through the product's own wait. Past this line the group
	// id is the kernel's again.
	require.NoError(t, waitForCommand(cmd, group, testLogger(&strings.Builder{})))
	t.Logf("leader %d collected; the group is empty and its id is free", pgid)

	bystander := startSessionLeaderAt(t, pgid)
	require.Equal(t, pgid, bystander.Process.Pid,
		"the id was not handed on, so a signal to it would reach nothing and this would pass without proving anything")
	t.Logf("the kernel handed pid %d to an unrelated session leader", bystander.Process.Pid)

	// And now the watcher, on a group it has every reason to believe is still
	// running: nothing closes done, which is exactly what it sees while Wait is
	// parked on a descendant that inherited the pipes.
	h := newHarness(t)
	w := h.svc.watch(context.Background(), group, time.Millisecond, make(chan struct{}))
	<-w.finished

	require.True(t, w.timedOut.Load(), "the watcher never decided to kill anything, so it signalled nothing for the wrong reason")
	require.Contains(t, h.logs.String(), "signal=TERM", "the escalation's first signal was never decided on")
	require.Contains(t, h.logs.String(), "signal=KILL", "the escalation's second signal was never decided on")
	require.ErrorIs(t, group.Kill(), platform.ErrGroupReleased)

	requireStillRunning(t, bystander.Process.Pid,
		"the timeout watcher killed a process group it never started: on a developer's machine that is their editor or their build")

	// And the control, which is what stops the assertion above being a test of
	// nothing: the same id, reached by the same call, from a group that still
	// holds it. If this does not kill the bystander then the id was never
	// reachable and its survival meant only that.
	control, err := platform.OpenProcessGroup(bystander.Process.Pid, "")
	require.NoError(t, err)
	require.NoError(t, control.Kill())
	_ = bystander.Wait()
	require.NotNil(t, bystander.ProcessState)
	sig, signalled := terminatingSignal(bystander.ProcessState)
	require.True(t, signalled)
	require.Equal(t, "SIGKILL", sig,
		"a group signal to this id reaches nothing, so the watcher not reaching it proved nothing")
}

// startSessionLeaderAt places an unrelated session leader on target.
//
// Its own session, so target is its process group id and not merely its pid:
// what the watcher sends is kill(-pgid), and a process that merely held the
// number would not answer it.
//
// The placement is checked and retried rather than assumed. Threads the Go
// runtime starts consume pids from the same namespace, so a write to
// ns_last_pid is a request rather than a guarantee.
func startSessionLeaderAt(t *testing.T, target int) *osexec.Cmd {
	t.Helper()

	for range 200 {
		require.NoError(t, os.WriteFile(nsLastPID, []byte(strconv.Itoa(target-1)), 0o600))

		cmd := osexec.Command(mustExecutable(t)) //nolint:gosec // the test binary re-executing itself
		cmd.Env = append(os.Environ(), helperEnvFor("ignore-term"))
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		stdout, err := cmd.StdoutPipe()
		require.NoError(t, err)
		require.NoError(t, cmd.Start())
		if cmd.Process.Pid != target {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			continue
		}

		// It announces itself once its SIGTERM handler is installed, so the
		// signal it declines is one it was ready for.
		line, err := bufio.NewReader(stdout).ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, "ready", strings.TrimSpace(line))
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		})
		return cmd
	}
	t.Fatalf("could not place a process on pid %d", target)
	return nil
}

// requireStillRunning reports whether a process this test started is still
// running, reading the kernel's own answer rather than asking whether its pid
// exists.
//
// The distinction is the whole point here. A process that has been SIGKILLed
// and not collected keeps its pid and answers kill(pid, 0) forever, so "the pid
// is there" is exactly as true for a bystander that survived as for one the
// watcher killed. The state field in /proc says which, and this is the platform
// that has it.
func requireStillRunning(t *testing.T, pid int, whatItMeans string) {
	t.Helper()

	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	require.NoError(t, err, whatItMeans)

	// Field 3 is the state, after the parenthesised command name — which may
	// itself contain spaces and parentheses.
	end := strings.LastIndexByte(string(data), ')')
	require.Positive(t, end)
	fields := strings.Fields(string(data)[end+1:])
	require.NotEmpty(t, fields)
	require.NotEqual(t, "Z", fields[0], whatItMeans)
}
