package process

import (
	"context"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// TestTermReachesAProcessThatHandlesIt asserts the handler actually ran, not
// merely that the process is gone — a SIGKILL would also make it gone.
//
// Windows has no deliverable, catchable termination request for a process
// without a console, so TERM there is a job termination and there is no handler
// to run. The test asserts the platform's real contract rather than skipping.
func TestTermReachesAProcessThatHandlesIt(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	r := ts.startHelper("handles-term", "handle-term")
	waitForLine(t, r, 10*time.Second, "waiting for TERM")

	require.NoError(t, ts.signalRecord(r, platform.SignalTerm, true))
	waitState(t, r, 10*time.Second,
		sandboxdv1.ProcessState_PROCESS_STATE_EXITED,
		sandboxdv1.ProcessState_PROCESS_STATE_CRASHED)

	if runtime.GOOS == "windows" {
		// The job was terminated. Nothing ran a handler, and the exit is not
		// clean — which is what CRASHED means.
		require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_CRASHED, r.currentState())
		return
	}
	waitForLine(t, r, 5*time.Second, "handled TERM")
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_EXITED, r.currentState())
	require.EqualValues(t, 0, r.status().GetExitCode())
}

// TestGracefulStopEscalatesToKill: a process that catches SIGTERM and ignores it
// is killed once the grace period is up, and the caller is told it came to that.
func TestGracefulStopEscalatesToKill(t *testing.T) {
	if runtime.GOOS == "windows" {
		// A Windows TERM is already a job termination; there is nothing to
		// ignore and nothing to escalate to. The graceful path is still
		// exercised there by TestGracefulStopStopsAProcess.
		t.Skip("Windows has no catchable termination request to ignore")
	}
	t.Parallel()
	ts := newTestSupervisor(t)

	r := ts.startHelper("ignores-term", "ignore-term")
	waitForLine(t, r, 10*time.Second, "ignoring TERM")
	pid := int(r.status().GetPid())

	escalated, err := ts.gracefulStop(r, 200*time.Millisecond, true, true)
	require.NoError(t, err)
	require.True(t, escalated, "a process that ignored SIGTERM must be reported as escalated")

	require.False(t, isLive(r.currentState()))
	waitFor(t, 5*time.Second, "the killed process to be gone", func() bool { return !pidAlive(pid) })
	require.Contains(t, strings.Join(logTexts(r), "\n"), "escalating to SIGKILL")
}

func TestGracefulStopStopsAProcess(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	r := ts.startHelper("cooperative", "silent")
	pid := int(r.status().GetPid())

	escalated, err := ts.gracefulStop(r, 2*time.Second, true, true)
	require.NoError(t, err)
	require.False(t, escalated, "a process with no TERM handler dies on the signal, without escalation")
	require.False(t, isLive(r.currentState()))
	waitFor(t, 5*time.Second, "the stopped process to be gone", func() bool { return !pidAlive(pid) })
}

// TestWholeTreeIsKilled is the acceptance test that matters most in #14.
// Signalling only the leader routinely leaves orphans: killing `npm run dev`
// without its group leaves the bundler holding the port, and the next start
// then fails to bind.
func TestWholeTreeIsKilled(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	r := ts.startHelper("has-children", "spawn")
	line := waitForLine(t, r, 20*time.Second, "grandchild ")

	grandchild, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "grandchild ")))
	require.NoError(t, err)
	require.NotZero(t, grandchild)
	leader := int(r.status().GetPid())
	require.NotEqual(t, leader, grandchild)

	// Both are running before the stop, so the assertion afterwards is about
	// the stop and not about a grandchild that never started.
	require.True(t, pidRunning(leader), "the leader should be running")
	require.True(t, pidRunning(grandchild), "the grandchild should be running")
	t.Cleanup(func() { killPID(t, grandchild) })

	_, err = ts.gracefulStop(r, 300*time.Millisecond, true, true)
	require.NoError(t, err)

	// pidRunning, not pidAlive: a killed-but-uncollected process answers every
	// portable liveness question forever, so "it stopped answering" is not the
	// same claim as "it is no longer running" — and the second is the one #14
	// asks for. The leader is this test binary's own child and is collected by
	// the supervisor's monitor; the grandchild is reparented on the leader's
	// death and collected by whatever init this host runs, which on a container
	// with no reaper is nothing at all.
	waitFor(t, 10*time.Second, "the leader to be gone", func() bool { return !pidRunning(leader) })
	waitFor(t, 10*time.Second, "the grandchild to be gone — no survivors",
		func() bool { return !pidRunning(grandchild) })
}

// TestSignalDoesNotTrustACachedPID is the pid-reuse guard on the signalling
// path. The record's start identity is deliberately corrupted, which is exactly
// what a reused pid looks like from the supervisor's side.
func TestSignalDoesNotTrustACachedPID(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	r := ts.startHelper("not-mine", "silent")
	pid := int(r.status().GetPid())

	r.mu.Lock()
	r.startID = "definitely-not-this-process"
	r.mu.Unlock()

	err := ts.signalRecord(r, platform.SignalKill, true)
	require.ErrorIs(t, err, errAlreadyExited)

	// And the process is untouched. Signalling a pid the agent cannot prove is
	// its own is how a supervisor kills someone's database.
	require.True(t, pidAlive(pid), "the supervisor must not signal a pid it cannot prove is its own")
}

func TestSignallingAnExitedProcessIsACleanError(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)
	ctx := context.Background()

	start, err := svc.StartProcess(ctx, &sandboxdv1.StartProcessRequest{
		Argv: helperArgv(t, "exit", "0"),
		Name: "gone",
		Env:  helperEnviron(),
	})
	require.NoError(t, err)

	r, ok := svc.sup.lookup(start.GetStatus().GetProcessId())
	require.True(t, ok)
	waitState(t, r, 10*time.Second, sandboxdv1.ProcessState_PROCESS_STATE_EXITED)

	_, err = svc.SignalProcess(ctx, &sandboxdv1.SignalProcessRequest{
		ProcessId: r.id,
		Signal:    sandboxdv1.SignalProcessRequest_SIGNAL_TERM,
	})
	require.Error(t, err)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "already exited")
}

func TestSignalProcessDefaultsToTheGroup(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)

	start, err := svc.StartProcess(context.Background(), &sandboxdv1.StartProcessRequest{
		Argv: helperArgv(t, "silent"),
		Name: "grouped",
		Env:  helperEnviron(),
	})
	require.NoError(t, err)

	// process_group is an optional bool precisely so that "unset" is
	// distinguishable from "false", and unset must mean the group.
	req := &sandboxdv1.SignalProcessRequest{
		ProcessId:    start.GetStatus().GetProcessId(),
		GracefulStop: true,
		GracePeriod:  durationpb.New(500 * time.Millisecond),
	}
	require.Nil(t, req.ProcessGroup)

	resp, err := svc.SignalProcess(context.Background(), req)
	require.NoError(t, err)
	require.False(t, isLive(resp.GetStatus().GetState()))
}

func TestUnsupportedSignalIsRejected(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)

	start, err := svc.StartProcess(context.Background(), &sandboxdv1.StartProcessRequest{
		Argv: helperArgv(t, "silent"),
		Name: "signal-vocabulary",
		Env:  helperEnviron(),
	})
	require.NoError(t, err)

	_, err = svc.SignalProcess(context.Background(), &sandboxdv1.SignalProcessRequest{
		ProcessId: start.GetStatus().GetProcessId(),
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "an unspecified signal is a caller error")

	if runtime.GOOS == "windows" {
		// HUP has no Windows meaning, and mapping it onto a termination would
		// be the worst possible reading of a reload request.
		_, err = svc.SignalProcess(context.Background(), &sandboxdv1.SignalProcessRequest{
			ProcessId: start.GetStatus().GetProcessId(),
			Signal:    sandboxdv1.SignalProcessRequest_SIGNAL_HUP,
		})
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	}
}

func TestOnFailureRestartsACrashButNotACleanExit(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	clean := ts.helperSpec("clean-exit", "exit", "0")
	clean.restartPolicy = sandboxdv1.RestartPolicy_RESTART_POLICY_ON_FAILURE
	r, err := ts.start(clean, false)
	require.NoError(t, err)
	waitState(t, r, 10*time.Second, sandboxdv1.ProcessState_PROCESS_STATE_EXITED)

	// Give the policy every chance to fire, then assert it did not.
	time.Sleep(300 * time.Millisecond)
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_EXITED, r.currentState())
	require.EqualValues(t, 0, r.status().GetRestartCount())

	crashy := ts.helperSpec("crashing", "exit", "1", "50")
	crashy.restartPolicy = sandboxdv1.RestartPolicy_RESTART_POLICY_ON_FAILURE
	crashy.maxRestarts = 2
	c, err := ts.start(crashy, false)
	require.NoError(t, err)

	waitFor(t, 20*time.Second, "the crash to be restarted", func() bool {
		return c.status().GetRestartCount() >= 1
	})
}

func TestAlwaysRestartsACleanExitToo(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	spec := ts.helperSpec("always-up", "exit", "0", "30")
	spec.restartPolicy = sandboxdv1.RestartPolicy_RESTART_POLICY_ALWAYS
	spec.maxRestarts = 3
	r, err := ts.start(spec, false)
	require.NoError(t, err)

	waitFor(t, 20*time.Second, "a clean exit to be restarted under the always policy", func() bool {
		return r.status().GetRestartCount() >= 1
	})
}

// TestBackoffGrowsBetweenRestarts asserts that each wait is longer than the one
// before it.
//
// Not that any of them equals a wall-clock figure: the previous version of this
// test required the first three restarts to take at least 700ms and failed on a
// CI runner at 649ms, which is the test being wrong rather than the runner being
// slow. Comparing the waits to each other is scale-free — it holds on a fast
// machine and a starved one alike, and a supervisor that hot-loops fails it on
// both.
//
// The wait measured is exit-to-next-spawn, not spawn-to-spawn. Spawn-to-spawn
// also contains the process's own startup and the log drain that follows its
// exit, and on a loaded runner those vary by more than the difference between
// two consecutive backoffs — which is how a correct supervisor gets a test
// failure. Between the exit transition and the next spawn there is nothing but
// the timer.
func TestBackoffGrowsBetweenRestarts(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t, func(c *testSupervisorOptions) {
		// High enough that the cap is not what the test ends up measuring.
		c.maxRestartBackoff = 10 * time.Second
		// And out of reach, so the counter reset is not either. A run that
		// lasts longer than the stability window resets the budget, and on a
		// loaded runner a race-instrumented helper takes long enough to start
		// and exit to cross a window measured in hundreds of milliseconds —
		// at which point the counter this test is waiting on goes back to zero
		// and it waits out its deadline for a number it will never see. The
		// reset has its own test; this one is about the backoff.
		c.stabilityWindow = time.Hour
	})

	spec := ts.helperSpec("backing-off", "exit", "1")
	spec.restartPolicy = sandboxdv1.RestartPolicy_RESTART_POLICY_ON_FAILURE
	spec.maxRestarts = 3
	spec.restartBackoff = 300 * time.Millisecond

	r, err := ts.start(spec, false)
	require.NoError(t, err)

	waits := observeRestartWaits(t, r, 3, 60*time.Second)

	waitFor(t, 30*time.Second, "the restart budget to be exhausted", func() bool {
		return r.status().GetRestartCount() >= 3 &&
			r.currentState() == sandboxdv1.ProcessState_PROCESS_STATE_CRASHED
	})

	// What the supervisor decided. Deterministic: no clock involved.
	announced := announcedBackoffs(t, r)
	require.Len(t, announced, 3, "one announcement per restart, got %v", announced)
	for i := 1; i < len(announced); i++ {
		require.Greater(t, announced[i], announced[i-1],
			"announced backoff %d (%s) should exceed backoff %d (%s)",
			i+1, announced[i], i, announced[i-1])
	}

	// What it actually waited.
	require.Len(t, waits, 3, "waits: %v", waits)
	for i := 1; i < len(waits); i++ {
		require.Greater(t, waits[i], waits[i-1],
			"wait %d (%s) should exceed wait %d (%s); a hot-looping supervisor has them all equal",
			i+1, waits[i], i, waits[i-1])
	}
}

// observeRestartWaits measures the gap between each run's exit and the next
// run's spawn.
//
// Polling is the only way in: a spawn is not a state a waiter can block on,
// because every restart reaches STARTING alike. exited_at is cleared by the
// spawn that follows it, so the value from the poll before a new started_at
// appeared is the one that belongs to the run that just ended.
func observeRestartWaits(t *testing.T, r *record, want int, timeout time.Duration) []time.Duration {
	t.Helper()

	var (
		waits     []time.Duration
		lastStart time.Time
		lastExit  time.Time
	)
	deadline := time.Now().Add(timeout)
	for len(waits) < want && time.Now().Before(deadline) {
		status := r.status()

		var startedAt time.Time
		if at := status.GetStartedAt(); at != nil {
			startedAt = at.AsTime()
		}
		if !startedAt.IsZero() && !startedAt.Equal(lastStart) {
			if !lastStart.IsZero() && !lastExit.IsZero() {
				waits = append(waits, startedAt.Sub(lastExit))
			}
			lastStart = startedAt
			lastExit = time.Time{}
		}
		if at := status.GetExitedAt(); at != nil {
			if exitedAt := at.AsTime(); !exitedAt.IsZero() {
				lastExit = exitedAt
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	return waits
}

// announcedBackoffs pulls the delays out of the supervisor's own notes, which
// is its decision rather than its timing.
func announcedBackoffs(t *testing.T, r *record) []time.Duration {
	t.Helper()

	var out []time.Duration
	for _, text := range logTexts(r) {
		const prefix = "supervisor: restarting in "
		if !strings.HasPrefix(text, prefix) {
			continue
		}
		field, _, ok := strings.Cut(strings.TrimPrefix(text, prefix), " ")
		if !ok {
			continue
		}
		d, err := time.ParseDuration(field)
		require.NoError(t, err, "could not read a delay out of %q", text)
		out = append(out, d)
	}
	return out
}

func TestBackoffForDoublesAndCaps(t *testing.T) {
	t.Parallel()
	require.Equal(t, time.Second, backoffFor(time.Second, 0, time.Minute))
	require.Equal(t, 2*time.Second, backoffFor(time.Second, 1, time.Minute))
	require.Equal(t, 4*time.Second, backoffFor(time.Second, 2, time.Minute))
	require.Equal(t, time.Minute, backoffFor(time.Second, 20, time.Minute), "the cap is what stops a restart never coming")
	require.Equal(t, time.Second, backoffFor(0, 0, time.Minute), "a zero base falls back to a second")
}

func TestMaxRestartsIsHonouredThenTheSupervisorGivesUp(t *testing.T) {
	t.Parallel()
	// The stability window out of reach: a run that outlasts it resets the
	// budget, and on a loaded runner these runs do. That is the reset working,
	// not the budget failing — it has its own test — but it makes this one
	// watch the supervisor restart a process it had just given up on.
	ts := newTestSupervisor(t, func(c *testSupervisorOptions) { c.stabilityWindow = time.Hour })

	spec := ts.helperSpec("doomed", "exit", "1")
	spec.restartPolicy = sandboxdv1.RestartPolicy_RESTART_POLICY_ALWAYS
	spec.maxRestarts = 2
	spec.restartBackoff = 20 * time.Millisecond
	r, err := ts.start(spec, false)
	require.NoError(t, err)

	waitFor(t, 30*time.Second, "the supervisor to give up", func() bool {
		return r.currentState() == sandboxdv1.ProcessState_PROCESS_STATE_CRASHED &&
			r.status().GetRestartCount() >= 2
	})

	// It stays given up: no further restarts once the budget is spent.
	time.Sleep(400 * time.Millisecond)
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_CRASHED, r.currentState())
	require.EqualValues(t, 2, r.status().GetRestartCount())
	require.Contains(t, strings.Join(logTexts(r), "\n"), "giving up after 2 restarts",
		"the reason has to be recorded where someone will read it")
}

// TestRestartCounterResetsAfterSustainedUptime: a service that crashes once a
// day is not in a crash loop, and charging it a restart it never gets back
// means it eventually stays down for no reason anyone can see.
func TestRestartCounterResetsAfterSustainedUptime(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t, func(c *testSupervisorOptions) { c.stabilityWindow = 150 * time.Millisecond })

	// Each run lasts longer than the stability window, so every exit resets the
	// counter and the budget of two is never exhausted.
	spec := ts.helperSpec("long-lived-crasher", "exit", "1", "250")
	spec.restartPolicy = sandboxdv1.RestartPolicy_RESTART_POLICY_ALWAYS
	spec.maxRestarts = 2
	spec.restartBackoff = 20 * time.Millisecond
	r, err := ts.start(spec, false)
	require.NoError(t, err)

	waitFor(t, 30*time.Second, "the counter to be reset after sustained uptime", func() bool {
		return strings.Contains(strings.Join(logTexts(r), "\n"), "restart counter reset")
	})

	// Well past the point where a supervisor without the reset would have given
	// up, it is still restarting rather than parked in CRASHED.
	time.Sleep(600 * time.Millisecond)
	require.NotContains(t, strings.Join(logTexts(r), "\n"), "giving up",
		"a process that keeps recovering must not exhaust its budget")
	require.LessOrEqual(t, r.status().GetRestartCount(), uint32(1),
		"the counter should have been reset rather than accumulating")
}

// TestDisableRestartStopsAnAlwaysProcessForGood.
func TestDisableRestartStopsAnAlwaysProcessForGood(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)

	start, err := svc.StartProcess(context.Background(), &sandboxdv1.StartProcessRequest{
		Argv:          helperArgv(t, "silent"),
		Name:          "always-restarting",
		Env:           helperEnviron(),
		RestartPolicy: sandboxdv1.RestartPolicy_RESTART_POLICY_ALWAYS,
		MaxRestarts:   5,
	})
	require.NoError(t, err)

	r, ok := svc.sup.lookup(start.GetStatus().GetProcessId())
	require.True(t, ok)

	resp, err := svc.SignalProcess(context.Background(), &sandboxdv1.SignalProcessRequest{
		ProcessId:      r.id,
		GracefulStop:   true,
		GracePeriod:    durationpb.New(500 * time.Millisecond),
		DisableRestart: true,
	})
	require.NoError(t, err)
	require.False(t, isLive(resp.GetStatus().GetState()))

	// It stays stopped. A supervisor that undoes a deliberate stop is worse
	// than one with no restart policy at all.
	time.Sleep(600 * time.Millisecond)
	require.False(t, isLive(r.currentState()), "state was %s", stateName(r.currentState()))
	require.EqualValues(t, 0, r.status().GetRestartCount())
}

// TestRestartKeepsTheProcessIDAndTheLogs.
func TestRestartKeepsTheProcessIDAndTheLogs(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)
	ctx := context.Background()

	start, err := svc.StartProcess(ctx, &sandboxdv1.StartProcessRequest{
		Argv: helperArgv(t, "announce", "0", "stdout", "first-run-marker"),
		Name: "restartable",
		Env:  helperEnviron(),
	})
	require.NoError(t, err)
	id := start.GetStatus().GetProcessId()
	firstPID := start.GetStatus().GetPid()

	r, ok := svc.sup.lookup(id)
	require.True(t, ok)
	waitForLine(t, r, 10*time.Second, "first-run-marker")

	resp, err := svc.RestartProcess(ctx, &sandboxdv1.RestartProcessRequest{
		ProcessId:   id,
		GracePeriod: durationpb.New(500 * time.Millisecond),
	})
	require.NoError(t, err)

	require.Equal(t, id, resp.GetStatus().GetProcessId(), "a restart is the same process, not a new one")
	require.NotEqual(t, firstPID, resp.GetStatus().GetPid(), "but it is a new OS process")
	require.True(t, isLive(resp.GetStatus().GetState()))

	// The log history spans the restart.
	stream := &recordingStream{}
	require.NoError(t, svc.sup.streamLogs(ctx, r, logRequest{sel: selector{tail: 500}}, stream))
	joined := strings.Join(stream.texts(), "\n")
	require.Contains(t, joined, "first-run-marker", "log continuity across a restart")

	// An explicit restart does not spend the automatic-restart budget.
	require.EqualValues(t, 0, resp.GetStatus().GetRestartCount())
}

func TestRestartOfAnExitedProcessStartsItAgain(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)
	ctx := context.Background()

	start, err := svc.StartProcess(ctx, &sandboxdv1.StartProcessRequest{
		Argv: helperArgv(t, "exit", "0"),
		Name: "revivable",
		Env:  helperEnviron(),
	})
	require.NoError(t, err)
	r, ok := svc.sup.lookup(start.GetStatus().GetProcessId())
	require.True(t, ok)
	waitState(t, r, 10*time.Second, sandboxdv1.ProcessState_PROCESS_STATE_EXITED)

	resp, err := svc.RestartProcess(ctx, &sandboxdv1.RestartProcessRequest{ProcessId: r.id})
	require.NoError(t, err)
	require.Equal(t, r.id, resp.GetStatus().GetProcessId())
}

// logTexts is every line currently in a process's ring buffer.
func logTexts(r *record) []string {
	lines := r.buf.ringLines()
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		out = append(out, line.Text)
	}
	return out
}

// TestRestartStandsDownAPendingPolicyRestart.
//
// A process in RESTARTING has already ended its run and has a spawn on a timer.
// An explicit restart arriving in that window has to stand the timer down, not
// race it: the run half is over, so a naive "is it still live?" check either
// refuses the request or starts a second copy beside the one the policy is
// about to start.
func TestRestartStandsDownAPendingPolicyRestart(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t, func(c *testSupervisorOptions) {
		// Long enough that the explicit restart lands squarely inside the
		// backoff rather than after it.
		c.maxRestartBackoff = 3 * time.Second
	})

	marker := filepath.Join(t.TempDir(), "ran-once")
	spec := ts.helperSpec("pending-restart", "once-fail", marker)
	spec.restartPolicy = sandboxdv1.RestartPolicy_RESTART_POLICY_ALWAYS
	spec.maxRestarts = 5
	spec.restartBackoff = 3 * time.Second
	r, err := ts.start(spec, false)
	require.NoError(t, err)

	// The first run fails, so the policy parks the record in RESTARTING with a
	// three-second timer.
	waitState(t, r, 20*time.Second, sandboxdv1.ProcessState_PROCESS_STATE_RESTARTING)

	require.NoError(t, ts.restart(r, 500*time.Millisecond),
		"an explicit restart during a backoff must succeed, not report the process did not stop")
	require.True(t, isLive(r.currentState()), "state was %s", stateName(r.currentState()))
	waitForLine(t, r, 10*time.Second, "second run, staying up")

	pid := int(r.status().GetPid())

	// Past the point where the stood-down timer would have fired: the automatic
	// restart did not also happen, so the process is the one the explicit
	// restart started and the policy's counter was never charged.
	time.Sleep(3500 * time.Millisecond)
	require.Equal(t, pid, int(r.status().GetPid()),
		"the pending policy restart must not have replaced the explicitly started process")
	require.EqualValues(t, 0, r.status().GetRestartCount())
	require.True(t, isLive(r.currentState()))
}

// TestForcedRemoveWaitsForAPendingRestartToStandDown: deleting a record that
// still has a spawn on a timer would leave that process supervised by nobody.
func TestForcedRemoveWaitsForAPendingRestartToStandDown(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	spec := ts.helperSpec("removed-mid-backoff", "exit", "1")
	spec.restartPolicy = sandboxdv1.RestartPolicy_RESTART_POLICY_ALWAYS
	spec.maxRestarts = 5
	spec.restartBackoff = 2 * time.Second
	r, err := ts.start(spec, false)
	require.NoError(t, err)

	waitState(t, r, 20*time.Second, sandboxdv1.ProcessState_PROCESS_STATE_RESTARTING)

	require.NoError(t, ts.remove(r, true, true))
	_, ok := ts.lookup(r.id)
	require.False(t, ok)

	// And nothing starts afterwards: the record is gone and so is its timer.
	time.Sleep(2500 * time.Millisecond)
	require.True(t, isTerminal(r.currentState()), "state was %s", stateName(r.currentState()))
	require.EqualValues(t, 0, ts.liveCount())
}
