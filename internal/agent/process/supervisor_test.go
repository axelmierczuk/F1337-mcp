package process

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	"github.com/axelmierczuk/fleet-mcp/internal/security/jail"
	"github.com/axelmierczuk/fleet-mcp/internal/security/policy"
)

// newTestService wraps a test-timed supervisor in the gRPC surface, so the
// request validation and the defaults are exercised by the same tests that
// exercise the supervisor.
func newTestService(t *testing.T, tweak ...func(*testSupervisorOptions)) *Service {
	t.Helper()
	ts := newTestSupervisor(t, tweak...)
	return &Service{
		deps: agent.Deps{
			Config: &agent.Config{StateDir: ts.dir},
			Jail:   jail.Unconfined(),
			Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
			Status: agent.NewStatus(),
		},
		sup: ts.Supervisor,
	}
}

func TestStartRunsAndSurvivesTheCallReturning(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	r := ts.startHelper("long-running", "sleep")
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_RUNNING, r.currentState())

	pid := r.status().GetPid()
	require.NotZero(t, pid)

	// The call that started it has returned. The process is the supervisor's,
	// not the call's, so it is still there.
	require.True(t, pidAlive(int(pid)), "the process should outlive the call that started it")
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_RUNNING, r.currentState())
}

func TestExitZeroIsExitedAndNonZeroIsCrashed(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	clean := ts.startHelper("clean", "exit", "0")
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_EXITED,
		waitState(t, clean, 10*time.Second,
			sandboxdv1.ProcessState_PROCESS_STATE_EXITED,
			sandboxdv1.ProcessState_PROCESS_STATE_CRASHED))
	require.EqualValues(t, 0, clean.status().GetExitCode())

	failed := ts.startHelper("failed", "exit", "1")
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_CRASHED,
		waitState(t, failed, 10*time.Second,
			sandboxdv1.ProcessState_PROCESS_STATE_EXITED,
			sandboxdv1.ProcessState_PROCESS_STATE_CRASHED))
	require.EqualValues(t, 1, failed.status().GetExitCode())
}

// TestListReflectsTransitions asserts that a list reports the state a process
// is in now, and that the state filter selects on it in both directions.
//
// Every list below is taken while the process is in a state this test put it
// in and nothing else can move it out of: the helper cannot exit until the
// marker file is written, and once it is, the exit is waited for rather than
// assumed. What replaced what: the fixture asked for a 150ms linger and then
// raced it, so "still RUNNING" was true only if the machine got from
// StartProcess to ListProcesses inside 150ms. Under the load of a full
// `go test ./...` it does not — 29 failures in 60 runs of this test under
// eight-way load, and 9 in 9 runs of the whole package — which is #70, and the
// release gate runs `go test -count=1 ./...` in exactly that configuration.
func TestListReflectsTransitions(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)
	ctx := context.Background()

	// Written when this test wants the process gone, and not before. What is
	// in it is the code the helper leaves with, so a helper that never waited
	// for it cannot produce that code — the handshake every assertion below
	// rests on is checked rather than assumed. See markerCode.
	stop := filepath.Join(t.TempDir(), "stop")

	start, err := svc.StartProcess(ctx, &sandboxdv1.StartProcessRequest{
		Argv: helperArgv(t, "exit-when", stop),
		Name: "transitions",
		Env:  helperEnviron(),
	})
	require.NoError(t, err)
	id := start.GetStatus().GetProcessId()

	listed := func(states ...sandboxdv1.ProcessState) []*sandboxdv1.ProcessStatus {
		t.Helper()
		list, err := svc.ListProcesses(ctx, &sandboxdv1.ListProcessesRequest{States: states})
		require.NoError(t, err)
		return list.GetProcesses()
	}

	r, ok := svc.sup.lookup(id)
	require.True(t, ok)

	// The supervisor's own record of the process the list is about to be asked
	// for. Asserted separately so that a failure says which half broke: this
	// one going red means the helper exited on its own and the fixture is
	// wrong, while this one holding and a list below disagreeing with it means
	// the list is.
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_RUNNING, r.currentState(),
		"the helper is waiting on a file this test has not written yet")

	running := listed()
	require.Len(t, running, 1)
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_RUNNING, running[0].GetState())

	// The filter is a filter: it keeps what matches and drops what does not.
	require.Len(t, listed(sandboxdv1.ProcessState_PROCESS_STATE_RUNNING), 1)
	require.Empty(t, listed(sandboxdv1.ProcessState_PROCESS_STATE_EXITED))

	// Now it exits, because this test said so — and with the code this test
	// put in the marker, which is the proof it exited on the marker rather
	// than on its own. A helper that stopped waiting leaves with markerUnread
	// instead, which is CRASHED and never EXITED.
	writeMarker(t, stop, "0")
	waitState(t, r, 10*time.Second, sandboxdv1.ProcessState_PROCESS_STATE_EXITED)

	exited := listed(sandboxdv1.ProcessState_PROCESS_STATE_EXITED)
	require.Len(t, exited, 1, "the exit should be visible in the very next list")
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_EXITED, exited[0].GetState())
	require.EqualValues(t, 0, exited[0].GetExitCode(), "the helper left with the code the marker carried")

	// A state filter that does not match returns nothing, rather than everything.
	require.Empty(t, listed(sandboxdv1.ProcessState_PROCESS_STATE_RUNNING))
}

func TestListFiltersByNamePattern(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)
	ctx := context.Background()

	for _, name := range []string{"web-dev", "web-api", "worker"} {
		_, err := svc.StartProcess(ctx, &sandboxdv1.StartProcessRequest{
			Argv: helperArgv(t, "sleep"),
			Name: name,
			Env:  helperEnviron(),
		})
		require.NoError(t, err)
	}

	list, err := svc.ListProcesses(ctx, &sandboxdv1.ListProcessesRequest{NamePattern: "^web-"})
	require.NoError(t, err)
	require.Len(t, list.GetProcesses(), 2)

	_, err = svc.ListProcesses(ctx, &sandboxdv1.ListProcessesRequest{NamePattern: "([unclosed"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestDuplicateNameNeedsReplaceExisting(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	first := ts.startHelper("dev-server", "sleep")
	firstPID := int(first.status().GetPid())

	_, err := ts.start(ts.helperSpec("dev-server", "sleep"), false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "replace_existing")

	second, err := ts.start(ts.helperSpec("dev-server", "sleep"), true)
	require.NoError(t, err)
	require.NotEqual(t, first.id, second.id)
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_RUNNING, second.currentState())

	// The replaced process is stopped, and stays stopped.
	require.False(t, isLive(first.currentState()), "the replaced process should have been stopped")
	waitFor(t, 5*time.Second, "the replaced process to be gone", func() bool { return !pidAlive(firstPID) })
}

func TestMaxConcurrentIsEnforced(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t, func(c *testSupervisorOptions) { c.maxConcurrent = 2 })

	ts.startHelper("one", "sleep")
	ts.startHelper("two", "sleep")

	_, err := ts.start(ts.helperSpec("three", "sleep"), false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "max_concurrent")
	require.Contains(t, err.Error(), "2")
	require.ErrorIs(t, err, policy.ErrTooManyProcesses)
}

// TestAFullAgentIsResourceExhausted. "Not now" and "not like this" are
// different answers, and the code is how a caller tells them apart: a start
// refused because the agent is full is worth retrying unchanged, and one
// refused because argv is empty never will be.
func TestAFullAgentIsResourceExhausted(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, func(c *testSupervisorOptions) { c.maxConcurrent = 1 })
	ctx := context.Background()

	_, err := svc.StartProcess(ctx, &sandboxdv1.StartProcessRequest{
		Argv: helperArgv(t, "silent"), Name: "the-one", Env: helperEnviron(),
	})
	require.NoError(t, err)

	_, err = svc.StartProcess(ctx, &sandboxdv1.StartProcessRequest{
		Argv: helperArgv(t, "silent"), Name: "one-too-many", Env: helperEnviron(),
	})
	require.Equal(t, codes.ResourceExhausted, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "max_concurrent")
}

func TestMaxConcurrentCountsOnlyLiveProcesses(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t, func(c *testSupervisorOptions) { c.maxConcurrent = 1 })

	done := ts.startHelper("shortlived", "exit", "0")
	waitState(t, done, 10*time.Second, sandboxdv1.ProcessState_PROCESS_STATE_EXITED)

	// The record is still tracked, but it does not occupy a slot.
	_, err := ts.start(ts.helperSpec("next", "sleep"), false)
	require.NoError(t, err)
}

func TestRemoveRefusesARunningProcessWithoutForce(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	r := ts.startHelper("stubborn", "sleep")
	pid := int(r.status().GetPid())

	err := ts.remove(r, false, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "force")
	_, stillTracked := ts.lookup(r.id)
	require.True(t, stillTracked, "a refused remove must not drop the record")

	require.NoError(t, ts.remove(r, true, true))
	_, stillTracked = ts.lookup(r.id)
	require.False(t, stillTracked)
	waitFor(t, 5*time.Second, "the forced-removed process to be gone", func() bool { return !pidAlive(pid) })
}

func TestRemoveKeepsLogsUnlessAsked(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	r := ts.startHelper("logged", "echo", "3", "0", "hello")
	waitState(t, r, 10*time.Second, sandboxdv1.ProcessState_PROCESS_STATE_EXITED)
	waitForLine(t, r, 5*time.Second, "hello 2")

	dir := r.dir
	require.NoError(t, ts.remove(r, false, false))
	require.DirExists(t, dir, "the logs of a reaped process are what explain why it died")
	require.NoFileExists(t, dir+"/"+recordFileName)
}

func TestStartProcessValidatesItsRequest(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		req  *sandboxdv1.StartProcessRequest
	}{
		{"no argv", &sandboxdv1.StartProcessRequest{Name: "x"}},
		{"empty argv[0]", &sandboxdv1.StartProcessRequest{Argv: []string{""}, Name: "x"}},
		{"no name", &sandboxdv1.StartProcessRequest{Argv: []string{"true"}}},
		{"bad probe pattern", &sandboxdv1.StartProcessRequest{
			Argv: []string{"true"}, Name: "x",
			ReadyProbe: &sandboxdv1.ReadyProbe{Probe: &sandboxdv1.ReadyProbe_LogPattern{LogPattern: "([unclosed"}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.StartProcess(ctx, tc.req)
			require.Equal(t, codes.InvalidArgument, status.Code(err), "%v", err)
		})
	}
}

func TestUnknownProcessIDIsNotFound(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)
	ctx := context.Background()

	_, err := svc.SignalProcess(ctx, &sandboxdv1.SignalProcessRequest{
		ProcessId: "nope-12345678",
		Signal:    sandboxdv1.SignalProcessRequest_SIGNAL_TERM,
	})
	require.Equal(t, codes.NotFound, status.Code(err))

	_, err = svc.RemoveProcess(ctx, &sandboxdv1.RemoveProcessRequest{ProcessId: "nope-12345678"})
	require.Equal(t, codes.NotFound, status.Code(err))
}

// TestProcessOutlivesTheCallerDisconnecting is the property the whole design
// exists for: the RPC context is the caller's, and the process is the agent's.
func TestProcessOutlivesTheCallerDisconnecting(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan *sandboxdv1.StartProcessResponse, 1)
	go func() {
		resp, err := svc.StartProcess(ctx, &sandboxdv1.StartProcessRequest{
			Argv:         helperArgv(t, "silent"),
			Name:         "disconnecting-client",
			Env:          helperEnviron(),
			WaitForReady: true,
			// A probe that will never pass, so the call is still waiting when
			// the client goes away.
			ReadyProbe: &sandboxdv1.ReadyProbe{
				Probe: &sandboxdv1.ReadyProbe_LogPattern{LogPattern: "never happens"},
			},
		})
		if err != nil {
			t.Errorf("StartProcess: %v", err)
			close(started)
			return
		}
		started <- resp
	}()

	// Let the process get going, then hang up like an agent CLI restarting.
	waitFor(t, 5*time.Second, "the process to be tracked", func() bool {
		return len(svc.sup.snapshotRecords()) == 1
	})
	r := svc.sup.snapshotRecords()[0]
	waitFor(t, 5*time.Second, "the process to have a pid", func() bool { return r.status().GetPid() != 0 })
	pid := int(r.status().GetPid())
	cancel()

	resp := <-started
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.GetReadyError(), "a caller that stopped waiting should be told so")

	require.True(t, pidAlive(pid), "cancelling the RPC context must not touch the process")
	require.True(t, isLive(r.currentState()), "the record should still be live, got %s", stateName(r.currentState()))
}

// TestManyShortLivedStartsLeaveNothingBehind is the portable half of the
// zombie assertion: every one of a hundred children is waited on, so every one
// reaches a terminal state and the supervisor's live count returns to zero.
// The Linux half reads the process table directly; see zombie_linux_test.go.
func TestManyShortLivedStartsLeaveNothingBehind(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a hundred processes")
	}
	t.Parallel()
	ts := newTestSupervisor(t, func(c *testSupervisorOptions) { c.maxConcurrent = 200 })

	const runs = 100
	require.Len(t, startShortLived(t, ts, "short", runs), runs)
	// The count Health reports is derived from the states and refreshed just
	// after each transition, so it settles a moment behind the last one.
	waitFor(t, 10*time.Second, "the supervised process count to fall to zero",
		func() bool { return ts.liveCount() == 0 })
}

// TestConcurrentStartListRemove is the race-detector test. The assertions are
// weak on purpose — what is under test is that nothing races, and -race is the
// assertion.
func TestConcurrentStartListRemove(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, func(c *testSupervisorOptions) { c.maxConcurrent = 64 })
	ctx := context.Background()

	var starters, lister, remover sync.WaitGroup
	ids := make(chan string, 64)

	// Four starters, not eight: what is under test is that concurrent calls do
	// not race, and -race is the assertion. Sixteen live helpers make that point
	// as well as thirty-two do, without starving a CI runner shared with every
	// other package's tests.
	for i := range 4 {
		starters.Add(1)
		go func() {
			defer starters.Done()
			for j := range 4 {
				resp, err := svc.StartProcess(ctx, &sandboxdv1.StartProcessRequest{
					Argv: helperArgv(t, "exit", "0", "20"),
					Name: fmt.Sprintf("racer-%d-%d", i, j),
					Env:  helperEnviron(),
				})
				if err != nil {
					continue
				}
				ids <- resp.GetStatus().GetProcessId()
			}
		}()
	}

	stop := make(chan struct{})
	lister.Add(1)
	go func() {
		defer lister.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = svc.ListProcesses(ctx, &sandboxdv1.ListProcessesRequest{})
		}
	}()

	remover.Add(1)
	go func() {
		defer remover.Done()
		for id := range ids {
			_, _ = svc.RemoveProcess(ctx, &sandboxdv1.RemoveProcessRequest{
				ProcessId: id, Force: true, DeleteLogs: true,
			})
		}
	}()

	starters.Wait()
	close(ids)
	remover.Wait()
	close(stop)
	lister.Wait()
}

// TestConcurrentStartsOfOneNameAdmitExactlyOne.
//
// The name check and the record's registration are a read-modify-write, and
// dropping the lock between them lets every caller read "the name is free"
// before any of them has taken it. The result is two dev servers under one
// name fighting over a port, and neither the caller nor a later
// replace_existing can tell which is which — the second start has already
// happened by the time anyone could notice.
func TestConcurrentStartsOfOneNameAdmitExactlyOne(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	const racers = 8
	var wg sync.WaitGroup
	results := make(chan error, racers)
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := ts.start(ts.helperSpec("one-name-only", "silent"), false)
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	admitted := 0
	for err := range results {
		if err == nil {
			admitted++
		}
	}
	require.Equal(t, 1, admitted, "exactly one of %d concurrent starts may take the name", racers)

	live := 0
	for _, r := range ts.snapshotRecords() {
		if isLive(r.currentState()) {
			live++
		}
	}
	require.Equal(t, 1, live, "and only one process may be left running under it")
}

// TestConcurrentStartsRespectMaxConcurrent is the same read-modify-write, seen
// through the cap rather than the name. An agent that runs more processes than
// its operator allowed has no way to get back under the limit afterwards.
func TestConcurrentStartsRespectMaxConcurrent(t *testing.T) {
	t.Parallel()
	const limit = 3
	ts := newTestSupervisor(t, func(c *testSupervisorOptions) { c.maxConcurrent = limit })

	const racers = 12
	var wg sync.WaitGroup
	results := make(chan error, racers)
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := ts.start(ts.helperSpec(fmt.Sprintf("capped-%d", i), "silent"), false)
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	admitted := 0
	for err := range results {
		if err == nil {
			admitted++
		}
	}
	require.Equal(t, limit, admitted, "%d concurrent starts against a cap of %d", racers, limit)

	live := 0
	for _, r := range ts.snapshotRecords() {
		if isLive(r.currentState()) {
			live++
		}
	}
	require.LessOrEqual(t, live, limit, "the agent must never supervise more than max_concurrent processes")
}

// newSupervisorWithPolicy builds a supervisor that shares a limiter with
// whatever else the test wants to hold slots in it.
func newSupervisorWithPolicy(t *testing.T, pol *policy.Policy, tweak ...func(*supervisorConfig)) *Supervisor {
	t.Helper()
	cfg := testConfig(t.TempDir())
	for _, fn := range tweak {
		fn(&cfg)
	}
	sup, err := newSupervisor(cfg, pol, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	t.Cleanup(func() {
		for _, r := range sup.snapshotRecords() {
			if isLive(r.currentState()) {
				_ = sup.stopRecord(r, 200*time.Millisecond)
			}
		}
		_ = sup.Close()
	})
	return sup
}

// TestTheConcurrencyLimitIsTheAgentsNotTheSupervisors.
//
// process.max_concurrent bounds how many processes this agent runs, not how
// many each service runs. A supervisor counting its own live records enforces
// the number a second time rather than sharing it, and an agent configured for
// 32 then runs 32 supervised processes beside 32 exec commands — 64 against a
// limit of 32, with neither service wrong about its own number, which is why
// the mistake survives review.
func TestTheConcurrencyLimitIsTheAgentsNotTheSupervisors(t *testing.T) {
	t.Parallel()

	pol := testPolicy(t, 2)
	// Another service on this agent — ExecService, in the shape it arrives in
	// with #40 — is holding one of the two slots.
	elsewhere, err := pol.Acquire(context.Background())
	require.NoError(t, err)

	sup := newSupervisorWithPolicy(t, pol)
	specOf := func(name string) startSpec {
		return startSpec{
			argv: helperArgv(t, "silent"), name: name, env: helperEnviron(),
			restartPolicy: sandboxdv1.RestartPolicy_RESTART_POLICY_NEVER,
			maxLogBytes:   1 << 18,
		}
	}

	_, err = sup.start(specOf("fits"), false)
	require.NoError(t, err, "one slot is free, so one supervised process fits")

	_, err = sup.start(specOf("does-not-fit"), false)
	require.Error(t, err, "the agent is full, even though the supervisor itself is running only one")
	require.Contains(t, err.Error(), "max_concurrent")

	// And when the other service is done, the room reappears.
	elsewhere()
	_, err = sup.start(specOf("fits-now"), false)
	require.NoError(t, err)
}

// TestAProcessGivesItsSlotBackOnEveryWayItStops. A slot held by a record that
// is no longer running is a slot the agent has lost for good, and the limit
// walks down to zero over the life of the daemon.
func TestAProcessGivesItsSlotBackOnEveryWayItStops(t *testing.T) {
	t.Parallel()

	pol := testPolicy(t, 4)
	sup := newSupervisorWithPolicy(t, pol)
	specOf := func(name, mode string, args ...string) startSpec {
		return startSpec{
			argv: helperArgv(t, mode, args...), name: name, env: helperEnviron(),
			restartPolicy: sandboxdv1.RestartPolicy_RESTART_POLICY_NEVER,
			maxLogBytes:   1 << 18,
		}
	}
	idle := func(what string) {
		waitFor(t, 10*time.Second, what, func() bool { return pol.InUse() == 0 })
	}

	// It exited on its own.
	exiting, err := sup.start(specOf("exits", "exit", "0"), false)
	require.NoError(t, err)
	waitState(t, exiting, 20*time.Second, sandboxdv1.ProcessState_PROCESS_STATE_EXITED)
	idle("an exited process to give its slot back")

	// It was removed.
	removed, err := sup.start(specOf("removed", "silent"), false)
	require.NoError(t, err)
	require.Equal(t, 1, pol.InUse())
	require.NoError(t, sup.remove(removed, true, true))
	idle("a removed process to give its slot back")

	// It was replaced, and the replacement took the slot rather than a second one.
	_, err = sup.start(specOf("replaced", "silent"), false)
	require.NoError(t, err)
	_, err = sup.start(specOf("replaced", "silent"), true)
	require.NoError(t, err)
	waitFor(t, 10*time.Second, "the replacement to hold exactly one slot",
		func() bool { return pol.InUse() == 1 })

	// The daemon stopped. The process keeps running — that is the contract —
	// but the slot belongs to the daemon that was counting it, and the next
	// agent takes one for it again when it re-adopts it.
	require.NoError(t, sup.Close())
	require.Zero(t, pol.InUse(), "Close must not leave the agent's limit spent")
}

// TestARestartTakesASlotAgain: a run that has ended holds no slot, so the run
// that replaces it has to take one. Nothing else keeps the limit honest across
// a service that restarts all day.
func TestARestartTakesASlotAgain(t *testing.T) {
	t.Parallel()

	pol := testPolicy(t, 4)
	// The stability window out of reach: a run that outlasts it resets the
	// budget, and this waits for the budget to run out.
	sup := newSupervisorWithPolicy(t, pol, func(c *supervisorConfig) { c.stabilityWindow = time.Hour })

	r, err := sup.start(startSpec{
		argv: helperArgv(t, "exit", "1", "20"), name: "restarts", env: helperEnviron(),
		restartPolicy:  sandboxdv1.RestartPolicy_RESTART_POLICY_ALWAYS,
		maxRestarts:    3,
		restartBackoff: 20 * time.Millisecond,
		maxLogBytes:    1 << 18,
	}, false)
	require.NoError(t, err)

	waitFor(t, 30*time.Second, "the restart budget to be exhausted", func() bool {
		return r.currentState() == sandboxdv1.ProcessState_PROCESS_STATE_CRASHED &&
			r.status().GetRestartCount() >= 3
	})
	// Three restarts, each of which took a slot and gave it back. A slot taken
	// per restart and never returned would have spent the whole limit by now.
	waitFor(t, 10*time.Second, "the last run's slot to come back",
		func() bool { return pol.InUse() == 0 })
}

// TestReadoptionTakesASlotInTheAgentLimit. A process that survived the last
// agent is running on this host now. An agent that rebuilds its limit as empty
// on every restart has a limit that means less every time it is upgraded.
func TestReadoptionTakesASlotInTheAgentLimit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	first := newRawSupervisor(t, dir)
	r, err := first.start(startSpec{
		argv: helperArgv(t, "silent"), name: "survives-upgrade", env: helperEnviron(),
		restartPolicy: sandboxdv1.RestartPolicy_RESTART_POLICY_NEVER,
		maxLogBytes:   1 << 18,
	}, false)
	require.NoError(t, err)
	pid := int(r.status().GetPid())
	t.Cleanup(func() { killPID(t, pid) })
	require.NoError(t, first.Close())

	pol := testPolicy(t, 1)
	second, err := newSupervisor(testConfig(dir), pol, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = second.Close() })

	adopted, ok := second.lookup(r.id)
	require.True(t, ok)
	require.True(t, isLive(adopted.currentState()), "state was %s", stateName(adopted.currentState()))
	require.Equal(t, 1, pol.InUse(), "a re-adopted process occupies a slot in the new agent's limit")

	_, err = second.start(startSpec{
		argv: helperArgv(t, "silent"), name: "one-too-many", env: helperEnviron(),
		restartPolicy: sandboxdv1.RestartPolicy_RESTART_POLICY_NEVER,
		maxLogBytes:   1 << 18,
	}, false)
	require.Error(t, err, "the agent is full of processes it inherited")
	require.Contains(t, err.Error(), "max_concurrent")
}

// TestStartingAProcessIsRefusedWhenExecIsDisabled.
//
// exec.enabled: false is the only configuration in which allowed_roots is a
// boundary rather than a decoration, and it is that only because an agent that
// runs commands does not need FileService to reach a path. Starting a
// supervised process runs a command.
func TestStartingAProcessIsRefusedWhenExecIsDisabled(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)
	ctx := context.Background()

	disabled := false
	svc.deps.Config.Exec.Enabled = &disabled
	require.True(t, svc.deps.Config.JailEnforced(), "this is the configuration where the jail is real")

	_, err := svc.StartProcess(ctx, &sandboxdv1.StartProcessRequest{
		Argv: helperArgv(t, "silent"),
		Name: "walks-past-the-jail",
		Env:  helperEnviron(),
	})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "exec.enabled")
	require.Empty(t, svc.sup.snapshotRecords(), "and nothing was spawned")

	// A restart is the same capability: it re-runs the same argv, and a record
	// can outlive the config change that disabled exec.
	_, err = svc.RestartProcess(ctx, &sandboxdv1.RestartProcessRequest{ProcessId: "anything-0001"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "exec.enabled")

	// And with exec on — the default, and what every other test here runs —
	// the same call works.
	enabled := true
	svc.deps.Config.Exec.Enabled = &enabled
	_, err = svc.StartProcess(ctx, &sandboxdv1.StartProcessRequest{
		Argv: helperArgv(t, "silent"),
		Name: "allowed",
		Env:  helperEnviron(),
	})
	require.NoError(t, err)
}

func TestSanitizeNameProducesUsablePathComponents(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]string{
		"web-dev":       "web-dev",
		"Web Dev":       "web-dev",
		"../../etc":     "etc",
		"":              "process",
		"///":           "process",
		"UPPER_case-99": "upper_case-99",
	} {
		assert.Equal(t, want, sanitizeName(input), "sanitizeName(%q)", input)
	}
	// However mangled the label, the id it produces is a single path component.
	for _, input := range []string{"../../etc", "a/b", `c\d`, ".."} {
		id := (&Supervisor{}).newProcessID(input)
		_, err := logDirName(id)
		require.NoError(t, err, "process id %q from name %q", id, input)
		require.False(t, strings.ContainsAny(id, `/\`), "process id %q", id)
	}
}

func TestStateMachineRefusesIllegalTransitions(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)
	r := ts.startHelper("machine", "sleep")

	// RUNNING cannot go back to STARTING without passing through RESTARTING.
	err := r.setState(sandboxdv1.ProcessState_PROCESS_STATE_STARTING, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "illegal state transition")
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_RUNNING, r.currentState())

	// ORPHANED is terminal.
	r.restoreState(sandboxdv1.ProcessState_PROCESS_STATE_ORPHANED)
	require.Error(t, r.setState(sandboxdv1.ProcessState_PROCESS_STATE_RUNNING, nil))
	require.Error(t, r.setState(sandboxdv1.ProcessState_PROCESS_STATE_EXITED, nil))
}

func TestSupervisorCloseLeavesProcessesRunning(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sup, err := newSupervisor(testConfig(dir), testPolicy(t, 16), slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	r, err := sup.start(startSpec{
		argv:          helperArgv(t, "sleep"),
		name:          "survivor",
		env:           helperEnviron(),
		restartPolicy: sandboxdv1.RestartPolicy_RESTART_POLICY_NEVER,
		maxLogBytes:   1 << 18,
	}, false)
	require.NoError(t, err)
	pid := int(r.status().GetPid())
	t.Cleanup(func() { killPID(t, pid) })

	require.NoError(t, sup.Close())

	// The supervisor is gone. The process is not — that is the contract the
	// daemon's shutdown path depends on.
	require.True(t, pidAlive(pid), "Close must not signal a supervised process")
}

// testConfig is newTestSupervisor's configuration, for the tests that build a
// supervisor by hand because they need to close and reopen one.
func testConfig(dir string) supervisorConfig {
	return supervisorConfig{
		stateDir:              dir,
		maxLogBytes:           256 * 1024,
		ringBufferLines:       200,
		defaultGracePeriod:    300 * time.Millisecond,
		maxFollowDuration:     2 * time.Second,
		retainSegments:        3,
		rawCapBytes:           1 << 20,
		stabilityWindow:       500 * time.Millisecond,
		defaultMaxRestarts:    3,
		defaultRestartBackoff: 20 * time.Millisecond,
		maxRestartBackoff:     200 * time.Millisecond,
		tailPollMin:           2 * time.Millisecond,
		tailPollMax:           20 * time.Millisecond,
		drainWindow:           200 * time.Millisecond,
		captureOffsetInterval: 100 * time.Millisecond,
		probeTimeout:          2 * time.Second,
		probeInterval:         20 * time.Millisecond,
		httpProbeTimeout:      500 * time.Millisecond,
		dialTimeout:           500 * time.Millisecond,
		defaultTailLines:      200,
	}
}
