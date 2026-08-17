package process

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/agent"
	"github.com/axelmierczuk/sandboxd-mcp/internal/security/jail"
)

// newTestService wraps a test-timed supervisor in the gRPC surface, so the
// request validation and the defaults are exercised by the same tests that
// exercise the supervisor.
func newTestService(t *testing.T, tweak ...func(*supervisorConfig)) *Service {
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

func TestListReflectsTransitions(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)
	ctx := context.Background()

	start, err := svc.StartProcess(ctx, &sandboxdv1.StartProcessRequest{
		Argv: helperArgv(t, "exit", "0", "150"),
		Name: "transitions",
		Env:  helperEnviron(),
	})
	require.NoError(t, err)
	id := start.GetStatus().GetProcessId()

	list, err := svc.ListProcesses(ctx, &sandboxdv1.ListProcessesRequest{})
	require.NoError(t, err)
	require.Len(t, list.GetProcesses(), 1)
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_RUNNING, list.GetProcesses()[0].GetState())

	r, ok := svc.sup.lookup(id)
	require.True(t, ok)
	waitState(t, r, 10*time.Second, sandboxdv1.ProcessState_PROCESS_STATE_EXITED)

	list, err = svc.ListProcesses(ctx, &sandboxdv1.ListProcessesRequest{
		States: []sandboxdv1.ProcessState{sandboxdv1.ProcessState_PROCESS_STATE_EXITED},
	})
	require.NoError(t, err)
	require.Len(t, list.GetProcesses(), 1, "the exit should be visible in the very next list")

	// A state filter that does not match returns nothing, rather than everything.
	list, err = svc.ListProcesses(ctx, &sandboxdv1.ListProcessesRequest{
		States: []sandboxdv1.ProcessState{sandboxdv1.ProcessState_PROCESS_STATE_RUNNING},
	})
	require.NoError(t, err)
	require.Empty(t, list.GetProcesses())
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
	ts := newTestSupervisor(t, func(c *supervisorConfig) { c.maxConcurrent = 2 })

	ts.startHelper("one", "sleep")
	ts.startHelper("two", "sleep")

	_, err := ts.start(ts.helperSpec("three", "sleep"), false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "max_concurrent")
	require.Contains(t, err.Error(), "2")
}

func TestMaxConcurrentCountsOnlyLiveProcesses(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t, func(c *supervisorConfig) { c.maxConcurrent = 1 })

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
	ts := newTestSupervisor(t, func(c *supervisorConfig) { c.maxConcurrent = 200 })

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
	svc := newTestService(t, func(c *supervisorConfig) { c.maxConcurrent = 64 })
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
	sup, err := newSupervisor(testConfig(dir), slog.New(slog.NewTextHandler(io.Discard, nil)))
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
		maxConcurrent:         16,
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
		probeTimeout:          2 * time.Second,
		probeInterval:         20 * time.Millisecond,
		httpProbeTimeout:      500 * time.Millisecond,
		dialTimeout:           500 * time.Millisecond,
		defaultTailLines:      200,
	}
}
