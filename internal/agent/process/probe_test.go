package process

import (
	"context"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

// startProbed starts a helper with a readiness probe and waits for the probe to
// conclude, returning whatever it concluded.
func (ts *testSupervisor) startProbed(name string, probe *probeSpec, mode string, args ...string) (*record, error) {
	ts.t.Helper()
	spec := ts.helperSpec(name, mode, args...)
	spec.probe = probe
	r, err := ts.start(spec, false)
	require.NoError(ts.t, err)
	return r, ts.waitForReady(context.Background(), r)
}

func testProbe(kind probeKind, timeout time.Duration) *probeSpec {
	return &probeSpec{kind: kind, timeout: timeout, interval: 20 * time.Millisecond}
}

func TestLogPatternProbeMatchesStdout(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	probe := testProbe(probeLogPattern, 5*time.Second)
	probe.patternSrc = `listening on \d+`
	probe.pattern = mustCompile(t, probe.patternSrc)

	r, err := ts.startProbed("stdout-ready", probe, "announce", "100", "stdout", "listening on 3000")
	require.NoError(t, err)
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_READY, r.currentState())
}

// TestLogPatternProbeMatchesStderr is the case that catches a probe wired to
// stdout only. Plenty of frameworks announce readiness on stderr.
func TestLogPatternProbeMatchesStderr(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	probe := testProbe(probeLogPattern, 5*time.Second)
	probe.patternSrc = `server started`
	probe.pattern = mustCompile(t, probe.patternSrc)

	r, err := ts.startProbed("stderr-ready", probe, "announce", "100", "stderr", "server started on :8080")
	require.NoError(t, err)
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_READY, r.currentState())
}

// TestLogPatternProbeDoesNotConsumeTheLog is the subtle one. The matcher reads
// the same stream a reader does; if it drained it, the line it matched on would
// be missing afterwards.
func TestLogPatternProbeDoesNotConsumeTheLog(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	probe := testProbe(probeLogPattern, 5*time.Second)
	probe.patternSrc = `ready`
	probe.pattern = mustCompile(t, probe.patternSrc)

	r, err := ts.startProbed("not-consumed", probe, "announce", "50", "stdout", "ready to serve")
	require.NoError(t, err)

	stream := &recordingStream{}
	require.NoError(t, ts.streamLogs(context.Background(), r, logRequest{sel: selector{tail: 100}}, stream))
	require.Contains(t, stream.texts(), "ready to serve",
		"the line the probe matched on must still be readable")
}

func TestTCPProbeWaitsForSomethingToListen(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	port := freePort(t)
	probe := testProbe(probeTCPPort, 5*time.Second)
	probe.port = uint32(port) //nolint:gosec // a port is in range by construction

	// Nothing is listening yet, and the probe must not report ready.
	require.False(t, dialLoopback(context.Background(), probe.port, 200*time.Millisecond),
		"nothing is listening on the port yet")

	r, err := ts.startProbed("tcp-ready", probe, "listen", "150", strconv.Itoa(port))
	require.NoError(t, err)
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_READY, r.currentState())
	require.True(t, dialLoopback(context.Background(), probe.port, time.Second))
}

// TestHTTPProbeTreats404AsReadyAnd500AsNot is the rule that looks backwards for
// a second: the question is whether the server is up, and a 404 is a server
// answering.
func TestHTTPProbeTreats404AsReadyAnd500AsNot(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		status    int
		wantReady bool
	}{
		{200, true},
		{404, true},
		{500, false},
	} {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			t.Parallel()
			ts := newTestSupervisor(t)

			port := freePort(t)
			probe := testProbe(probeHTTPGet, 1500*time.Millisecond)
			probe.url = "http://127.0.0.1:" + strconv.Itoa(port) + "/"

			r, err := ts.startProbed("http-"+strconv.Itoa(tc.status), probe,
				"http", strconv.Itoa(port), strconv.Itoa(tc.status))

			if tc.wantReady {
				require.NoError(t, err)
				require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_READY, r.currentState())
				return
			}
			require.Error(t, err)
			require.IsType(t, &probeTimeoutError{}, err, "a 500 is not ready, it is a timeout")
			require.True(t, isLive(r.currentState()), "a probe that did not pass must leave the process running")
		})
	}
}

// TestHTTPProbeHasItsOwnTimeout: a probe that hangs on connect must not turn a
// bounded readiness budget into an unbounded one. The address here is one that
// swallows the SYN, so a client without its own timeout waits out the OS.
func TestHTTPProbeHasItsOwnTimeout(t *testing.T) {
	t.Parallel()

	start := time.Now()
	// 192.0.2.0/24 is TEST-NET-1: routable nowhere, so the connect hangs.
	ready := httpReady(context.Background(), "http://192.0.2.1:8080/", 300*time.Millisecond)
	elapsed := time.Since(start)

	require.False(t, ready)
	require.Less(t, elapsed, 5*time.Second, "the probe's own timeout must bound the connect")
}

func TestUptimeProbeIsTheFallbackForSilentProcesses(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	probe := testProbe(probeUptime, 3*time.Second)
	probe.uptime = 200 * time.Millisecond

	started := time.Now()
	r, err := ts.startProbed("uptime-ready", probe, "silent")
	require.NoError(t, err)
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_READY, r.currentState())
	require.GreaterOrEqual(t, time.Since(started), probe.uptime,
		"an uptime probe cannot pass before the uptime has elapsed")
}

// TestProbeTimeoutLeavesTheProcessRunning is the rule that matters most in #12.
// A slow start is not a failed start, and killing it throws away the logs that
// are the only way to diagnose it.
func TestProbeTimeoutLeavesTheProcessRunning(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	probe := testProbe(probeLogPattern, 300*time.Millisecond)
	probe.patternSrc = `this never appears`
	probe.pattern = mustCompile(t, probe.patternSrc)

	// The trailing argument keeps the helper alive after its three lines: the
	// point of the test is a process that is still running when the probe gives
	// up, and one that exits first takes the other branch.
	r, err := ts.startProbed("slow-start", probe, "echo", "3", "10", "still working", "600000")
	require.Error(t, err)
	require.IsType(t, &probeTimeoutError{}, err)
	require.Contains(t, err.Error(), "still running")

	require.True(t, isLive(r.currentState()), "state was %s", stateName(r.currentState()))
	require.True(t, pidAlive(int(r.status().GetPid())), "the process must survive its probe timing out")

	// And its logs are intact, which is the reason it was left alive.
	waitForLine(t, r, 5*time.Second, "still working 2")
}

// TestProbeFailsFastWhenTheProcessExits: the error has to say the process
// exited. "Timed out after 30s" sends the reader looking for a slow start.
func TestProbeFailsFastWhenTheProcessExits(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	probe := testProbe(probeLogPattern, 30*time.Second)
	probe.patternSrc = `never`
	probe.pattern = mustCompile(t, probe.patternSrc)

	started := time.Now()
	r, err := ts.startProbed("dies-early", probe, "exit", "3", "50")
	elapsed := time.Since(started)

	require.Error(t, err)
	require.IsType(t, &probeExitError{}, err)
	require.Contains(t, err.Error(), "exited")
	require.Contains(t, err.Error(), "code 3")
	require.NotContains(t, err.Error(), "did not pass within")
	require.Less(t, elapsed, 25*time.Second, "the probe must not wait out its timeout for a process that is already gone")
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_CRASHED, r.currentState())
}

// TestWaitForReadyFalseReturnsImmediately: the probe still runs, the call just
// does not block on it.
func TestWaitForReadyFalseReturnsImmediately(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)

	resp, err := svc.StartProcess(context.Background(), &sandboxdv1.StartProcessRequest{
		Argv: helperArgv(t, "announce", "200", "stdout", "up and running"),
		Name: "no-wait",
		Env:  helperEnviron(),
		ReadyProbe: &sandboxdv1.ReadyProbe{
			Probe:    &sandboxdv1.ReadyProbe_LogPattern{LogPattern: "up and running"},
			Timeout:  durationpb.New(5 * time.Second),
			Interval: durationpb.New(20 * time.Millisecond),
		},
		WaitForReady: false,
	})
	require.NoError(t, err)
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_STARTING, resp.GetStatus().GetState())
	require.Empty(t, resp.GetReadyError())

	// The probe was not abandoned; it was just not waited for.
	r, ok := svc.sup.lookup(resp.GetStatus().GetProcessId())
	require.True(t, ok)
	waitState(t, r, 10*time.Second, sandboxdv1.ProcessState_PROCESS_STATE_READY)
}

func TestWaitForReadySurfacesTheErrorWithoutFailingTheCall(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)

	resp, err := svc.StartProcess(context.Background(), &sandboxdv1.StartProcessRequest{
		Argv: helperArgv(t, "silent"),
		Name: "never-ready",
		Env:  helperEnviron(),
		ReadyProbe: &sandboxdv1.ReadyProbe{
			Probe:    &sandboxdv1.ReadyProbe_LogPattern{LogPattern: "never"},
			Timeout:  durationpb.New(200 * time.Millisecond),
			Interval: durationpb.New(20 * time.Millisecond),
		},
		WaitForReady: true,
	})
	// Not an RPC error: the process runs, and stopping it is the caller's call.
	require.NoError(t, err)
	require.NotEmpty(t, resp.GetReadyError())
	require.Contains(t, resp.GetReadyError(), "did not pass within")
	require.True(t, pidAlive(int(resp.GetStatus().GetPid())))
}

func TestProbeDefaultsFromProto(t *testing.T) {
	t.Parallel()

	spec, err := probeFromProto(&sandboxdv1.ReadyProbe{
		Probe: &sandboxdv1.ReadyProbe_TcpPort{TcpPort: 3000},
	}, 30*time.Second, 250*time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, probeTCPPort, spec.kind)
	require.Equal(t, 30*time.Second, spec.timeout)
	require.Equal(t, 250*time.Millisecond, spec.interval)

	// An uptime probe longer than the default timeout stretches the timeout
	// rather than making a probe that cannot pass.
	spec, err = probeFromProto(&sandboxdv1.ReadyProbe{
		Probe: &sandboxdv1.ReadyProbe_Uptime{Uptime: durationpb.New(60 * time.Second)},
	}, 30*time.Second, 250*time.Millisecond)
	require.NoError(t, err)
	require.Greater(t, spec.timeout, spec.uptime)

	// No probe at all is not an error; it is the "spawned means running" path.
	spec, err = probeFromProto(nil, time.Second, time.Second)
	require.NoError(t, err)
	require.Nil(t, spec)

	for _, bad := range []*sandboxdv1.ReadyProbe{
		{Probe: &sandboxdv1.ReadyProbe_LogPattern{LogPattern: "([unclosed"}},
		{Probe: &sandboxdv1.ReadyProbe_TcpPort{TcpPort: 0}},
		{Probe: &sandboxdv1.ReadyProbe_TcpPort{TcpPort: 70000}},
		{Probe: &sandboxdv1.ReadyProbe_HttpGetUrl{HttpGetUrl: ""}},
		{Probe: &sandboxdv1.ReadyProbe_Uptime{Uptime: durationpb.New(0)}},
	} {
		_, err := probeFromProto(bad, time.Second, time.Second)
		require.Error(t, err, "%v", bad)
	}
}

func TestProbeRoundTripsThroughTheRecord(t *testing.T) {
	t.Parallel()

	for _, spec := range []*probeSpec{
		{kind: probeLogPattern, patternSrc: `ready`, pattern: mustCompile(t, "ready"), timeout: time.Second, interval: time.Millisecond},
		{kind: probeTCPPort, port: 3000, timeout: time.Second, interval: time.Millisecond},
		{kind: probeHTTPGet, url: "http://127.0.0.1:1/", timeout: time.Second, interval: time.Millisecond},
		{kind: probeUptime, uptime: time.Second, timeout: 2 * time.Second, interval: time.Millisecond},
	} {
		back := probeFromPersisted(spec.persisted())
		require.NotNil(t, back)
		require.Equal(t, spec.kind, back.kind)
		require.Equal(t, spec.describe(), back.describe())
	}

	require.Nil(t, (*probeSpec)(nil).persisted())
	require.Nil(t, probeFromPersisted(nil))
	require.Nil(t, probeFromPersisted(&persistedProbe{Kind: "something-else"}))
}

func mustCompile(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	re, err := regexp.Compile(pattern)
	require.NoError(t, err)
	return re
}
