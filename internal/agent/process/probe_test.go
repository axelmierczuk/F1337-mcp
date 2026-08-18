package process

import (
	"context"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
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

// TestLogPatternProbeIgnoresTheRunBeforeThisOne is #57 at the seam it happens.
//
// A restart keeps the process's log buffer — that is what makes the output of
// the run that died readable afterwards — so the pre-scan is looking at the
// previous run's lines as well as this run's. It must credit only this run's.
//
// Nothing here waits on a duration. The helper announces once per marker file,
// so the second run cannot print the pattern however long anyone watches, and
// the probe's own verdict is the recorded fact the assertions are on.
func TestLogPatternProbeIgnoresTheRunBeforeThisOne(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	probe := testProbe(probeLogPattern, 300*time.Millisecond)
	probe.patternSrc = `listening on \d+`
	probe.pattern = mustCompile(t, probe.patternSrc)

	marker := filepath.Join(t.TempDir(), "announced")
	r, err := ts.startProbed("announces-once", probe, "announce-once", marker, "listening on 3000")
	require.NoError(t, err, "the first run announces itself and is ready")
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_READY, r.currentState())

	require.NoError(t, ts.restart(r, time.Second))
	err = ts.waitForReady(context.Background(), r)

	require.Error(t, err, "the restarted run never printed the pattern, so its probe cannot have passed")
	require.IsType(t, &probeTimeoutError{}, err)
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_STARTING, r.currentState(),
		"a process whose probe has not passed is STARTING, not READY")

	// The restarted run is alive and talking; it is only the announcement it
	// does not repeat. Without this the test would also pass against a probe
	// that had somehow lost the process.
	waitForLine(t, r, 10*time.Second, "restarted without announcing")
	require.Equal(t, 1, countLines(r, "listening on 3000"),
		"the helper announces once per marker file; more than one would mean the scenario, not the product, is wrong")
}

// TestARestartedProcessIsReadyOnItsOwnOutput is the other half. Bounding the
// pre-scan must not cost a restart its readiness: a process that announces
// itself on every run is ready again on every run.
func TestARestartedProcessIsReadyOnItsOwnOutput(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	probe := testProbe(probeLogPattern, 10*time.Second)
	probe.patternSrc = `listening on \d+`
	probe.pattern = mustCompile(t, probe.patternSrc)

	r, err := ts.startProbed("announces-always", probe, "announce", "50", "stdout", "listening on 3000")
	require.NoError(t, err)
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_READY, r.currentState())

	require.NoError(t, ts.restart(r, time.Second))
	require.NoError(t, ts.waitForReady(context.Background(), r))
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_READY, r.currentState())

	// And it is the second run's own announcement it passed on, not the first's:
	// there are two of them in the log by the time it is ready again.
	require.Equal(t, 2, countLines(r, "listening on 3000"))
}

// TestTheProbePreScanIsBoundedAtTheMarkAndNotBefore pins the boundary itself,
// without a process in the way.
//
// The two halves are one line apart: the same text, matched or ignored
// according to which side of the mark it was appended on. A pre-scan that
// ignored everything — the shape a fix that simply deleted it would have — is
// as red here as one that ignored nothing.
func TestTheProbePreScanIsBoundedAtTheMarkAndNotBefore(t *testing.T) {
	t.Parallel()

	probe := testProbe(probeLogPattern, 200*time.Millisecond)
	probe.patternSrc = `listening on \d+`
	probe.pattern = mustCompile(t, probe.patternSrc)

	buf := newLogBuffer(50, nil)
	buf.append(sandboxdv1.Stream_STREAM_STDOUT, "listening on 3000", time.Now(), false)
	mark := buf.nextSequence()
	r := &record{buf: buf, changed: make(chan struct{})}

	err := probe.run(context.Background(), r, mark, time.Second, time.Second)
	require.IsType(t, &probeTimeoutError{}, err,
		"the only matching line was printed before this run began")

	buf.append(sandboxdv1.Stream_STREAM_STDOUT, "listening on 3000", time.Now(), false)
	require.NoError(t, probe.run(context.Background(), r, mark, time.Second, time.Second),
		"the same line, printed by this run, is exactly what the pre-scan is for")
}

// TestTheMarkSurvivesTheRingTurningOver pins what the mark is made of.
//
// The retained buffer is a ring: it evicts, and the position of any given line
// in it moves as it fills. A mark that named a position — an index, an offset
// into the retained lines — would stop naming the same line the moment one was
// evicted, and it can go wrong in either direction. Too wide and the pre-scan
// credits this run with the last one's announcement, which is #57 back. Too
// narrow and it skips past the line this run actually printed, and a process
// that is serving never reports ready.
//
// A sequence number is neither, because it goes on meaning the same thing
// after the line it named has left the ring. Both halves below run against a
// ring that has already turned over.
func TestTheMarkSurvivesTheRingTurningOver(t *testing.T) {
	t.Parallel()

	probe := testProbe(probeLogPattern, 200*time.Millisecond)
	probe.patternSrc = `listening on \d+`
	probe.pattern = mustCompile(t, probe.patternSrc)

	// Eviction must not widen the bound. The run before this one is still in
	// the ring, and its announcement is below the mark however the ring is
	// packed.
	{
		buf := newLogBuffer(4, nil)
		buf.append(sandboxdv1.Stream_STREAM_STDOUT, "starting up", time.Now(), false)       // 0
		buf.append(sandboxdv1.Stream_STREAM_STDOUT, "listening on 3000", time.Now(), false) // 1
		mark := buf.nextSequence()                                                          // 2
		for i := range 3 {
			buf.append(sandboxdv1.Stream_STREAM_STDOUT, "working "+strconv.Itoa(i), time.Now(), false)
		}
		oldest, ok := buf.oldestRetainedSeq()
		require.True(t, ok)
		require.Equal(t, uint64(1), oldest, "the ring has to have evicted a line, or this is not about eviction")

		r := &record{buf: buf, changed: make(chan struct{})}
		require.IsType(t, &probeTimeoutError{}, probe.run(context.Background(), r, mark, time.Second, time.Second),
			"the only matching line in the ring belongs to the run before this one")
	}

	// And it must not narrow it. Same shape, except the first line this run
	// printed is the announcement: a mark that had been a position would now be
	// pointing past it.
	{
		buf := newLogBuffer(4, nil)
		buf.append(sandboxdv1.Stream_STREAM_STDOUT, "starting up", time.Now(), false)  // 0
		buf.append(sandboxdv1.Stream_STREAM_STDOUT, "and stopping", time.Now(), false) // 1
		mark := buf.nextSequence()                                                     // 2
		buf.append(sandboxdv1.Stream_STREAM_STDOUT, "listening on 3000", time.Now(), false)
		for i := range 2 {
			buf.append(sandboxdv1.Stream_STREAM_STDOUT, "serving "+strconv.Itoa(i), time.Now(), false)
		}
		oldest, ok := buf.oldestRetainedSeq()
		require.True(t, ok)
		require.Equal(t, uint64(1), oldest, "the ring has to have evicted a line, or this is not about eviction")

		r := &record{buf: buf, changed: make(chan struct{})}
		require.NoError(t, probe.run(context.Background(), r, mark, time.Second, time.Second),
			"this run's own announcement is still in the ring and still above the mark")
	}
}

// TestALogPatternProbeDoesNotMatchTheSupervisorsOwnNotes: log_pattern is
// documented as matching a line on stdout or stderr, and the supervisor's
// notes are neither.
//
// The note that matters most is the one it writes when a probe gives up,
// because it quotes the pattern that gave up. A probe that read the
// supervisor's notes would find that line in the history — which is exactly
// what a probe resumed after an agent restart reads — and take its own failure
// for the process's announcement.
func TestALogPatternProbeDoesNotMatchTheSupervisorsOwnNotes(t *testing.T) {
	t.Parallel()

	probe := testProbe(probeLogPattern, 200*time.Millisecond)
	probe.patternSrc = `ready`
	probe.pattern = mustCompile(t, probe.patternSrc)

	buf := newLogBuffer(50, nil)
	buf.note(`supervisor: readiness probe (log_pattern "ready") did not pass within 30s; the process is still running and its logs are readable`)
	r := &record{buf: buf, changed: make(chan struct{})}

	require.IsType(t, &probeTimeoutError{}, probe.run(context.Background(), r, 0, time.Second, time.Second),
		"the supervisor talking about the probe is not the process announcing itself")

	buf.append(sandboxdv1.Stream_STREAM_STDOUT, "ready to serve", time.Now(), false)
	require.NoError(t, probe.run(context.Background(), r, 0, time.Second, time.Second))
}

// countLines is how many captured lines contain substr.
func countLines(r *record, substr string) int {
	n := 0
	for _, line := range r.buf.ringLines() {
		if strings.Contains(line.Text, substr) {
			n++
		}
	}
	return n
}

func TestTCPProbeWaitsForSomethingToListen(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	// A port neither loopback address answers on, which is a stronger
	// requirement than freePort meets. freePort binds 127.0.0.1 and lets go, so
	// it proves that one address was free a moment ago; the probe dials ::1 as
	// well, and on a machine running several suites at once the number it hands
	// back can be taken between the two. Asking again costs nothing and is the
	// difference between a precondition and a race.
	var port int
	waitFor(t, 30*time.Second, "a loopback port nothing is listening on", func() bool {
		port = freePort(t)
		return !dialLoopback(context.Background(), uint32(port), 200*time.Millisecond) //nolint:gosec // a port is in range by construction
	})

	probe := testProbe(probeTCPPort, 5*time.Second)
	probe.port = uint32(port) //nolint:gosec // a port is in range by construction

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
		back := probeFromPersisted(spec.persisted(), time.Minute, time.Second)
		require.NotNil(t, back)
		require.Equal(t, spec.kind, back.kind)
		require.Equal(t, spec.describe(), back.describe())
		require.Equal(t, spec.timeout, back.timeout, "a persisted timeout is not overwritten by the default")
		require.Equal(t, spec.interval, back.interval, "a persisted interval is not overwritten by the default")
	}

	require.Nil(t, (*probeSpec)(nil).persisted())
	require.Nil(t, probeFromPersisted(nil, time.Minute, time.Second))
	require.Nil(t, probeFromPersisted(&persistedProbe{Kind: "something-else"}, time.Minute, time.Second))
}

// TestAProbeReadOffDiskWithNoTimingsStillRuns is the crash loop that would not
// have been a crash: re-adoption now runs a persisted probe on the startup
// path, and a ticker of zero panics.
//
// A record naming a probe with no interval cannot be written by this agent, so
// it arrives from an edit or a corruption. Left unguarded it takes the daemon
// down on every start, and every start re-reads the same record — a crash loop
// with nothing on the host able to break it, over a field nobody set.
func TestAProbeReadOffDiskWithNoTimingsStillRuns(t *testing.T) {
	t.Parallel()

	spec := probeFromPersisted(&persistedProbe{Kind: "log_pattern", Pattern: "ready"},
		300*time.Millisecond, 20*time.Millisecond)
	require.NotNil(t, spec)
	require.Positive(t, spec.interval, "a probe with no interval would panic time.NewTicker")
	require.Positive(t, spec.timeout, "a probe with no timeout would give up before it looked")

	buf := newLogBuffer(10, nil)
	r := &record{buf: buf, changed: make(chan struct{})}
	require.IsType(t, &probeTimeoutError{}, spec.run(context.Background(), r, 0, time.Second, time.Second))

	buf.append(sandboxdv1.Stream_STREAM_STDOUT, "ready to serve", time.Now(), false)
	require.NoError(t, spec.run(context.Background(), r, 0, time.Second, time.Second))
}

func mustCompile(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	re, err := regexp.Compile(pattern)
	require.NoError(t, err)
	return re
}
