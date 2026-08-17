package tools

import (
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

// The rendering is the product here — a listing a model has to re-query is a
// listing that failed — so it is asserted on its own, without a gRPC
// connection in the way.

func TestRenderProcessTable_IsCompactAndAligned(t *testing.T) {
	now := time.Now()
	rows := make([]ProcessLine, 0, 20)
	for i := range 20 {
		rows = append(rows, processLine(&sandboxdv1.ProcessStatus{
			ProcessId:      fmt.Sprintf("proc-%016d", i),
			Name:           fmt.Sprintf("service-%02d", i),
			Argv:           []string{"node", "server.js", "--port", "3000"},
			State:          sandboxdv1.ProcessState_PROCESS_STATE_READY,
			Pid:            int32(40000 + i), //nolint:gosec // small test value
			StartedAt:      timestamppb.New(now.Add(-3 * time.Minute)),
			ListeningPorts: []uint32{uint32(3000 + i)}, //nolint:gosec // small test value
			LastLogLine:    "ready - compiled successfully in 812ms",
		}, now))
	}

	table := renderProcessTable(rows)
	lines := strings.Split(strings.TrimSpace(table), "\n")

	// One header, twenty rows, one footnote.
	require.GreaterOrEqual(t, len(lines), 21)
	assert.Contains(t, lines[0], "STATE")
	assert.Contains(t, lines[0], "LAST LOG")

	// Columns line up: every row starts its NAME at the same offset as the
	// header's, which is what makes the table scannable rather than merely
	// present.
	nameAt := strings.Index(lines[0], "NAME")
	require.Positive(t, nameAt)
	for _, line := range lines[1:21] {
		assert.Truef(t, strings.HasPrefix(line[nameAt:], "service-"),
			"row is not aligned under NAME: %q", line)
	}

	// And it stays small: twenty rows of table, not twenty JSON objects.
	assert.Less(t, len(table), 3000, "twenty rows must stay under three kilobytes")
	for _, line := range lines {
		assert.NotContains(t, line, "  \n")
		assert.False(t, strings.HasSuffix(line, " "), "rows must not carry trailing padding: %q", line)
	}
}

func TestRenderProcessTable_ShowsExitCodesAndAbsentPids(t *testing.T) {
	now := time.Now()
	rows := []ProcessLine{
		processLine(&sandboxdv1.ProcessStatus{
			ProcessId: "a", Name: "migrate", State: sandboxdv1.ProcessState_PROCESS_STATE_CRASHED,
			Pid: 999, ExitCode: 1,
			StartedAt: timestamppb.New(now.Add(-time.Minute)), ExitedAt: timestamppb.New(now),
			LastLogLine: "relation \"users\" does not exist",
		}, now),
	}

	table := renderProcessTable(rows)
	assert.Contains(t, table, "crashed(1)", "the exit code belongs beside the state")
	assert.NotContains(t, table, "999",
		"an exited process must not report the pid it used to hold; something else owns it now")
	assert.Contains(t, table, "relation")
}

func TestProcessLine_ExitCodeIsAbsentWhileRunning(t *testing.T) {
	now := time.Now()
	running := processLine(&sandboxdv1.ProcessStatus{
		State: sandboxdv1.ProcessState_PROCESS_STATE_RUNNING, Pid: 42,
	}, now)
	assert.Nil(t, running.ExitCode, "a running process has no exit code, and zero is a real one")
	assert.Equal(t, int32(42), running.PID)

	exited := processLine(&sandboxdv1.ProcessStatus{
		State: sandboxdv1.ProcessState_PROCESS_STATE_EXITED, Pid: 42, ExitCode: 0,
	}, now)
	require.NotNil(t, exited.ExitCode)
	assert.Equal(t, int32(0), *exited.ExitCode)
}

func TestProcessLine_UptimeIsTheLifetimeOfAnExitedProcess(t *testing.T) {
	now := time.Now()
	line := processLine(&sandboxdv1.ProcessStatus{
		State:     sandboxdv1.ProcessState_PROCESS_STATE_EXITED,
		StartedAt: timestamppb.New(now.Add(-2 * time.Hour)),
		ExitedAt:  timestamppb.New(now.Add(-90 * time.Minute)),
	}, now)
	// Half an hour of life, not the two hours since it started.
	assert.Equal(t, "30m0s", line.Uptime)
}

func TestProcessLine_BoundsAgentSuppliedText(t *testing.T) {
	now := time.Now()
	line := processLine(&sandboxdv1.ProcessStatus{
		Name:        "noisy",
		Argv:        []string{strings.Repeat("x", 400)},
		LastLogLine: strings.Repeat("y", 400) + "\nsecond line",
		State:       sandboxdv1.ProcessState_PROCESS_STATE_RUNNING,
	}, now)

	assert.LessOrEqual(t, len(line.LastLogLine), maxLastLogLine+4)
	assert.LessOrEqual(t, len(line.Command), maxCommandChars+4)
	assert.NotContains(t, line.LastLogLine, "\n", "a newline in one field would break the table")
}

// The name is the one string in a row that came from the caller rather than
// from the process, and it was the one string not bounded. A newline in it
// splits a row in two, which breaks the only claim this listing makes.
func TestProcessLine_BoundsTheProcessName(t *testing.T) {
	now := time.Now()
	line := processLine(&sandboxdv1.ProcessStatus{
		Name:  "web\ndev\r\nlisten 0.0.0.0",
		State: sandboxdv1.ProcessState_PROCESS_STATE_RUNNING,
		Pid:   17,
	}, now)
	assert.NotContains(t, line.Name, "\n", "a newline in a name would split its row in two")
	assert.NotContains(t, line.Name, "\r")

	long := processLine(&sandboxdv1.ProcessStatus{
		Name:  strings.Repeat("n", 4000),
		State: sandboxdv1.ProcessState_PROCESS_STATE_RUNNING,
	}, now)
	assert.LessOrEqual(t, len(long.Name), maxProcessName+4)

	// And the table built from it stays one line per process.
	table := renderProcessTable([]ProcessLine{line, long})
	rows := 0
	for _, l := range strings.Split(strings.TrimSpace(table), "\n") {
		if strings.HasPrefix(l, "running") {
			rows++
		}
	}
	assert.Equal(t, 2, rows, "one row per process: %q", table)
}

// A row whose last column is empty must not carry the previous column's
// padding. That is every row of a listing taken just after a fleet of services
// was started, which is when a listing is most often taken.
func TestRenderProcessTable_DoesNotPadARowWithNoLastLogLine(t *testing.T) {
	now := time.Now()
	rows := []ProcessLine{
		processLine(&sandboxdv1.ProcessStatus{
			Name: "quiet", State: sandboxdv1.ProcessState_PROCESS_STATE_RUNNING, Pid: 11,
			StartedAt: timestamppb.New(now.Add(-time.Minute)),
		}, now),
		processLine(&sandboxdv1.ProcessStatus{
			Name: "talkative", State: sandboxdv1.ProcessState_PROCESS_STATE_RUNNING, Pid: 12,
			StartedAt: timestamppb.New(now.Add(-time.Minute)), LastLogLine: "listening on :8080",
		}, now),
	}

	for _, line := range strings.Split(renderProcessTable(rows), "\n") {
		assert.Falsef(t, strings.HasSuffix(line, " "), "row carries trailing padding: %q", line)
	}
}

func TestProcessLine_SortsListeningPorts(t *testing.T) {
	line := processLine(&sandboxdv1.ProcessStatus{ListeningPorts: []uint32{9229, 3000, 5173}}, time.Now())
	assert.Equal(t, []uint32{3000, 5173, 9229}, line.ListeningPorts)
}

// ------------------------------------------------------------- log render

// A fake stream, so the rendering can be driven past the cases a real agent
// makes hard to produce on demand.
type scriptedLogs struct {
	responses []*sandboxdv1.GetProcessLogsResponse
	next      int
	err       error
}

func (s *scriptedLogs) Recv() (*sandboxdv1.GetProcessLogsResponse, error) {
	if s.next >= len(s.responses) {
		if s.err != nil {
			return nil, s.err
		}
		return nil, io.EOF
	}
	resp := s.responses[s.next]
	s.next++
	return resp, nil
}

func line(stream sandboxdv1.Stream, text string, dropped uint64, continued bool) *sandboxdv1.GetProcessLogsResponse {
	return &sandboxdv1.GetProcessLogsResponse{
		Event: &sandboxdv1.GetProcessLogsResponse_Line{Line: &sandboxdv1.LogLine{
			Stream: stream, Text: text, DroppedBefore: dropped, Continued: continued,
			Timestamp: timestamppb.Now(),
		}},
	}
}

func TestRenderLogStream_MarksDropsInlineAndTagsStreams(t *testing.T) {
	stream := &scriptedLogs{responses: []*sandboxdv1.GetProcessLogsResponse{
		line(sandboxdv1.Stream_STREAM_STDOUT, "compiling", 0, false),
		line(sandboxdv1.Stream_STREAM_STDERR, "warning: deprecated", 0, false),
		line(sandboxdv1.Stream_STREAM_STDOUT, "done", 17, false),
		line(sandboxdv1.Stream_STREAM_UNSPECIFIED, "supervisor: restarting", 0, false),
		{Event: &sandboxdv1.GetProcessLogsResponse_Summary{Summary: &sandboxdv1.LogSummary{
			LinesReturned: 4, LinesDropped: 17,
			State: sandboxdv1.ProcessState_PROCESS_STATE_RUNNING,
		}}},
	}}

	out, summary, err := renderLogStream(stream, maxRenderedLogBytes)
	require.NoError(t, err)
	require.NotNil(t, summary)

	rendered := strings.Split(out.Text, "\n")
	require.Len(t, rendered, 5, "the drop marker is a line of its own, in sequence")
	assert.Equal(t, "compiling", rendered[0], "stdout is unprefixed; it is the common case")
	assert.Equal(t, "E| warning: deprecated", rendered[1])
	assert.Contains(t, rendered[2], "17 line(s) dropped")
	assert.Equal(t, "done", rendered[3])
	assert.Equal(t, "S| supervisor: restarting", rendered[4],
		"a supervisor line must not read as the process's own output")
	assert.Equal(t, uint64(17), summary.GetLinesDropped())
}

func TestRenderLogStream_MarksASplitLine(t *testing.T) {
	stream := &scriptedLogs{responses: []*sandboxdv1.GetProcessLogsResponse{
		line(sandboxdv1.Stream_STREAM_STDOUT, "first half", 0, true),
		line(sandboxdv1.Stream_STREAM_STDOUT, "second half", 0, false),
	}}
	out, _, err := renderLogStream(stream, maxRenderedLogBytes)
	require.NoError(t, err)
	assert.Contains(t, out.Text, "first half [+]",
		"a split line must not read as two short lines")
}

func TestRenderLogStream_TruncatesFromTheFrontAndSaysSo(t *testing.T) {
	responses := make([]*sandboxdv1.GetProcessLogsResponse, 0, 200)
	for i := range 200 {
		responses = append(responses, line(sandboxdv1.Stream_STREAM_STDOUT, fmt.Sprintf("line %03d", i), 0, false))
	}
	stream := &scriptedLogs{responses: responses}

	out, _, err := renderLogStream(stream, 400)
	require.NoError(t, err)

	assert.True(t, out.Truncated)
	assert.Positive(t, out.LinesOmitted)
	assert.Positive(t, out.BytesOmitted)
	assert.Contains(t, out.Text, "earlier line(s) omitted",
		"output is never silently cut")
	assert.Contains(t, out.Text, "line 199", "the recent end is the useful end")
	assert.NotContains(t, out.Text, "line 000")
	assert.Less(t, len(out.Text), 900)
}

func TestRenderLogStream_ReturnsWhatArrivedBeforeAFailure(t *testing.T) {
	stream := &scriptedLogs{
		responses: []*sandboxdv1.GetProcessLogsResponse{
			line(sandboxdv1.Stream_STREAM_STDOUT, "before the failure", 0, false),
		},
		err: fmt.Errorf("the stream broke"),
	}
	out, _, err := renderLogStream(stream, maxRenderedLogBytes)
	require.Error(t, err)
	assert.Contains(t, out.Text, "before the failure", "a partial log beats none")
}

// --------------------------------------------------------------- probes

func TestReadyProbeArgs_ConvertsEachCondition(t *testing.T) {
	for _, tc := range []struct {
		name string
		args ReadyProbeArgs
		want func(*sandboxdv1.ReadyProbe) bool
	}{
		{"log", ReadyProbeArgs{LogPattern: "Listening on"}, func(p *sandboxdv1.ReadyProbe) bool {
			return p.GetLogPattern() == "Listening on"
		}},
		{"tcp", ReadyProbeArgs{TCPPort: 3000}, func(p *sandboxdv1.ReadyProbe) bool {
			return p.GetTcpPort() == 3000
		}},
		{"http", ReadyProbeArgs{HTTPGetURL: "http://127.0.0.1:3000/healthz"}, func(p *sandboxdv1.ReadyProbe) bool {
			return p.GetHttpGetUrl() == "http://127.0.0.1:3000/healthz"
		}},
		{"uptime", ReadyProbeArgs{UptimeSeconds: 2.5}, func(p *sandboxdv1.ReadyProbe) bool {
			return p.GetUptime().AsDuration() == 2500*time.Millisecond
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.args.toProto()
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.True(t, tc.want(got))
		})
	}
}

func TestReadyProbeArgs_TimeoutIsCarried(t *testing.T) {
	got, err := (&ReadyProbeArgs{TCPPort: 3000, TimeoutSeconds: 45}).toProto()
	require.NoError(t, err)
	assert.Equal(t, durationpb.New(45*time.Second).AsDuration(), got.GetTimeout().AsDuration())
	assert.Equal(t, 45*time.Second, probeDeadline(got))
}

func TestReadyProbeArgs_RejectsZeroOrTwoConditions(t *testing.T) {
	_, err := (&ReadyProbeArgs{TimeoutSeconds: 5}).toProto()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tcp_port")
	assert.Contains(t, err.Error(), "omit ready_probe")

	_, err = (&ReadyProbeArgs{TCPPort: 3000, UptimeSeconds: 2}).toProto()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one")

	_, err = (&ReadyProbeArgs{TCPPort: 99999}).toProto()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1-65535")
}

func TestReadyProbeArgs_NilIsNoProbe(t *testing.T) {
	var p *ReadyProbeArgs
	got, err := p.toProto()
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestProbeDeadline_FallsBackToTheAgentDefault(t *testing.T) {
	assert.Equal(t, 30*time.Second, probeDeadline(&sandboxdv1.ReadyProbe{}))
}

// The probe's two seconds-valued arguments are bounded like every other one.
//
// They are floats, and a float64 that does not fit in an int64 converts to a
// value the spec leaves to the implementation: arm64 saturates to the maximum,
// amd64 wraps to the minimum. Unbounded, ready_probe.timeout_seconds therefore
// buys either an RPC deadline three centuries out — a start call that can hang
// for the life of the process — or one that has already expired, so the call
// reports a timeout for a start that never left, and which of the two depends
// on the workstation's architecture. The same argument applies to
// uptime_seconds, which becomes a duration the agent waits out.
func TestReadyProbeArgs_BoundsItsSecondsArguments(t *testing.T) {
	for _, seconds := range []float64{
		maxSecondsArgument + 1,
		1e9,
		9223372030, // just inside int64 nanoseconds, so the deadline arithmetic overflows
		1e18,       // far outside it, where the conversion itself is implementation-defined
	} {
		probe, err := (&ReadyProbeArgs{TCPPort: 3000, TimeoutSeconds: seconds}).toProto()
		require.NoErrorf(t, err, "timeout_seconds=%g", seconds)

		deadline := probeDeadline(probe)
		assert.Positivef(t, deadline, "timeout_seconds=%g gave a deadline that has already expired", seconds)
		assert.LessOrEqualf(t, deadline, maxSecondsArgument*time.Second,
			"timeout_seconds=%g must be bounded, not taken at its word", seconds)
		assert.Positivef(t, deadline+followSlack,
			"timeout_seconds=%g overflows the start call's deadline into the past", seconds)

		uptime, err := (&ReadyProbeArgs{UptimeSeconds: seconds}).toProto()
		require.NoErrorf(t, err, "uptime_seconds=%g", seconds)
		assert.Positivef(t, uptime.GetUptime().AsDuration(), "uptime_seconds=%g", seconds)
		assert.LessOrEqualf(t, uptime.GetUptime().AsDuration(), maxSecondsArgument*time.Second,
			"uptime_seconds=%g must be bounded", seconds)
	}
}

// And a negative one is named rather than silently dropped, the way
// grace_seconds already is on signal and restart.
func TestReadyProbeArgs_RejectsNegativeSeconds(t *testing.T) {
	_, err := (&ReadyProbeArgs{TCPPort: 3000, TimeoutSeconds: -1}).toProto()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout_seconds")
	assert.Contains(t, err.Error(), "negative")

	_, err = (&ReadyProbeArgs{UptimeSeconds: -1}).toProto()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "uptime_seconds")
	assert.Contains(t, err.Error(), "negative")
}

// ------------------------------------------------------------- deadlines

// A graceful stop blocks on the agent for the whole grace period before it
// answers, and an unset grace_seconds is not a zero grace — the agent applies
// its own default. Sizing the deadline from the argument alone is how a call
// gives up on a stop that is still working and reports a timeout for it.
func TestSignalDeadline_ClearsTheGraceTheAgentWillActuallyTake(t *testing.T) {
	const callTimeout = 15 * time.Second

	// Unset: the agent's own default, plus the same slack an explicit one gets.
	assert.GreaterOrEqualf(t,
		signalDeadline(true, 0, callTimeout),
		defaultGraceSeconds*time.Second+followSlack,
		"an unset grace_seconds still costs the agent %ds before it escalates", defaultGraceSeconds)

	// Explicit and larger: it wins.
	assert.Equal(t, 90*time.Second+followSlack, signalDeadline(true, 90, callTimeout))

	// Explicit and smaller: the argument is honoured, and the ordinary call
	// timeout is still the floor.
	assert.Equal(t, time.Second+followSlack, signalDeadline(true, 1, callTimeout))
	assert.Equal(t, 60*time.Second, signalDeadline(true, 1, 60*time.Second))

	// Not a graceful stop: nothing blocks on the agent.
	assert.Equal(t, callTimeout, signalDeadline(false, 0, callTimeout))
	assert.Equal(t, callTimeout, signalDeadline(false, 600, callTimeout))
}

func TestGracePeriodFor_UsesTheAgentDefaultOnlyWhenUnset(t *testing.T) {
	assert.Equal(t, defaultGraceSeconds*time.Second, gracePeriodFor(0))
	assert.Equal(t, defaultGraceSeconds*time.Second, gracePeriodFor(-5))
	assert.Equal(t, 45*time.Second, gracePeriodFor(45))
}

// ---------------------------------------------------------------- enums

func TestParseSignal_AcceptsBothSpellings(t *testing.T) {
	for _, name := range []string{"TERM", "term", "SIGTERM", " sigterm "} {
		got, err := parseSignal(name)
		require.NoErrorf(t, err, "%q", name)
		assert.Equal(t, sandboxdv1.SignalProcessRequest_SIGNAL_TERM, got)
	}
	_, err := parseSignal("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "graceful_stop")
}

func TestParseStates_RejectsAnUnknownName(t *testing.T) {
	got, err := parseStates([]string{"running", "crashed"})
	require.NoError(t, err)
	assert.Len(t, got, 2)

	_, err = parseStates([]string{"zombie"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "starting, ready, running")
}

func TestParsePolicyAndStream(t *testing.T) {
	got, err := parsePolicy("on-failure")
	require.NoError(t, err)
	assert.Equal(t, sandboxdv1.RestartPolicy_RESTART_POLICY_ON_FAILURE, got)
	_, err = parsePolicy("sometimes")
	require.Error(t, err)

	stream, err := parseStream("")
	require.NoError(t, err)
	assert.Equal(t, sandboxdv1.Stream_STREAM_UNSPECIFIED, stream)
	stream, err = parseStream("stderr")
	require.NoError(t, err)
	assert.Equal(t, sandboxdv1.Stream_STREAM_STDERR, stream)
	_, err = parseStream("syslog")
	require.Error(t, err)
}

func TestClip_CutsOnARuneBoundary(t *testing.T) {
	got := clip(strings.Repeat("é", 200), 20)
	assert.True(t, strings.HasSuffix(got, "…"))
	assert.True(t, isValidUTF8(got), "clipping mid-rune would put invalid UTF-8 into the result")
}

// clipCell is clip plus the one thing a table cell needs and a rendered line
// does not: it flattens before it bounds, because a cell of a fixed-width table
// is one line by definition and bounding a string that still holds a newline
// bounds the wrong thing.
func TestClipCell_FlattensBeforeItBounds(t *testing.T) {
	got := clipCell("web\ndev\r\nlisten", 64)
	assert.Equal(t, "web dev listen", got)
	assert.NotContains(t, got, "\n")

	// And a cell that is only newlines and padding leaves nothing hanging off
	// the end of its row.
	assert.Empty(t, clipCell("  \n  \r\n", 64))

	long := clipCell(strings.Repeat("é", 200)+"\nsecond line", 20)
	assert.True(t, strings.HasSuffix(long, "…"))
	assert.NotContains(t, long, "\n")
}

func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}
