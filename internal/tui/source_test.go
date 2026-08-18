package tui

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/client"
)

// fakeStream replays a scripted log stream, so the rendering can be tested
// without a connection. It is the same narrowing fleet_process_logs uses.
type fakeStream struct {
	events []*sandboxdv1.GetProcessLogsResponse
	err    error
	i      int
}

func (f *fakeStream) Recv() (*sandboxdv1.GetProcessLogsResponse, error) {
	if f.i >= len(f.events) {
		if f.err != nil {
			return nil, f.err
		}
		return nil, io.EOF
	}
	e := f.events[f.i]
	f.i++
	return e, nil
}

func line(text string, stream sandboxdv1.Stream, dropped uint64) *sandboxdv1.GetProcessLogsResponse {
	return &sandboxdv1.GetProcessLogsResponse{Event: &sandboxdv1.GetProcessLogsResponse_Line{
		Line: &sandboxdv1.LogLine{Text: text, Stream: stream, DroppedBefore: dropped},
	}}
}

// TestDropMarkersAreRenderedInline. A gap in the log is reported where it
// happened rather than as a count at the end, because a reader who sees the two
// lines either side of it adjacent will draw a conclusion from their adjacency.
func TestDropMarkersAreRenderedInline(t *testing.T) {
	t.Parallel()

	logs, err := readLogStream(&fakeStream{events: []*sandboxdv1.GetProcessLogsResponse{
		line("before the gap", sandboxdv1.Stream_STREAM_STDOUT, 0),
		line("after the gap", sandboxdv1.Stream_STREAM_STDOUT, 412),
		{Event: &sandboxdv1.GetProcessLogsResponse_Summary{Summary: &sandboxdv1.LogSummary{
			LinesReturned: 2, LinesDropped: 412, FollowDeadlineReached: true,
		}}},
	}}, 100)
	require.NoError(t, err)

	require.Len(t, logs.Lines, 3)
	require.Equal(t, "before the gap", logs.Lines[0].Text)
	require.True(t, logs.Lines[1].Marker, "the gap is not marked")
	require.Contains(t, logs.Lines[1].Text, "412 line(s) dropped")
	require.Equal(t, "after the gap", logs.Lines[2].Text)
	require.Equal(t, uint64(412), logs.Dropped)
	require.True(t, logs.DeadlineReached)
}

// TestStreamPrefixesMatchFleetProcessLogs. stdout unprefixed because it is the
// common case, stderr "E| ", and the supervisor's own lines "S| " so they are
// not mistaken for the process's output.
func TestStreamPrefixesMatchFleetProcessLogs(t *testing.T) {
	t.Parallel()

	logs, err := readLogStream(&fakeStream{events: []*sandboxdv1.GetProcessLogsResponse{
		line("plain", sandboxdv1.Stream_STREAM_STDOUT, 0),
		line("failed", sandboxdv1.Stream_STREAM_STDERR, 0),
		line("restarting", sandboxdv1.Stream_STREAM_UNSPECIFIED, 0),
	}}, 100)
	require.NoError(t, err)
	require.Equal(t, []string{"plain", "E| failed", "S| restarting"}, texts(logs))
}

// TestASplitLineSaysItWasSplit, or the two halves read as two independent
// short lines.
func TestASplitLineSaysItWasSplit(t *testing.T) {
	t.Parallel()

	logs, err := readLogStream(&fakeStream{events: []*sandboxdv1.GetProcessLogsResponse{
		{Event: &sandboxdv1.GetProcessLogsResponse_Line{Line: &sandboxdv1.LogLine{
			Text: "first half", Stream: sandboxdv1.Stream_STREAM_STDOUT, Continued: true,
		}}},
	}}, 100)
	require.NoError(t, err)
	require.Equal(t, []string{"first half [+]"}, texts(logs))
}

// TestALogWindowIsBounded. The rendering keeps at most MaxLines, oldest first,
// so a process that outruns the pane costs a fixed amount of memory — and says
// that it was cut rather than silently dropping the front.
func TestALogWindowIsBounded(t *testing.T) {
	t.Parallel()

	var events []*sandboxdv1.GetProcessLogsResponse
	for i := range 500 {
		events = append(events, line(string(rune('a'+i%26)), sandboxdv1.Stream_STREAM_STDOUT, 0))
	}
	logs, err := readLogStream(&fakeStream{events: events}, 50)
	require.NoError(t, err)
	require.Len(t, logs.Lines, 50)
	require.True(t, logs.Truncated, "output was cut without saying so")
}

// TestAFailedStreamKeepsWhatArrived. A partial window beats a blank pane, and
// the caller reports the error beside it.
func TestAFailedStreamKeepsWhatArrived(t *testing.T) {
	t.Parallel()

	logs, err := readLogStream(&fakeStream{
		events: []*sandboxdv1.GetProcessLogsResponse{line("got this far", sandboxdv1.Stream_STREAM_STDOUT, 0)},
		err:    status.Error(codes.Unavailable, "connection refused"),
	}, 100)
	require.ErrorIs(t, err, client.ErrUnreachable, "the failure is not in the shared vocabulary")
	require.Equal(t, []string{"got this far"}, texts(logs))
}

// TestALogLineCannotCarryAnEscape. This is where the least trustworthy string
// in the program enters it.
func TestALogLineCannotCarryAnEscape(t *testing.T) {
	t.Parallel()

	logs, err := readLogStream(&fakeStream{events: []*sandboxdv1.GetProcessLogsResponse{
		line("\x1b[2J\x1b[Hwiped the screen", sandboxdv1.Stream_STREAM_STDOUT, 0),
	}}, 100)
	require.NoError(t, err)
	require.Equal(t, []string{"[2J[Hwiped the screen"}, texts(logs))
	require.NotContains(t, logs.Lines[0].Text, "\x1b")
}

// TestAProcessThatHasExitedHasNoPid. Showing the pid it used to hold invites a
// signal aimed at whatever now owns it.
func TestAProcessThatHasExitedHasNoPid(t *testing.T) {
	t.Parallel()

	started := time.Date(2026, 8, 17, 11, 0, 0, 0, time.UTC)
	exited := started.Add(90 * time.Second)
	now := exited.Add(time.Hour)

	dead := projectProcess(&sandboxdv1.ProcessStatus{
		ProcessId: "p1", Name: "gone", Pid: 4211,
		State:     sandboxdv1.ProcessState_PROCESS_STATE_EXITED,
		StartedAt: timestamppb.New(started), ExitedAt: timestamppb.New(exited),
	}, now)
	require.Equal(t, int32(0), dead.PID)
	require.Equal(t, client.ProcessExited, dead.State)
	require.Equal(t, "1m30s", dead.Uptime, "uptime is measured to the exit, not to now")

	live := projectProcess(&sandboxdv1.ProcessStatus{
		ProcessId: "p2", Name: "alive", Pid: 4300,
		State: sandboxdv1.ProcessState_PROCESS_STATE_RUNNING, StartedAt: timestamppb.New(now.Add(-time.Minute)),
	}, now)
	require.Equal(t, int32(4300), live.PID)
	require.Equal(t, "1m0s", live.Uptime)
}

// TestProcessStateWordsAreTheSharedOnes. The TUI must not have its own list.
func TestProcessStateWordsAreTheSharedOnes(t *testing.T) {
	t.Parallel()

	for wire, want := range map[sandboxdv1.ProcessState]string{
		sandboxdv1.ProcessState_PROCESS_STATE_STARTING:    client.ProcessStarting,
		sandboxdv1.ProcessState_PROCESS_STATE_READY:       client.ProcessReady,
		sandboxdv1.ProcessState_PROCESS_STATE_RUNNING:     client.ProcessRunning,
		sandboxdv1.ProcessState_PROCESS_STATE_EXITED:      client.ProcessExited,
		sandboxdv1.ProcessState_PROCESS_STATE_CRASHED:     client.ProcessCrashed,
		sandboxdv1.ProcessState_PROCESS_STATE_RESTARTING:  client.ProcessRestarting,
		sandboxdv1.ProcessState_PROCESS_STATE_ORPHANED:    client.ProcessOrphaned,
		sandboxdv1.ProcessState_PROCESS_STATE_UNSPECIFIED: client.ProcessUnknown,
	} {
		p := projectProcess(&sandboxdv1.ProcessStatus{State: wire}, time.Now())
		require.Equal(t, want, p.State)
		// And the model's notion of "still there" agrees with the client's.
		require.Equal(t, client.ProcessStateLive(wire), isLive(p.State), want)
	}
}

// TestNothingProbedIsNotTheSameAsNothingThere.
//
// "unknown" means nothing has looked; "unreachable" means something looked and
// found nothing. An operator who cannot tell them apart will chase a machine
// that is fine.
func TestNothingProbedIsNotTheSameAsNothingThere(t *testing.T) {
	t.Parallel()

	never := Sandbox{Health: client.HealthUnknown}
	applyHealth(&never, client.HealthStatus{})
	require.Equal(t, client.HealthUnknown, never.Health)

	dialed := Sandbox{Health: client.HealthUnknown}
	applyHealth(&dialed, client.HealthStatus{CheckedAt: time.Now()})
	require.Equal(t, client.HealthUnknown, dialed.Health, "a channel with no probe yet is not unreachable")

	failed := Sandbox{Health: client.HealthUnknown}
	applyHealth(&failed, client.HealthStatus{
		CheckedAt: time.Now(), Err: status.Error(codes.Unavailable, "connection refused"),
	})
	require.Equal(t, client.HealthUnreachable, failed.Health)
	require.Equal(t, "no answer within the timeout", failed.Detail)
}

// TestHealthWordsAreTheSharedOnes, and a live probe replaces the registry's
// cached agent version and last-seen time.
func TestHealthWordsAreTheSharedOnes(t *testing.T) {
	t.Parallel()

	now := time.Now()
	for wire, want := range map[sandboxdv1.HealthResponse_Status]string{
		sandboxdv1.HealthResponse_STATUS_SERVING:  client.HealthServing,
		sandboxdv1.HealthResponse_STATUS_DEGRADED: client.HealthDegraded,
		sandboxdv1.HealthResponse_STATUS_DRAINING: client.HealthDraining,
	} {
		row := Sandbox{Health: client.HealthUnknown, Agent: "stale", LastSeen: now.Add(-time.Hour)}
		applyHealth(&row, client.HealthStatus{
			Reachable: true, Status: wire, CheckedAt: now, AgentVersion: "v9.9.9", Message: "fine",
		})
		require.Equal(t, want, row.Health)
		require.Equal(t, "v9.9.9", row.Agent)
		require.Equal(t, now, row.LastSeen)
	}
}

// TestProbeDetailUsesTheSharedFailureVocabulary, so the reason the TUI gives
// for a sandbox not answering and the reason `fleetctl list` gives are the same
// sentence.
func TestProbeDetailUsesTheSharedFailureVocabulary(t *testing.T) {
	t.Parallel()

	require.Equal(t, "no answer within the timeout", probeDetail(status.Error(codes.Unavailable, "x")))
	require.Equal(t, "no answer within the timeout", probeDetail(status.Error(codes.DeadlineExceeded, "x")))
	require.Equal(t, "certificate rejected", probeDetail(status.Error(codes.Unauthenticated, "x")))
	require.Contains(t, probeDetail(errors.New("something else")), "something else")
}

// TestOnlySignalsTheWireHasAreAccepted: a name the proto does not have is
// refused here rather than sent and rejected on the far side.
func TestOnlySignalsTheWireHasAreAccepted(t *testing.T) {
	t.Parallel()

	for _, name := range signals {
		_, err := parseSignal(name)
		require.NoErrorf(t, err, "the picker offers SIG%s and the wire does not have it", name)
	}
	_, err := parseSignal("QUIT")
	require.Error(t, err)
	require.Contains(t, err.Error(), "TERM, KILL, INT, HUP, USR1, USR2")
}

func texts(l Logs) []string {
	out := make([]string, 0, len(l.Lines))
	for _, line := range l.Lines {
		out = append(out, line.Text)
	}
	return out
}
