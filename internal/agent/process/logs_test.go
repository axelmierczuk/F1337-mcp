package process

import (
	"context"
	"fmt"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/platform"
)

func TestStreamsAreDistinguishableAndOrdered(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	// 250ms between writes. stdout and stderr are separate files followed by
	// separate goroutines, so the agent's read order reproduces the process's
	// write order only for writes further apart than a poll interval — 20ms at
	// most here. Two writes microseconds apart on different streams can be read
	// in either order, and no capture that tags streams separately can do
	// better without the process cooperating.
	r := ts.startHelper("two-streams", "streams", "250", "2")
	waitForLine(t, r, 20*time.Second, "err 1")

	stream := &recordingStream{}
	require.NoError(t, ts.streamLogs(context.Background(), r, logRequest{sel: selector{tail: 100}}, stream))

	var got, stdout, stderr []string
	for _, line := range stream.lines {
		switch line.GetStream() {
		case sandboxdv1.Stream_STREAM_STDOUT:
			got = append(got, "out:"+line.GetText())
			stdout = append(stdout, line.GetText())
		case sandboxdv1.Stream_STREAM_STDERR:
			got = append(got, "err:"+line.GetText())
			stderr = append(stderr, line.GetText())
		case sandboxdv1.Stream_STREAM_UNSPECIFIED:
			// A supervisor note. Not the process's output.
		}
	}

	// Within a stream the order is exact, and it is exact by construction: one
	// goroutine reads one file in order.
	require.Equal(t, []string{"out 0", "out 1"}, stdout)
	require.Equal(t, []string{"err 0", "err 1"}, stderr)

	// Across streams, with the writes well separated, read order is write order.
	require.Equal(t, []string{"out:out 0", "err:err 0", "out:out 1", "err:err 1"}, got)

	// And a stream filter returns exactly one of them.
	only := &recordingStream{}
	require.NoError(t, ts.streamLogs(context.Background(), r,
		logRequest{sel: selector{tail: 100, stream: sandboxdv1.Stream_STREAM_STDERR}}, only))
	require.Equal(t, []string{"err 0", "err 1"}, only.texts())
}

func TestRingBufferEvictsOldestFirst(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t, func(c *supervisorConfig) { c.ringBufferLines = 10 })

	r := ts.startHelper("evicting", "echo", "50", "0", "line")
	waitState(t, r, 10*time.Second, sandboxdv1.ProcessState_PROCESS_STATE_EXITED)
	waitForLine(t, r, 5*time.Second, "line 49")

	lines := r.buf.ringLines()
	require.Len(t, lines, 10, "the ring holds exactly its configured number of lines")
	require.Equal(t, "line 49", lines[len(lines)-1].Text)
	require.Equal(t, "line 40", lines[0].Text, "the oldest lines are the ones evicted")
}

func TestLogsSurviveTheProcessExiting(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	r := ts.startHelper("dead-but-readable", "echo", "5", "0", "last words")
	waitState(t, r, 10*time.Second, sandboxdv1.ProcessState_PROCESS_STATE_EXITED)
	waitForLine(t, r, 5*time.Second, "last words 4")

	stream := &recordingStream{}
	require.NoError(t, ts.streamLogs(context.Background(), r, logRequest{sel: selector{tail: 100}}, stream))
	require.Contains(t, stream.texts(), "last words 0")
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_EXITED, stream.summary.GetState())

	// Until RemoveProcess, and not after.
	require.NoError(t, ts.remove(r, false, true))
	_, ok := ts.lookup(r.id)
	require.False(t, ok)
}

func TestFileRotationPrunesOldSegments(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t, func(c *supervisorConfig) { c.retainSegments = 2 })

	spec := ts.helperSpec("rotating", "echo", "3000", "0", "rotate-me-with-some-padding-to-make-the-record-larger")
	spec.maxLogBytes = 16 * 1024
	r, err := ts.start(spec, false)
	require.NoError(t, err)

	waitState(t, r, 30*time.Second, sandboxdv1.ProcessState_PROCESS_STATE_EXITED)
	waitForLine(t, r, 10*time.Second, "rotate-me-with-some-padding-to-make-the-record-larger 2999")

	segments := r.buf.segments()
	require.Greater(t, len(segments), 1, "the log should have rotated at its cap")
	require.LessOrEqual(t, len(segments), 3, "retain=2 plus the live segment")

	// Nothing older than the retention is left behind.
	require.NoFileExists(t, segments[len(segments)-1]+".3")
}

// TestBackpressureOnAMillionLines is the assertion that a chatty process cannot
// take the agent down with it: the heap stays bounded, the drops are counted
// rather than hidden, and — the part that is easy to get wrong — the process
// itself is never blocked, so it still exits promptly.
func TestBackpressureOnAMillionLines(t *testing.T) {
	if testing.Short() {
		t.Skip("emits a million lines")
	}
	t.Parallel()
	ts := newTestSupervisor(t, func(c *supervisorConfig) {
		c.ringBufferLines = 500
		c.maxLogBytes = 128 * 1024
		c.retainSegments = 2
		c.rawCapBytes = 512 * 1024
	})

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	const lines = 1_000_000
	started := time.Now()
	r := ts.startHelper("firehose", "spew", fmt.Sprint(lines))

	// The process is never blocked on the agent, so it exits on its own.
	waitState(t, r, 60*time.Second, sandboxdv1.ProcessState_PROCESS_STATE_EXITED)
	require.Less(t, time.Since(started), 60*time.Second)

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	growth := int64(after.HeapAlloc) - int64(before.HeapAlloc) //nolint:gosec // heap sizes here are far below the int64 range
	require.Less(t, growth, int64(64<<20),
		"the agent's heap must not grow with the process's output (grew %d bytes)", growth)

	// The ring is still exactly its configured size, and the lines that fell
	// out of it were counted rather than silently discarded.
	require.Len(t, r.buf.ringLines(), 500)

	stream := &recordingStream{}
	require.NoError(t, ts.streamLogs(context.Background(), r,
		logRequest{sel: selector{tail: 100_000}}, stream))
	require.NotNil(t, stream.summary)
	require.Positive(t, stream.summary.GetLinesDropped(),
		"a process that outran the buffer must have its drops counted")
	require.Positive(t, stream.lines[0].GetDroppedBefore(),
		"the gap must be visible on the first line, not only in the summary")
}

// TestFollowAlwaysReturnsAtItsDeadline uses a process that produces nothing at
// all — the case where a follow with no deadline would hang forever, and the
// model on the other end would simply stop.
func TestFollowAlwaysReturnsAtItsDeadline(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	r := ts.startHelper("silent-forever", "silent")

	stream := &recordingStream{}
	started := time.Now()
	require.NoError(t, ts.streamLogs(context.Background(), r, logRequest{
		sel:       selector{tail: 100},
		follow:    true,
		followFor: 300 * time.Millisecond,
	}, stream))
	elapsed := time.Since(started)

	require.NotNil(t, stream.summary)
	require.True(t, stream.summary.GetFollowDeadlineReached(),
		"a follow that ended on its deadline must say so")
	require.GreaterOrEqual(t, elapsed, 300*time.Millisecond)
	require.Less(t, elapsed, 10*time.Second, "the follow must not outlast its deadline")
}

func TestFollowDurationIsClampedNotHonoured(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t, func(c *supervisorConfig) { c.maxFollowDuration = 250 * time.Millisecond })

	r := ts.startHelper("clamped", "silent")

	// An hour requested. A quarter of a second allowed.
	require.Equal(t, 250*time.Millisecond, ts.clampFollow(time.Hour))
	require.Equal(t, 250*time.Millisecond, ts.clampFollow(0), "zero means the maximum, not forever")
	require.Equal(t, 100*time.Millisecond, ts.clampFollow(100*time.Millisecond))

	stream := &recordingStream{}
	started := time.Now()
	require.NoError(t, ts.streamLogs(context.Background(), r, logRequest{
		sel:       selector{tail: 10},
		follow:    true,
		followFor: time.Hour,
	}, stream))

	require.True(t, stream.summary.GetFollowDeadlineReached())
	require.Less(t, time.Since(started), 5*time.Second, "an hour-long follow must be clamped")
}

func TestFollowEndsWhenTheProcessExits(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t, func(c *supervisorConfig) { c.maxFollowDuration = 30 * time.Second })

	r := ts.startHelper("exits-mid-follow", "echo", "3", "50", "working")

	stream := &recordingStream{}
	started := time.Now()
	require.NoError(t, ts.streamLogs(context.Background(), r, logRequest{
		sel:       selector{tail: 10},
		follow:    true,
		followFor: 30 * time.Second,
	}, stream))
	elapsed := time.Since(started)

	require.Less(t, elapsed, 25*time.Second, "the follow should end on the exit, not on the deadline")
	require.NotNil(t, stream.summary)
	require.False(t, stream.summary.GetFollowDeadlineReached())
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_EXITED, stream.summary.GetState(),
		"the summary carries the final state")
}

func TestTwoConcurrentFollowersBothReceiveOutput(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t, func(c *supervisorConfig) { c.maxFollowDuration = 5 * time.Second })

	r := ts.startHelper("two-followers", "echo", "20", "20", "broadcast")

	var wg sync.WaitGroup
	streams := []*recordingStream{{}, {}}
	for _, s := range streams {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ts.streamLogs(context.Background(), r, logRequest{
				sel:       selector{tail: 1},
				follow:    true,
				followFor: 3 * time.Second,
			}, s)
		}()
	}
	wg.Wait()

	for i, s := range streams {
		require.Positive(t, s.count(), "follower %d received nothing", i)
		require.Contains(t, strings.Join(s.texts(), "\n"), "broadcast 19", "follower %d", i)
	}
}

func TestFollowStopsWhenTheCallerHangsUp(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t, func(c *supervisorConfig) { c.maxFollowDuration = 30 * time.Second })

	r := ts.startHelper("hangup", "silent")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- ts.streamLogs(ctx, r, logRequest{
			sel: selector{tail: 10}, follow: true, followFor: 30 * time.Second,
		}, &recordingStream{})
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("a follow whose caller hung up should return at once")
	}
	require.True(t, isLive(r.currentState()), "and the process keeps running")
}

func TestTailSinceAndFilterCompose(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	r := ts.startHelper("composing", "echo", "20", "10", "item")
	waitState(t, r, 20*time.Second, sandboxdv1.ProcessState_PROCESS_STATE_EXITED)
	waitForLine(t, r, 5*time.Second, "item 19")

	all := r.buf.ringLines()
	require.GreaterOrEqual(t, len(all), 20)

	t.Run("tail_lines", func(t *testing.T) {
		stream := &recordingStream{}
		require.NoError(t, ts.streamLogs(context.Background(), r, logRequest{sel: selector{tail: 3}}, stream))
		require.Equal(t, []string{"item 17", "item 18", "item 19"}, stream.texts())
	})

	t.Run("filter_pattern", func(t *testing.T) {
		stream := &recordingStream{}
		require.NoError(t, ts.streamLogs(context.Background(), r, logRequest{
			sel: selector{tail: 100, filter: regexp.MustCompile(`item 1[0-2]$`)},
		}, stream))
		require.Equal(t, []string{"item 10", "item 11", "item 12"}, stream.texts())
	})

	t.Run("since", func(t *testing.T) {
		// Everything at or after the tenth line's timestamp.
		var pivot time.Time
		for _, line := range all {
			if line.Text == "item 10" {
				pivot = line.At
			}
		}
		require.False(t, pivot.IsZero())

		stream := &recordingStream{}
		require.NoError(t, ts.streamLogs(context.Background(), r, logRequest{
			sel: selector{tail: 100, since: pivot},
		}, stream))
		require.NotContains(t, stream.texts(), "item 9")
		require.Contains(t, stream.texts(), "item 10")
	})

	t.Run("all three together", func(t *testing.T) {
		var pivot time.Time
		for _, line := range all {
			if line.Text == "item 5" {
				pivot = line.At
			}
		}
		stream := &recordingStream{}
		require.NoError(t, ts.streamLogs(context.Background(), r, logRequest{
			sel: selector{tail: 2, since: pivot, filter: regexp.MustCompile(`item 1\d$`)},
		}, stream))
		require.Equal(t, []string{"item 18", "item 19"}, stream.texts())
	})
}

// TestLongLinesAreSplitNotDropped: a process emitting a minified bundle on one
// line must not lose it, and a reader must be able to tell the pieces apart
// from a process that genuinely emitted short lines.
func TestLongLinesAreSplitNotDropped(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	const size = maxLineBytes*2 + 500
	r := ts.startHelper("long-line", "longline", fmt.Sprint(size))
	waitState(t, r, 10*time.Second, sandboxdv1.ProcessState_PROCESS_STATE_EXITED)

	waitFor(t, 10*time.Second, "the whole long line to be captured", func() bool {
		total := 0
		for _, line := range r.buf.ringLines() {
			total += len(line.Text)
		}
		return total >= size
	})

	stream := &recordingStream{}
	require.NoError(t, ts.streamLogs(context.Background(), r, logRequest{sel: selector{tail: 100}}, stream))

	var joined strings.Builder
	continued := 0
	for i, line := range stream.lines {
		if line.GetStream() != sandboxdv1.Stream_STREAM_STDOUT {
			continue
		}
		joined.WriteString(line.GetText())
		if line.GetContinued() {
			continued++
			require.Less(t, i, len(stream.lines)-1, "a continued line must be followed by its continuation")
		}
		require.LessOrEqual(t, len(line.GetText()), maxLineBytes, "no line may exceed the cap")
	}
	require.Equal(t, 2, continued, "a line of %d bytes splits into three pieces", size)
	require.Equal(t, size, joined.Len(), "the pieces must reassemble into the original line")
	require.Equal(t, strings.Repeat("x", size), joined.String())
}

func TestGetProcessLogsValidatesItsRequest(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)

	err := svc.GetProcessLogs(&sandboxdv1.GetProcessLogsRequest{ProcessId: ""}, nil)
	require.Error(t, err)

	err = svc.GetProcessLogs(&sandboxdv1.GetProcessLogsRequest{ProcessId: "missing-1234"}, nil)
	require.Error(t, err)
}

// TestGetProcessLogsThroughTheService exercises the request translation:
// defaults, the RE2 compile, and the clamp.
func TestGetProcessLogsThroughTheService(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, func(c *supervisorConfig) { c.maxFollowDuration = 300 * time.Millisecond })

	start, err := svc.StartProcess(context.Background(), &sandboxdv1.StartProcessRequest{
		Argv: helperArgv(t, "echo", "5", "0", "served"),
		Name: "served",
		Env:  helperEnviron(),
	})
	require.NoError(t, err)

	r, ok := svc.sup.lookup(start.GetStatus().GetProcessId())
	require.True(t, ok)
	waitForLine(t, r, 10*time.Second, "served 4")

	stream := &fakeServerStream{recordingStream: &recordingStream{}, ctx: context.Background()}
	require.NoError(t, svc.GetProcessLogs(&sandboxdv1.GetProcessLogsRequest{
		ProcessId:      start.GetStatus().GetProcessId(),
		TailLines:      2,
		FilterPattern:  `served \d`,
		Follow:         true,
		FollowDuration: durationpb.New(time.Hour),
		Since:          timestamppb.New(time.Now().Add(-time.Hour)),
	}, stream))

	require.Equal(t, []string{"served 3", "served 4"}, stream.texts())
	require.True(t, stream.summary.GetFollowDeadlineReached())

	// A bad filter is the caller's mistake, reported as one.
	err = svc.GetProcessLogs(&sandboxdv1.GetProcessLogsRequest{
		ProcessId:     start.GetStatus().GetProcessId(),
		FilterPattern: "([unclosed",
	}, stream)
	require.Error(t, err)
}

func TestSupervisorNotesAreNeitherStdoutNorStderr(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	r := ts.startHelper("noted", "silent")
	r.buf.note("supervisor: something happened")

	both := &recordingStream{}
	require.NoError(t, ts.streamLogs(context.Background(), r, logRequest{sel: selector{tail: 100}}, both))
	require.Contains(t, both.texts(), "supervisor: something happened")

	// A caller asking only for what the process itself said does not get them.
	onlyStdout := &recordingStream{}
	require.NoError(t, ts.streamLogs(context.Background(), r,
		logRequest{sel: selector{tail: 100, stream: sandboxdv1.Stream_STREAM_STDOUT}}, onlyStdout))
	require.NotContains(t, onlyStdout.texts(), "supervisor: something happened")
}

func TestSplitLine(t *testing.T) {
	t.Parallel()
	require.Equal(t, []string{"short"}, splitLine("short"))
	require.Equal(t, []string{""}, splitLine(""))

	long := strings.Repeat("a", maxLineBytes+1)
	parts := splitLine(long)
	require.Len(t, parts, 2)
	require.Len(t, parts[0], maxLineBytes)
	require.Len(t, parts[1], 1)
	require.Equal(t, long, strings.Join(parts, ""))
}

// fakeServerStream adapts the recorder to the generated streaming interface, so
// the service-level tests exercise the same method a gRPC client would call.
type fakeServerStream struct {
	*recordingStream
	ctx context.Context
	grpcServerStreamStub
}

func (s *fakeServerStream) Context() context.Context { return s.ctx }

// TestASlowFollowerIsDroppedAndTold covers the other half of the drop
// accounting. The retention shortfall in the million-line test is what a reader
// missed because the buffer turned over; this is what one particular follower
// missed because it could not keep up, which is counted per follower and
// reported on the next line it does receive.
func TestASlowFollowerIsDroppedAndTold(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t, func(c *supervisorConfig) { c.maxFollowDuration = 5 * time.Second })

	stream := &recordingStream{}
	// A follower that takes a millisecond per line cannot keep up with a
	// process emitting fifty thousand of them.
	stream.onLine = func(*sandboxdv1.LogLine) { time.Sleep(time.Millisecond) }

	r := ts.startHelper("outruns-its-reader", "spew", "50000")

	require.NoError(t, ts.streamLogs(context.Background(), r, logRequest{
		sel:       selector{tail: 1},
		follow:    true,
		followFor: 2 * time.Second,
	}, stream))

	require.NotNil(t, stream.summary)
	require.Positive(t, stream.summary.GetLinesDropped(),
		"a follower that fell behind must be told how much it missed")

	var reported uint64
	for _, line := range stream.lines {
		reported += line.GetDroppedBefore()
	}
	require.Positive(t, reported, "the gap has to be visible inline, not only in the summary")
}

// TestListeningPortsAreReportedFromTheLivePID asserts the wiring, not the
// platform read: ListeningPorts is best effort by contract — it shells out to
// lsof on macOS and returns nothing when lsof is absent — so the assertion is
// that the status carries whatever the platform reports for that pid, and that
// it is read live rather than cached from before the bind.
func TestListeningPortsAreReportedFromTheLivePID(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	port := freePort(t)
	r := ts.startHelper("binds-a-port", "listen", "0", strconv.Itoa(port))
	waitFor(t, 20*time.Second, "the helper to bind its port", func() bool {
		return dialLoopback(context.Background(), uint32(port), 200*time.Millisecond) //nolint:gosec // a port is in range by construction
	})

	pid := int(r.status().GetPid())
	expected, err := platform.ListeningPorts(pid)
	if err != nil || len(expected) == 0 {
		t.Skipf("this host cannot enumerate listening ports (err=%v); the field is documented as best effort", err)
	}
	require.Contains(t, expected, uint32(port))                               //nolint:gosec // a port is in range by construction
	require.Subset(t, r.status().GetListeningPorts(), []uint32{uint32(port)}, //nolint:gosec // a port is in range by construction
		"the status must report the ports the platform can see for the live pid")

	// An exited process reports none: the field describes a live process, and a
	// stale answer is worse than an empty one.
	_, err = ts.gracefulStop(r, time.Second, true, true)
	require.NoError(t, err)
	require.Empty(t, r.status().GetListeningPorts())
}
