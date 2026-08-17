package process

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/platform"
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
	ts := newTestSupervisor(t, func(c *testSupervisorOptions) { c.ringBufferLines = 10 })

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
	ts := newTestSupervisor(t, func(c *testSupervisorOptions) { c.retainSegments = 2 })

	// A thousand lines of that length against a 16 KiB cap is a dozen
	// rotations, which proves the rotation and the pruning as well as three
	// thousand did and costs a third of the time on a runner that is already
	// running every other package's tests.
	spec := ts.helperSpec("rotating", "echo", "1000", "0", "rotate-me-with-some-padding-to-make-the-record-larger")
	spec.maxLogBytes = 16 * 1024
	r, err := ts.start(spec, false)
	require.NoError(t, err)

	waitState(t, r, 60*time.Second, sandboxdv1.ProcessState_PROCESS_STATE_EXITED)
	// Three thousand lines through the tailer, the rotation and the ring, on a
	// runner already running every other package's tests. The budget is how
	// long the assertion is willing to wait, not what it asserts.
	waitForLine(t, r, 60*time.Second, "rotate-me-with-some-padding-to-make-the-record-larger 999")

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
	ts := newTestSupervisor(t, func(c *testSupervisorOptions) {
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

	// The process is never blocked on the agent, so it exits on its own. The
	// budget is generous because a million lines through a race-instrumented
	// binary on a shared four-vCPU runner is genuinely slow; what is under test
	// is that the process finishes at all rather than waiting on a reader, and
	// a supervisor that blocks it does not finish in three minutes either.
	waitState(t, r, 300*time.Second, sandboxdv1.ProcessState_PROCESS_STATE_EXITED)
	require.Less(t, time.Since(started), 300*time.Second)

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
	ts := newTestSupervisor(t, func(c *testSupervisorOptions) { c.maxFollowDuration = 250 * time.Millisecond })

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
	ts := newTestSupervisor(t, func(c *testSupervisorOptions) { c.maxFollowDuration = 30 * time.Second })

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
	ts := newTestSupervisor(t, func(c *testSupervisorOptions) { c.maxFollowDuration = 5 * time.Second })

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
	ts := newTestSupervisor(t, func(c *testSupervisorOptions) { c.maxFollowDuration = 30 * time.Second })

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

	// 40ms between lines: wide enough that the agent's read timestamps are not
	// all the same on a host whose clock ticks every 15ms.
	r := ts.startHelper("composing", "echo", "20", "40", "item")
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
		// Timestamps are the agent's read times, and a batch of lines read in
		// one go shares one. On a host with a coarse clock several consecutive
		// lines therefore carry the same instant, and since is inclusive — so
		// "everything at or after item 10's timestamp" legitimately includes
		// the lines that were read alongside it. Asserting that a particular
		// neighbour is absent asserts the clock's resolution, not the filter.
		var pivot time.Time
		for _, line := range all {
			if line.Text == "item 10" {
				pivot = line.At
			}
		}
		require.False(t, pivot.IsZero())

		// A line that is strictly older than the pivot, chosen from the data
		// rather than assumed to exist at a particular index.
		var older logLine
		for _, line := range all {
			if line.At.Before(pivot) {
				older = line
			}
		}
		require.NotEmpty(t, older.Text, "no line was read before item 10; the helper's gaps are too small")

		stream := &recordingStream{}
		require.NoError(t, ts.streamLogs(context.Background(), r, logRequest{
			sel: selector{tail: 100, since: pivot},
		}, stream))

		require.Contains(t, stream.texts(), "item 10")
		require.NotContains(t, stream.texts(), older.Text,
			"a line read strictly before the pivot must be excluded")
		for _, line := range stream.lines {
			require.False(t, line.GetTimestamp().AsTime().Before(pivot),
				"line %q predates the since filter", line.GetText())
		}
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

// gatedStream parks a follow inside its first Send until the test releases it,
// which is how the test puts the process's exit and the follower's next look at
// the state in a fixed order rather than a raced one.
type gatedStream struct {
	*recordingStream
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *gatedStream) Send(resp *sandboxdv1.GetProcessLogsResponse) error {
	g.once.Do(func() {
		close(g.entered)
		<-g.release
	})
	return g.recordingStream.Send(resp)
}

// TestFollowDeliversTheFinalLinesOfAProcessThatExits.
//
// The supervisor lets the tailers finish reading what the process wrote in its
// last breath *before* it records the exit, so that a follow ending on the exit
// carries those lines — they are what make the crash diagnosable from the log
// rather than only from the exit code. Ending the follow on the terminal state
// alone throws them away again: by the time the state is observable they are
// already sitting in this follower's queue, and the busier the host, the more
// of them there are.
func TestFollowDeliversTheFinalLinesOfAProcessThatExits(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t, func(c *testSupervisorOptions) { c.maxFollowDuration = 10 * time.Second })

	r := ts.startHelper("last-words", "silent")
	// One line for the replay to send, so the follow parks with its
	// subscription already taken and nothing yet delivered from it.
	r.buf.note("first")

	gate := &gatedStream{
		recordingStream: &recordingStream{},
		entered:         make(chan struct{}),
		release:         make(chan struct{}),
	}
	done := make(chan error, 1)
	go func() {
		done <- ts.streamLogs(context.Background(), r, logRequest{
			sel: selector{tail: 10}, follow: true, followFor: 5 * time.Second,
		}, gate)
	}()
	<-gate.entered

	// The rest of what the process had to say, and then its exit, both while
	// the follower is between reads of its queue.
	r.buf.note("last words")
	_, err := ts.gracefulStop(r, 2*time.Second, true, true)
	require.NoError(t, err)
	require.True(t, isTerminal(r.currentState()), "state was %s", stateName(r.currentState()))

	close(gate.release)
	require.NoError(t, <-done)

	require.Contains(t, gate.texts(), "last words",
		"a follow that ends on the exit must still carry what the process wrote before it")
	require.NotNil(t, gate.summary)
	require.False(t, gate.summary.GetFollowDeadlineReached(), "it ended on the exit, not on the deadline")
	require.EqualValues(t, len(gate.texts()), gate.summary.GetLinesReturned(),
		"the summary must count the lines the drain sent")
}

// TestDropsAfterTheLastDeliveredLineAreStillCounted.
//
// A drop count rides on the next line the follower is handed. A follower that
// falls behind and never catches up is handed no next line — so the drops
// after its last delivery have nothing to ride on, and they are the bulk of
// them. The summary that omits them reports a hole smaller than the hole, and
// a wrong number is worse than none because it looks like an answer.
//
// Everything here happens while the follower is parked, so the arithmetic is
// exact rather than a race: 256 lines fit in its queue, every line after that
// is a drop, and none of them will ever be attached to anything.
func TestDropsAfterTheLastDeliveredLineAreStillCounted(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t, func(c *testSupervisorOptions) { c.maxFollowDuration = 10 * time.Second })

	r := ts.startHelper("outran-its-reader-completely", "silent")
	r.buf.note("first")

	gate := &gatedStream{
		recordingStream: &recordingStream{},
		entered:         make(chan struct{}),
		release:         make(chan struct{}),
	}
	done := make(chan error, 1)
	go func() {
		done <- ts.streamLogs(context.Background(), r, logRequest{
			sel: selector{tail: 10}, follow: true, followFor: 5 * time.Second,
		}, gate)
	}()
	<-gate.entered

	const beyondTheQueue = 500
	for i := range subscriberQueue + beyondTheQueue {
		r.buf.note(fmt.Sprintf("flood %d", i))
	}
	_, err := ts.gracefulStop(r, 2*time.Second, true, true)
	require.NoError(t, err)

	close(gate.release)
	require.NoError(t, <-done)

	require.NotNil(t, gate.summary)
	require.GreaterOrEqual(t, gate.summary.GetLinesDropped(), uint64(beyondTheQueue),
		"the follower missed at least %d lines and has to be told so, even though no line it received could carry the count",
		beyondTheQueue)
}

// TestReplayDoesNotReadTheWholeHistoryIntoMemory.
//
// The on-disk history is the one thing in this package with no bound on it: a
// process may hold max_log_bytes times retain+1 segments, and answering one
// GetProcessLogs by reading all of it means a single call can allocate more
// than the agent's whole working set. It is not an exotic request either — the
// disk is read whenever the ring cannot cover the caller's tail, which any
// filter_pattern that matches rarely guarantees on every call.
func TestReplayDoesNotReadTheWholeHistoryIntoMemory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "log.jsonl")

	const onDisk = 3 * maxReplayLines
	f, err := os.Create(path) //nolint:gosec // the test's own temp directory
	require.NoError(t, err)
	w := bufio.NewWriterSize(f, 1<<20)
	for i := range onDisk {
		data, err := json.Marshal(logLine{
			Seq:    uint64(i), //nolint:gosec // a loop index below onDisk
			Stream: sandboxdv1.Stream_STREAM_STDOUT,
			At:     time.Now(),
			Text:   fmt.Sprintf("history %d", i),
		})
		require.NoError(t, err)
		_, err = w.Write(append(data, '\n'))
		require.NoError(t, err)
	}
	require.NoError(t, w.Flush())
	require.NoError(t, f.Close())

	file, err := newRotatingFile(path, 1<<30, 3)
	require.NoError(t, err)
	buf := newLogBuffer(8, file)
	t.Cleanup(func() { _ = buf.close() })

	// A ring holding only the newest handful, so replay knows there is history
	// below it and goes to disk for the rest.
	const inRing = 8
	restored := make([]logLine, 0, inRing)
	for i := onDisk; i < onDisk+inRing; i++ {
		restored = append(restored, logLine{
			Seq:    uint64(i), //nolint:gosec // a loop index below onDisk+inRing
			Stream: sandboxdv1.Stream_STREAM_STDOUT,
			At:     time.Now(),
			Text:   fmt.Sprintf("history %d", i),
		})
	}
	buf.restore(restored, 0)

	r := &record{buf: buf}
	lines, _ := r.replay(selector{tail: onDisk}, buf.ringLines())

	require.NotEmpty(t, lines, "the history is still read; it is only bounded")
	require.LessOrEqual(t, len(lines), maxReplayLines+inRing,
		"one call materialised %d of the %d lines on disk; the agent's heap is not the size of a process's log",
		len(lines), onDisk)
	require.Equal(t, fmt.Sprintf("history %d", onDisk+inRing-1), lines[len(lines)-1].Text,
		"and it is the newest lines that are kept")
}

// TestRawCaptureTruncationReportsWhatItDiscarded.
//
// The transport file is truncated in place because nothing else can bound a
// file a process the agent does not control keeps appending to. Normally that
// happens when the tailer has caught up and nothing is lost. Past the hard
// ceiling it happens anyway, and then it throws away everything between where
// the tailer got to and where the process got to — which, unlike the
// stat-to-truncate race, is a quantity the agent knows. #13 asks for a gap in
// the log to be visible rather than silent, and a measurable gap taken
// silently is the only case that would not have been.
func TestRawCaptureTruncationReportsWhatItDiscarded(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outPath, errPath := rawPaths(dir)

	const rawCap int64 = 4096
	const unread int64 = 1000
	size := rawCap*rawHardCapFactor + unread
	require.NoError(t, os.WriteFile(outPath, bytes.Repeat([]byte("x"), int(size)), 0o600))
	require.NoError(t, os.WriteFile(errPath, nil, 0o600))

	buf := newLogBuffer(64, nil)
	capt, err := newCapture(dir, buf, [2]int64{}, rawCap, time.Millisecond, time.Millisecond, time.Millisecond)
	require.NoError(t, err)
	t.Cleanup(capt.close)

	// The tailer is rawCap bytes in and the process is way past the ceiling:
	// the branch that discards rather than waits.
	capt.stdout.offset.Store(rawCap)
	capt.maybeTruncate(capt.stdout)

	info, err := os.Stat(outPath)
	require.NoError(t, err)
	require.Zero(t, info.Size(), "past the hard ceiling the file is truncated without waiting to catch up")
	require.EqualValues(t, 0, capt.stdout.offset.Load())

	var noted string
	for _, line := range buf.ringLines() {
		if strings.Contains(line.Text, "had not been read yet") {
			noted = line.Text
		}
	}
	require.NotEmpty(t, noted, "a discard the agent measured has to be in the log, not only in this file's comments")
	require.Contains(t, noted, strconv.FormatInt(size-rawCap, 10), "and it has to say how much")
	require.Contains(t, noted, "stdout", "and which stream lost it")
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
	svc := newTestService(t, func(c *testSupervisorOptions) { c.maxFollowDuration = 300 * time.Millisecond })

	// The helper lingers well past maxFollowDuration after its last line. Without
	// that the process exits while the lines are still being drained, the follow
	// ends because there is nothing left to follow, and the deadline below is
	// never what stopped it -- which is a property of how fast the machine tore
	// the process down, not of the clamp this test is about.
	start, err := svc.StartProcess(context.Background(), &sandboxdv1.StartProcessRequest{
		Argv: helperArgv(t, "echo", "5", "0", "served", "10000"),
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
	// The request asked to follow for an hour; returning at all is the clamp.
	require.True(t, stream.summary.GetFollowDeadlineReached())

	// A bad filter is the caller's mistake, reported as one.
	err = svc.GetProcessLogs(&sandboxdv1.GetProcessLogsRequest{
		ProcessId:     start.GetStatus().GetProcessId(),
		FilterPattern: "([unclosed",
	}, stream)
	require.Error(t, err)
}

// TestGetProcessLogsFollowEndsWhenTheProcessExits covers the other way a follow
// can end. A caller that asked to follow for an hour and got an answer in
// milliseconds needs to be able to tell "the deadline passed" from "there is
// nothing left to follow", because only the second means the logs are complete.
func TestGetProcessLogsFollowEndsWhenTheProcessExits(t *testing.T) {
	t.Parallel()
	svc := newTestService(t, func(c *testSupervisorOptions) { c.maxFollowDuration = time.Hour })

	start, err := svc.StartProcess(context.Background(), &sandboxdv1.StartProcessRequest{
		Argv: helperArgv(t, "echo", "3", "0", "done"),
		Name: "done",
		Env:  helperEnviron(),
	})
	require.NoError(t, err)

	r, ok := svc.sup.lookup(start.GetStatus().GetProcessId())
	require.True(t, ok)
	waitState(t, r, 10*time.Second, sandboxdv1.ProcessState_PROCESS_STATE_EXITED)

	stream := &fakeServerStream{recordingStream: &recordingStream{}, ctx: context.Background()}
	require.NoError(t, svc.GetProcessLogs(&sandboxdv1.GetProcessLogsRequest{
		ProcessId:      start.GetStatus().GetProcessId(),
		Follow:         true,
		FollowDuration: durationpb.New(time.Hour),
	}, stream))

	// It returned rather than following a dead process for an hour, and it said
	// which of the two reasons that was.
	require.False(t, stream.summary.GetFollowDeadlineReached())
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_EXITED, stream.summary.GetState())
	require.Equal(t, []string{"done 0", "done 1", "done 2"}, stream.texts())
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
//
// This one failed on windows-latest with a drop count of zero, and the cause is
// not Windows. A drop count travels on the *next* line the follower is handed,
// so the counts sit at the back of a 256-deep queue behind the lines that were
// delivered before the queue ever filled. A follower that has not worked
// through those 256 has been told nothing yet — and on Windows, where a
// one-millisecond sleep is nearer fifteen, it never does before the process
// finishes. Two things had to be true for the count to survive that, and
// neither was:
//
//   - a follow ending on the process's exit has to drain what is already
//     queued for it, rather than returning on the state alone; and
//   - the drops accumulated after the last delivery have to be counted too,
//     because no line will ever carry them.
//
// Both are in the summary's contract, and the second is the larger number.
func TestASlowFollowerIsDroppedAndTold(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t, func(c *testSupervisorOptions) { c.maxFollowDuration = 5 * time.Second })

	stream := &recordingStream{}
	// A follower that takes a millisecond per line cannot keep up with a
	// process emitting fifty thousand of them.
	stream.onLine = func(*sandboxdv1.LogLine) { time.Sleep(time.Millisecond) }

	// Fifty thousand lines spread over about four seconds, so the flood is
	// still flooding when the two-second follow ends. A single burst finishes
	// in milliseconds on an idle machine and in rather more than two seconds on
	// a loaded one, and a follower cannot fall behind a process that finished
	// before it subscribed — which is the whole of why this test used to fail
	// on Windows and once in five on Linux.
	r := ts.startHelper("outruns-its-reader", "spew", "1000", "80", "50")

	require.NoError(t, ts.streamLogs(context.Background(), r, logRequest{
		sel:       selector{tail: 1},
		follow:    true,
		followFor: 2 * time.Second,
	}, stream))

	require.NotNil(t, stream.summary)
	require.Positive(t, stream.summary.GetLinesDropped(),
		"a follower that fell behind must be told how much it missed")
	// The inline half of the same guarantee — that a gap shows up on the line
	// after it, not only in the summary — is asserted by
	// TestADroppedRunIsReportedOnTheNextLineTheFollowerReceives, which induces
	// the drops rather than racing a process for them. Asserting it here as
	// well is what made this test fail on Windows for a reason that had nothing
	// to do with the drop accounting: whether any *delivered* line carries a
	// count depends on how far through a 256-deep queue the follower got before
	// the process finished, and a one-millisecond sleep is nearer fifteen there.
}

// TestADroppedRunIsReportedOnTheNextLineTheFollowerReceives is the inline half
// of the drop contract, with the timing taken out of it: the buffer is driven
// directly, so the queue is filled, overrun and read at exactly the points the
// assertions describe.
func TestADroppedRunIsReportedOnTheNextLineTheFollowerReceives(t *testing.T) {
	t.Parallel()

	buf := newLogBuffer(4, nil)
	_, sub := buf.snapshot()

	// Exactly fills the follower's queue. Nothing has been dropped yet.
	for i := range subscriberQueue {
		buf.note(fmt.Sprintf("queued %d", i))
	}
	// And now it overruns. These cannot be delivered, so they are counted
	// against this follower and wait for a line to travel on.
	const lost = 50
	for i := range lost {
		buf.note(fmt.Sprintf("lost %d", i))
	}

	first := <-sub.ch
	require.Equal(t, "queued 0", first.line.Text)
	require.Zero(t, first.dropped, "nothing had been dropped when this line was queued")

	// One slot is free again, so the next line fits — and carries the whole run
	// of drops that happened while there was no room for it.
	buf.note("after the gap")

	var carried uint64
	var found bool
	for range subscriberQueue + 1 {
		d := <-sub.ch
		if d.line.Text == "after the gap" {
			carried, found = d.dropped, true
			break
		}
		require.Zero(t, d.dropped, "line %q is from before the gap", d.line.Text)
	}
	require.True(t, found, "the line after the gap must have been delivered")
	require.EqualValues(t, lost, carried,
		"the gap has to be visible on the line that follows it, and it has to be the whole gap")
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
