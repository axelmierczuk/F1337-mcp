package process

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
)

// Why a supervised process writes to a file rather than to a pipe.
//
// The obvious capture is a pipe from the child to the agent. It is also wrong
// here, for one reason: the read end dies with the agent. A supervised process
// exists precisely to outlive an agent upgrade, and after the restart the pipe
// is gone — the process either takes a SIGPIPE on its next write or writes into
// a closed descriptor, and either way the agent can never capture another line
// from it. #15 requires the opposite: a re-adopted process's logs keep growing.
//
// So the child's stdout and stderr are ordinary files, opened by the agent and
// inherited by the child. They survive the agent, the child keeps appending to
// them across a restart, and the agent re-opens them at the recorded offset and
// carries on. The cost is that the agent tails rather than reads: it polls for
// new bytes instead of blocking on a descriptor. The poll backs off from
// tailPollMin to tailPollMax while a process is quiet, so an idle fleet costs
// nothing measurable, and a chatty one is read at the fast interval.
//
// The structured, rotating history in logbuf.go is written by the agent from
// what it tails. These raw files are transport, not history.

// chunkBytes is how much the tailer reads per syscall.
const chunkBytes = 32 * 1024

// capture owns one process's output files and the goroutines that turn them
// into log lines.
type capture struct {
	dir string
	buf *logBuffer

	stdout *streamTail
	stderr *streamTail

	rawCap      int64
	pollMin     time.Duration
	pollMax     time.Duration
	drainWindow time.Duration

	stop      chan struct{}
	wg        sync.WaitGroup
	stopOnce  sync.Once
	closeOnce sync.Once
}

// streamTail follows one raw capture file.
type streamTail struct {
	path   string
	stream sandboxdv1.Stream

	r *os.File
	// offset is written by the tailer goroutine and read by the persist path,
	// which runs on whichever goroutine performed a state transition. Atomic
	// rather than mutex-guarded because it is one word, read far more often
	// than it is written, and on the hot path of every read cycle.
	offset atomic.Int64

	// partial holds bytes read since the last newline. It is capped at
	// maxLineBytes: a process that never emits a newline is split into
	// continued lines rather than buffered until the agent runs out of memory.
	partial []byte
}

func newStreamTail(path string, stream sandboxdv1.Stream, r *os.File, offset int64) *streamTail {
	t := &streamTail{path: path, stream: stream, r: r}
	t.offset.Store(offset)
	return t
}

// rawPaths returns the two capture files inside a process's directory.
func rawPaths(dir string) (stdout, stderr string) {
	return filepath.Join(dir, "stdout.raw"), filepath.Join(dir, "stderr.raw")
}

// openCaptureFiles creates the files the child will write to and returns them
// open for writing. The caller hands them to exec.Cmd and closes its own
// handles once the child has them; nothing in the agent writes to them again.
//
// truncate is set for a fresh spawn and clear for a re-adoption, where the
// process is already writing to these files at an offset the agent recorded.
func openCaptureFiles(dir string, truncate bool) (stdout, stderr *os.File, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("process: create log directory %s: %w", dir, err)
	}
	outPath, errPath := rawPaths(dir)
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if truncate {
		flags |= os.O_TRUNC
	}
	stdout, err = os.OpenFile(outPath, flags, 0o600) //nolint:gosec // path is the agent's own state directory
	if err != nil {
		return nil, nil, fmt.Errorf("process: open %s: %w", outPath, err)
	}
	stderr, err = os.OpenFile(errPath, flags, 0o600) //nolint:gosec // path is the agent's own state directory
	if err != nil {
		_ = stdout.Close()
		return nil, nil, fmt.Errorf("process: open %s: %w", errPath, err)
	}
	return stdout, stderr, nil
}

// newCapture opens the agent's read handles on a process's capture files and
// starts following them from the given offsets.
func newCapture(dir string, buf *logBuffer, offsets [2]int64, rawCap int64, pollMin, pollMax, drainWindow time.Duration) (*capture, error) {
	outPath, errPath := rawPaths(dir)

	outFile, err := os.Open(outPath) //nolint:gosec // path is the agent's own state directory
	if err != nil {
		return nil, fmt.Errorf("process: follow %s: %w", outPath, err)
	}
	errFile, err := os.Open(errPath) //nolint:gosec // path is the agent's own state directory
	if err != nil {
		_ = outFile.Close()
		return nil, fmt.Errorf("process: follow %s: %w", errPath, err)
	}

	return &capture{
		dir:         dir,
		buf:         buf,
		stdout:      newStreamTail(outPath, sandboxdv1.Stream_STREAM_STDOUT, outFile, offsets[0]),
		stderr:      newStreamTail(errPath, sandboxdv1.Stream_STREAM_STDERR, errFile, offsets[1]),
		rawCap:      rawCap,
		pollMin:     pollMin,
		pollMax:     pollMax,
		drainWindow: drainWindow,
		stop:        make(chan struct{}),
	}, nil
}

// start launches one goroutine per stream. exited is closed by the supervisor
// when the process has been reaped; the tailers drain what is left and return.
func (c *capture) start(exited <-chan struct{}) {
	for _, t := range []*streamTail{c.stdout, c.stderr} {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.follow(t, exited)
		}()
	}
}

// close stops the tailers and waits for them. It is idempotent, and it is what
// keeps a supervisor's goroutine count proportional to its live processes
// rather than to every process it has ever run.
func (c *capture) close() {
	c.stopOnce.Do(func() { close(c.stop) })
	c.finish()
}

// finish waits for the tailers to end on their own — which they do once the
// process has been reaped and the drain window has passed — and releases the
// read handles. close is finish plus an explicit stop.
func (c *capture) finish() {
	c.wg.Wait()
	c.closeOnce.Do(func() {
		_ = c.stdout.r.Close()
		_ = c.stderr.r.Close()
	})
}

// offsets reports how far each tailer has consumed, for the persisted record.
// A re-adopting agent resumes from these rather than replaying output it has
// already captured.
func (c *capture) offsets() [2]int64 {
	return [2]int64{c.stdout.offset.Load(), c.stderr.offset.Load()}
}

// follow is one stream's read loop.
//
// It ends when the capture is stopped, or when the process has been reaped and
// either two consecutive reads came back empty or the drain window elapsed.
// The drain window is what stops a grandchild that inherited the capture file
// and keeps writing from holding the exit — and the state machine — open.
func (c *capture) follow(t *streamTail, exited <-chan struct{}) {
	poll := c.pollMin
	chunk := make([]byte, chunkBytes)
	drains := 0
	var drainUntil time.Time

	finish := func() {
		t.flushPartial(c.buf)
		_ = c.buf.flush()
	}

	for {
		select {
		case <-c.stop:
			finish()
			return
		default:
		}
		if drainUntil.IsZero() {
			select {
			case <-exited:
				drainUntil = time.Now().Add(c.drainWindow)
			default:
			}
		} else if time.Now().After(drainUntil) {
			finish()
			return
		}

		c.maybeTruncate(t)

		n, err := t.r.ReadAt(chunk, t.offset.Load())
		if n > 0 {
			t.offset.Add(int64(n))
			t.consume(c.buf, chunk[:n])
			// A failed flush loses on-disk history, which is not a reason to
			// stop capturing a running process. The ring buffer, which is what
			// a reader sees first, is unaffected.
			_ = c.buf.flush()
			poll = c.pollMin
			drains = 0
			continue
		}
		if err != nil && !errors.Is(err, io.EOF) {
			// The file was removed or became unreadable. There is nothing left
			// to follow.
			finish()
			return
		}

		if !drainUntil.IsZero() {
			drains++
			if drains > 1 {
				finish()
				return
			}
		}

		select {
		case <-c.stop:
			finish()
			return
		case <-time.After(poll):
		}
		if poll < c.pollMax {
			poll = min(poll*2, c.pollMax)
		}
	}
}

// consume turns freshly read bytes into log lines.
func (t *streamTail) consume(buf *logBuffer, data []byte) {
	now := time.Now()
	for len(data) > 0 {
		idx := bytes.IndexByte(data, '\n')
		if idx < 0 {
			t.partial = append(t.partial, data...)
			// A producer that never emits a newline still has its output
			// bounded: emit a continued line as soon as one chunk's worth has
			// accumulated.
			for len(t.partial) >= maxLineBytes {
				buf.append(t.stream, string(t.partial[:maxLineBytes]), now, true)
				t.partial = t.partial[maxLineBytes:]
			}
			return
		}
		t.partial = append(t.partial, data[:idx]...)
		data = data[idx+1:]
		t.emit(buf, string(t.partial), now)
		t.partial = t.partial[:0]
	}
}

// emit writes one complete line, splitting it if it is over the cap.
func (t *streamTail) emit(buf *logBuffer, text string, now time.Time) {
	text = strings.TrimSuffix(text, "\r")
	parts := splitLine(text)
	for i, part := range parts {
		buf.append(t.stream, part, now, i < len(parts)-1)
	}
}

// flushPartial emits whatever is left when the stream ends without a trailing
// newline, which is how most processes' last line arrives.
func (t *streamTail) flushPartial(buf *logBuffer) {
	if len(t.partial) == 0 {
		return
	}
	t.emit(buf, string(t.partial), time.Now())
	t.partial = t.partial[:0]
}

// maybeTruncate keeps the raw transport file from growing without bound.
//
// The file is appended to by a process the agent does not control, so it cannot
// be rotated the way the agent's own history file is: renaming it leaves the
// child writing to the renamed inode, and the child's descriptor cannot be
// replaced from outside. Truncating in place is the only lever, and it is the
// same one logrotate's copytruncate mode pulls.
//
// Two guards make the loss window as small as it can be made:
//
//   - Only when the tailer is between lines. A truncate with bytes pending in
//     partial would join half of one line to the start of the next.
//   - Only when the file's size equals what the tailer has consumed. A process
//     that is actively writing fails this check and the truncate is deferred to
//     the next cycle, which for a continuously chatty process means it happens
//     during one of the gaps every process has.
//
// What remains is a write landing between the stat and the truncate. Those
// bytes are lost and, unlike a drop from the ring buffer or a follower's queue,
// the loss cannot be counted — the agent has no way to learn how much a
// descriptor it does not hold wrote in that instant. It is documented here
// rather than hidden. It is bounded by one write, which is the smallest that
// window can be made without a lever the OS does not offer.
//
// The size check is dropped once the file passes rawCap*rawHardCapFactor. A
// process that writes continuously never satisfies it, and "lossless but
// unbounded" is the wrong trade for a file on someone else's disk: past the
// hard ceiling the agent truncates anyway. That discard is a different thing
// from the race above and much larger — up to the whole gap between what the
// tailer has read and where the process has got to — but it is *knowable*, so
// it is measured and written into the process's own log rather than taken
// silently. #13 asks for a gap in the log to be visible rather than silent,
// and a gap the agent could have measured and did not is the one case that
// would not have been.
func (c *capture) maybeTruncate(t *streamTail) {
	offset := t.offset.Load()
	if c.rawCap <= 0 || offset < c.rawCap || len(t.partial) > 0 {
		return
	}
	info, err := os.Stat(t.path)
	if err != nil {
		return
	}
	if info.Size() != offset && info.Size() < c.rawCap*rawHardCapFactor {
		return
	}
	unread := info.Size() - offset
	if err := os.Truncate(t.path, 0); err != nil {
		return
	}
	t.offset.Store(0)
	if unread > 0 {
		c.buf.note(fmt.Sprintf(
			"supervisor: dropped %d bytes of %s output that had not been read yet; the process is writing faster than the agent can capture it and its capture file had passed the %d-byte ceiling",
			unread, streamLabel(t.stream), c.rawCap*rawHardCapFactor))
	}
}

// streamLabel names a stream the way a reader of the log expects to see it.
func streamLabel(s sandboxdv1.Stream) string {
	switch s {
	case sandboxdv1.Stream_STREAM_STDOUT:
		return "stdout"
	case sandboxdv1.Stream_STREAM_STDERR:
		return "stderr"
	case sandboxdv1.Stream_STREAM_UNSPECIFIED:
		return "supervisor"
	default:
		return "unknown"
	}
}

// rawHardCapFactor is how far past rawCap a capture file may grow before the
// agent truncates it without waiting for the process to pause.
const rawHardCapFactor = 8
