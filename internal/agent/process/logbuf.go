package process

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

// maxLineBytes is the longest single log line the supervisor will emit. A
// process that writes more than this without a newline — a progress bar, a
// minified bundle, a base64 blob — has its output split into several lines
// rather than buffered until it runs the agent out of memory.
//
// Every piece but the last carries continued=true, so a reader can tell a split
// from a process that genuinely emitted short lines.
const maxLineBytes = 16 * 1024

// subscriberQueue is how many lines a follower may fall behind by before the
// supervisor starts dropping for it.
//
// It is deliberately small. The point of a queue here is to absorb a burst
// while a slow gRPC stream catches up, not to become a second unbounded buffer:
// a follower that cannot keep up with a process emitting a million lines is
// going to be told about a gap either way, and the only question is how much
// heap the agent buys before telling it.
const subscriberQueue = 256

// logLine is one captured line. Timestamps are taken by the agent when it reads
// the line, not by the process that wrote it — under load the agent's read lags
// the write slightly, and that is fine. Do not "fix" it by trusting a timestamp
// parsed out of the process's own output: half of them have no timestamp, and
// the other half are in the process's timezone rather than the agent's.
type logLine struct {
	Seq    uint64            `json:"seq"`
	Stream sandboxdv1.Stream `json:"stream"`
	At     time.Time         `json:"ts"`
	Text   string            `json:"text"`
	// Cont marks a line that was split because it exceeded maxLineBytes. The
	// next line is its continuation.
	Cont bool `json:"cont,omitempty"`
}

// delivery is a line handed to one follower, plus the number of lines that
// follower missed immediately before it. The drop count travels with the line
// rather than being read from the subscriber later, because by the time the
// follower reads it the counter has moved on.
type delivery struct {
	line    logLine
	dropped uint64
}

// subscriber is one live follower of a process's output — a GetProcessLogs
// call with follow set, or a log_pattern probe.
//
// A probe is an ordinary subscriber on purpose. It is the whole answer to "the
// probe must not consume the log stream": the buffer fans out to every
// subscriber and to the ring, so a matcher reading its own channel removes
// nothing from anyone else's view.
type subscriber struct {
	ch      chan delivery
	pending uint64 // lines dropped since the last successful delivery
}

// logBuffer is a process's captured output: a bounded in-memory ring for fast
// tailing, a size-capped rotating file for history that outlives the ring, and
// a fan-out to live followers.
//
// Appends never block. A full subscriber queue drops and counts; a full ring
// evicts its oldest line. That is the backpressure contract: the process on the
// other end of the pipe must never be held up by a slow reader, and the agent's
// heap must not grow to accommodate one.
type logBuffer struct {
	mu sync.Mutex

	ring     []logLine
	capLines int
	head     int // index of the oldest line when the ring is full
	size     int // lines currently in the ring

	nextSeq  uint64 // sequence the next appended line will take
	logBytes uint64 // total bytes of text captured, for ProcessStatus.log_bytes
	lastLine string // most recent line, for ProcessStatus.last_log_line
	evicted  uint64 // lines that have left the ring

	subs map[*subscriber]struct{}

	file *rotatingFile

	closed bool
}

func newLogBuffer(capLines int, file *rotatingFile) *logBuffer {
	if capLines <= 0 {
		capLines = 1
	}
	return &logBuffer{
		ring:     make([]logLine, capLines),
		capLines: capLines,
		subs:     map[*subscriber]struct{}{},
		file:     file,
	}
}

// append records one line and fans it out. It is called from the capture
// goroutines and must stay cheap: a mutex, a slice write, a buffered file
// write, and a non-blocking send per follower.
func (b *logBuffer) append(stream sandboxdv1.Stream, text string, at time.Time, cont bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}

	line := logLine{Seq: b.nextSeq, Stream: stream, At: at, Text: text, Cont: cont}
	b.nextSeq++
	b.logBytes += uint64(len(text))
	b.lastLine = text

	if b.size == b.capLines {
		b.ring[b.head] = line
		b.head = (b.head + 1) % b.capLines
		b.evicted++
	} else {
		b.ring[(b.head+b.size)%b.capLines] = line
		b.size++
	}

	if b.file != nil {
		// A write failure here is reported once by the caller of flush and then
		// tolerated: losing the on-disk history is bad, but stopping the capture
		// of a running process because a disk filled is worse.
		_ = b.file.write(line)
	}

	for sub := range b.subs {
		select {
		case sub.ch <- delivery{line: line, dropped: sub.pending}:
			sub.pending = 0
		default:
			sub.pending++
		}
	}
}

// note records a supervisor decision in the process's own log, tagged as
// neither stdout nor stderr.
//
// Restarts, backoff and giving up are the facts a reader needs most when
// looking at a process that is not running, and the log is where they look. A
// stream filter for stdout or stderr excludes these, so a caller who wants only
// what the process itself said still gets exactly that.
func (b *logBuffer) note(text string) {
	b.append(sandboxdv1.Stream_STREAM_UNSPECIFIED, text, time.Now(), false)
}

// flush pushes buffered file writes to the OS. The capture goroutines call it
// once per read batch, so a reader never trails the writer by more than one
// poll interval.
func (b *logBuffer) flush() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.file == nil {
		return nil
	}
	return b.file.flush()
}

// snapshot is the atomic pair a follower needs: everything currently retained
// in the ring, and a subscription that will carry everything after it.
//
// Taking them under one lock is what makes the log_pattern probe correct. A
// probe that subscribed and then read the ring separately would miss a line
// appended between the two calls — and the line it misses is exactly the
// "listening on :3000" it was waiting for, because a process that prints it
// immediately is the case the race needs.
func (b *logBuffer) snapshot() ([]logLine, *subscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()

	sub := &subscriber{ch: make(chan delivery, subscriberQueue)}
	if !b.closed {
		b.subs[sub] = struct{}{}
	} else {
		close(sub.ch)
	}
	return b.ringLinesLocked(), sub
}

// unsubscribe detaches a follower. It is safe to call twice.
func (b *logBuffer) unsubscribe(sub *subscriber) {
	if sub == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.subs, sub)
}

// ringLines returns the retained lines, oldest first.
func (b *logBuffer) ringLines() []logLine {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ringLinesLocked()
}

func (b *logBuffer) ringLinesLocked() []logLine {
	out := make([]logLine, 0, b.size)
	for i := range b.size {
		out = append(out, b.ring[(b.head+i)%b.capLines])
	}
	return out
}

// stats reports what ProcessStatus needs about the output so far.
func (b *logBuffer) stats() (bytes uint64, last string, produced uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.logBytes, b.lastLine, b.nextSeq
}

// oldestRetainedSeq is the sequence of the oldest line still in the ring, and
// whether the ring holds anything at all.
func (b *logBuffer) oldestRetainedSeq() (uint64, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.size == 0 {
		return b.nextSeq, false
	}
	return b.ring[b.head].Seq, true
}

// restore seeds the buffer from lines recovered off disk, which is how a
// re-adopted process keeps its history across an agent restart. The sequence
// counter resumes after the highest sequence seen, so a follower cannot be
// handed two different lines with the same number.
func (b *logBuffer) restore(lines []logLine, logBytes uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, line := range lines {
		if b.size == b.capLines {
			b.ring[b.head] = line
			b.head = (b.head + 1) % b.capLines
			b.evicted++
		} else {
			b.ring[(b.head+b.size)%b.capLines] = line
			b.size++
		}
		if line.Seq >= b.nextSeq {
			b.nextSeq = line.Seq + 1
		}
		b.lastLine = line.Text
	}
	b.logBytes = logBytes
}

// close stops fan-out and releases the file. Followers see their channels
// closed, which is what ends a follow on RemoveProcess rather than leaving the
// call to wait out its deadline against a process that no longer exists.
func (b *logBuffer) close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	for sub := range b.subs {
		close(sub.ch)
		delete(b.subs, sub)
	}
	if b.file == nil {
		return nil
	}
	return b.file.close()
}

// segments returns the on-disk history files, oldest first.
func (b *logBuffer) segments() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.file == nil {
		return nil
	}
	return b.file.segments()
}

// rotatingFile is the size-capped, pruned, on-disk copy of a process's output.
//
// It holds the agent's own structured record — one JSON object per line, with
// the stream, the agent's read time and the sequence number — rather than the
// raw bytes, because a reader coming back after the ring has turned over needs
// the same three facts a live follower gets. The raw capture files the process
// itself writes to are a different thing entirely; see tail.go.
type rotatingFile struct {
	path     string
	maxBytes int64
	retain   int

	f    *os.File
	w    *bufio.Writer
	size int64
}

func newRotatingFile(path string, maxBytes int64, retain int) (*rotatingFile, error) {
	if maxBytes <= 0 {
		maxBytes = 32 * 1024 * 1024
	}
	if retain < 1 {
		retain = 1
	}
	r := &rotatingFile{path: path, maxBytes: maxBytes, retain: retain}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *rotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // path is the agent's own state directory
	if err != nil {
		return fmt.Errorf("process: open log file %s: %w", r.path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("process: stat log file %s: %w", r.path, err)
	}
	r.f = f
	r.w = bufio.NewWriterSize(f, 64*1024)
	r.size = info.Size()
	return nil
}

func (r *rotatingFile) write(line logLine) error {
	if r.f == nil {
		return nil
	}
	data, err := json.Marshal(line)
	if err != nil {
		return fmt.Errorf("process: encode log line: %w", err)
	}
	data = append(data, '\n')
	if r.size+int64(len(data)) > r.maxBytes {
		if err := r.rotate(); err != nil {
			return err
		}
	}
	n, err := r.w.Write(data)
	r.size += int64(n)
	if err != nil {
		return fmt.Errorf("process: write log file %s: %w", r.path, err)
	}
	return nil
}

func (r *rotatingFile) flush() error {
	if r.w == nil {
		return nil
	}
	if err := r.w.Flush(); err != nil {
		return fmt.Errorf("process: flush log file %s: %w", r.path, err)
	}
	return nil
}

// rotate renames the current segment out of the way, shifts the older ones
// down, and deletes anything past the retention count.
func (r *rotatingFile) rotate() error {
	if err := r.flush(); err != nil {
		return err
	}
	if err := r.f.Close(); err != nil {
		return fmt.Errorf("process: close log file %s: %w", r.path, err)
	}
	r.f, r.w = nil, nil

	// Shift from the oldest end so nothing is overwritten before it moves.
	for i := r.retain; i >= 1; i-- {
		older := fmt.Sprintf("%s.%d", r.path, i+1)
		newer := fmt.Sprintf("%s.%d", r.path, i)
		if i == r.retain {
			_ = os.Remove(newer)
			continue
		}
		if _, err := os.Stat(newer); err == nil {
			_ = os.Rename(newer, older)
		}
	}
	if err := os.Rename(r.path, r.path+".1"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("process: rotate log file %s: %w", r.path, err)
	}
	return r.open()
}

func (r *rotatingFile) close() error {
	if r.f == nil {
		return nil
	}
	flushErr := r.flush()
	closeErr := r.f.Close()
	r.f, r.w = nil, nil
	if flushErr != nil {
		return flushErr
	}
	if closeErr != nil {
		return fmt.Errorf("process: close log file %s: %w", r.path, closeErr)
	}
	return nil
}

// segments lists the retained history files oldest first, ending with the live
// one.
func (r *rotatingFile) segments() []string {
	var older []string
	for i := 1; i <= r.retain; i++ {
		p := fmt.Sprintf("%s.%d", r.path, i)
		if _, err := os.Stat(p); err == nil {
			older = append(older, p)
		}
	}
	// .1 is the most recent rotation, so the numeric order is newest first.
	sort.Sort(sort.Reverse(sort.StringSlice(older)))
	return append(older, r.path)
}

// readSegments parses log lines back out of the on-disk history, oldest first,
// keeping at most limit lines from the end.
//
// A truncated final line — the agent was SIGKILLed mid-flush — is skipped
// rather than failing the read. Losing the last line of a log is not a reason
// to refuse the other nine thousand.
func readSegments(paths []string, limit int) ([]logLine, error) {
	var out []logLine
	for _, path := range paths {
		f, err := os.Open(path) //nolint:gosec // path is the agent's own state directory
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("process: read log segment %s: %w", path, err)
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes+4096)
		for scanner.Scan() {
			var line logLine
			if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
				continue
			}
			out = append(out, line)
			if limit > 0 && len(out) > limit*2 {
				// Keep the slice from growing to the size of the whole history
				// when the caller only wants a tail of it.
				out = out[len(out)-limit:]
			}
		}
		err = scanner.Err()
		_ = f.Close()
		if err != nil && !errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("process: scan log segment %s: %w", path, err)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}

// selector is the filtering half of a GetProcessLogs request, resolved against
// the agent's defaults.
type selector struct {
	stream sandboxdv1.Stream
	since  time.Time
	filter *regexp.Regexp
	tail   int
}

// matches reports whether a line belongs in the response. tail is applied by
// the caller, after filtering, so "the last 20 lines matching ERROR" means what
// it reads like.
func (s selector) matches(line logLine) bool {
	if s.stream != sandboxdv1.Stream_STREAM_UNSPECIFIED && line.Stream != s.stream {
		return false
	}
	if !s.since.IsZero() && line.At.Before(s.since) {
		return false
	}
	if s.filter != nil && !s.filter.MatchString(line.Text) {
		return false
	}
	return true
}

// splitLine breaks text at maxLineBytes, returning the pieces in order. Every
// piece but the last is a continuation.
//
// It splits on bytes rather than runes and may therefore cut a multi-byte
// character in half. That is deliberate: the alternative is scanning for a rune
// boundary in output that may not be UTF-8 at all, and a reader that
// concatenates the pieces — which is what continued is for — gets the original
// bytes back either way.
func splitLine(text string) []string {
	if len(text) <= maxLineBytes {
		return []string{text}
	}
	var parts []string
	for len(text) > maxLineBytes {
		parts = append(parts, text[:maxLineBytes])
		text = text[maxLineBytes:]
	}
	return append(parts, text)
}

// logDirName is the per-process directory under the state directory. Process
// ids are generated by the supervisor from a sanitised name plus random
// characters, so they are already safe as path components; this asserts it
// rather than assuming it, because the id reaches here from a persisted record
// that a previous version of the agent wrote.
func logDirName(id string) (string, error) {
	if id == "" || id == "." || id == ".." || strings.ContainsAny(id, `/\`) {
		return "", fmt.Errorf("process: %q is not a usable process id", id)
	}
	return id, nil
}
