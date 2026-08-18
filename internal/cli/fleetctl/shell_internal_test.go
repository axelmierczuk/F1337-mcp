package fleetctl

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
)

// The four ways `fleetctl shell` can end, and the local terminal at each of
// them.
//
// A CLI that leaves a terminal in raw mode has left the operator with a shell
// that does not echo what they type and does not respond to Ctrl-C — worse than
// one that never ran — so each of the four paths is exercised here rather than
// argued about in a comment. Two of them (a signal, a panic on a pump
// goroutine) end with the process gone in production, which is exactly why they
// are driven through a fake terminal in a test process rather than by hand.

// fakeTerminal stands in for the operator's terminal.
type fakeTerminal struct {
	// input is what the operator "types". A test writes into it; the input pump
	// reads it.
	input chan []byte
	// written collects what the session rendered.
	written syncWriter

	// restored counts how many times the terminal was put back. It is a count
	// rather than a flag so a test can assert restoration happened exactly
	// once, whichever paths raced to do it.
	restored atomic.Int32
	// rawErr, when set, is what makeRaw fails with.
	rawErr error
	// restoreErr, when set, is what the undo fails with.
	restoreErr error
	// panicOnRead makes the input pump panic, which is the only way to reach
	// the goroutine-panic restoration path.
	panicOnRead bool
	// writeErr, when set, is what rendering session output fails with — the
	// operator's terminal going away underneath a session that is still
	// producing output.
	writeErr error

	resizes chan [2]int
}

func newFakeTerminal() *fakeTerminal {
	return &fakeTerminal{input: make(chan []byte, 16), resizes: make(chan [2]int, 16)}
}

func (f *fakeTerminal) Read(p []byte) (int, error) {
	if f.panicOnRead {
		panic("terminal read exploded")
	}
	chunk, ok := <-f.input
	if !ok {
		return 0, io.EOF
	}
	return copy(p, chunk), nil
}

func (f *fakeTerminal) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.written.Write(p)
}

func (f *fakeTerminal) makeRaw() (func() error, error) {
	if f.rawErr != nil {
		return nil, f.rawErr
	}
	return func() error {
		f.restored.Add(1)
		return f.restoreErr
	}, nil
}

func (f *fakeTerminal) size() *sandboxdv1.ShellSize {
	return &sandboxdv1.ShellSize{Columns: 100, Rows: 40}
}

func (f *fakeTerminal) watch(ctx context.Context, onChange func(int, int)) {
	for {
		select {
		case <-ctx.Done():
			return
		case size := <-f.resizes:
			onChange(size[0], size[1])
		}
	}
}

func (f *fakeTerminal) rendered() string { return f.written.String() }

// syncWriter collects output written from the render loop while a test reads it.
type syncWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *syncWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// fakeStream stands in for the gRPC stream.
type fakeStream struct {
	// ctx is the stream's own context, so Recv ends when the session is
	// cancelled. A real gRPC stream does exactly that, and a fake that blocked
	// forever instead would make the signal path untestable — the very path
	// that matters most.
	ctx context.Context

	// responses is what the session receives. Closing it ends the stream the
	// way a server returning does.
	responses chan *sandboxdv1.ShellResponse
	// recvErr, when set, is what Recv fails with once responses is drained —
	// which is how a dropped connection is spelled here.
	recvErr error

	mu   sync.Mutex
	sent []*sandboxdv1.ShellRequest
	// sendErr, when set, is what Send fails with.
	sendErr error
	closed  bool
}

func newFakeStream() *fakeStream {
	return &fakeStream{ctx: context.Background(), responses: make(chan *sandboxdv1.ShellResponse, 16)}
}

func (f *fakeStream) Send(req *sandboxdv1.ShellRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sendErr != nil {
		return f.sendErr
	}
	f.sent = append(f.sent, req)
	return nil
}

func (f *fakeStream) Recv() (*sandboxdv1.ShellResponse, error) {
	select {
	case resp, ok := <-f.responses:
		if !ok {
			if f.recvErr != nil {
				return nil, f.recvErr
			}
			return nil, io.EOF
		}
		return resp, nil
	case <-f.ctx.Done():
		return nil, f.ctx.Err()
	}
}

func (f *fakeStream) CloseSend() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

// requests is everything the session has sent so far.
func (f *fakeStream) requests() []*sandboxdv1.ShellRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*sandboxdv1.ShellRequest(nil), f.sent...)
}

// dataSent is every byte the session forwarded from the terminal, joined.
func (f *fakeStream) dataSent() string {
	var b strings.Builder
	for _, req := range f.requests() {
		if data := req.GetData(); data != nil {
			b.Write(data)
		}
	}
	return b.String()
}

// newSession wires a fake terminal to a fake stream.
func newSession(term terminal, stream shellStream) (*shellSession, *bytes.Buffer) {
	notes := &bytes.Buffer{}
	return &shellSession{term: term, stream: stream, notes: notes}, notes
}

// exitResponse is the terminal message a session ends with.
func exitResponse(code int32) *sandboxdv1.ShellResponse {
	return &sandboxdv1.ShellResponse{Event: &sandboxdv1.ShellResponse_Exit{
		Exit: &sandboxdv1.ShellExit{ExitCode: code},
	}}
}

func dataResponse(text string) *sandboxdv1.ShellResponse {
	return &sandboxdv1.ShellResponse{Event: &sandboxdv1.ShellResponse_Data{Data: []byte(text)}}
}

// ------------------------------------------------- path 1: a normal exit

// TestShellSession_RestoresTheTerminalOnANormalExit is the ordinary path, and
// the one that also pins the exit code: `exit 3` on the far end has to be
// `exit 3` here, or a script wrapping this command cannot tell a failed build
// from a failed connection.
func TestShellSession_RestoresTheTerminalOnANormalExit(t *testing.T) {
	term := newFakeTerminal()
	stream := newFakeStream()
	sess, _ := newSession(term, stream)

	stream.responses <- dataResponse("a prompt, and then some output\n")
	stream.responses <- exitResponse(3)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	code, err := sess.run(ctx, cancel, &sandboxdv1.ShellOpen{})
	require.NoError(t, err)
	assert.Equal(t, 3, code)
	assert.Equal(t, int32(1), term.restored.Load(), "the terminal has to be put back exactly once")
	assert.Contains(t, term.rendered(), "a prompt, and then some output")

	// The open is the first thing on the wire, and it carries the size: a
	// session opened without one draws its first screen at 80x24 and reflows.
	first := stream.requests()[0]
	require.NotNil(t, first.GetOpen())
}

// ------------------------------------------ path 2: a signal

// TestShellSession_RestoresTheTerminalOnASignal covers the path that ends with
// the process gone.
//
// This is not the operator pressing Ctrl-C — raw mode is what stops that being
// a signal at all, and TestShellSession_SendsTheInterruptByteRatherThanDying
// covers it. This is `kill`, a terminal window closing, or a service manager
// stopping the process while it holds the operator's terminal in raw mode.
//
// The stream here deliberately does *not* notice the cancellation, which is
// what makes this a test of the signal handler rather than of the unwinding
// after it. A real teardown crosses a gRPC stream and a TLS connection and can
// take as long as it takes; the operator's terminal has to be usable before any
// of that, so the handler restores first and cancels second. With a stream that
// unblocked on cancellation, the restore in the render loop would cover for a
// handler that did nothing.
func TestShellSession_RestoresTheTerminalOnASignal(t *testing.T) {
	requireSelfSignal(t)

	term := newFakeTerminal()
	stream := newFakeStream()
	sess, _ := newSession(term, stream)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan int, 1)
	go func() {
		code, err := sess.run(ctx, cancel, &sandboxdv1.ShellOpen{})
		assert.NoError(t, err)
		done <- code
	}()

	// Wait until the session is actually running before signalling it:
	// delivering a signal to a session that has not entered raw mode yet would
	// prove nothing about restoring it.
	waitForCondition(t, "the session to send its open", func() bool {
		return len(stream.requests()) > 0
	})

	require.NoError(t, deliverSignalToSelf())

	waitForCondition(t, "the terminal to be restored while teardown is still in progress", func() bool {
		return term.restored.Load() == 1
	})
	select {
	case <-done:
		t.Fatal("the session ended before the assertion could observe the terminal being restored first")
	default:
	}

	// And it ends once the stream does.
	close(stream.responses)
	select {
	case code := <-done:
		assert.Equal(t, sessionFailed, code)
	case <-time.After(30 * time.Second):
		t.Fatal("the session did not end after a signal")
	}
	assert.Equal(t, int32(1), term.restored.Load(), "the terminal was restored more than once")
}

// TestShellSession_ReportsASessionCancelledBeneathIt is the other half: what
// the command returns when the session is torn down under it rather than
// exiting.
func TestShellSession_ReportsASessionCancelledBeneathIt(t *testing.T) {
	term := newFakeTerminal()
	stream := newFakeStream()
	sess, notes := newSession(term, stream)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream.ctx = ctx

	done := make(chan int, 1)
	go func() {
		code, err := sess.run(ctx, cancel, &sandboxdv1.ShellOpen{})
		assert.NoError(t, err)
		done <- code
	}()

	waitForCondition(t, "the session to send its open", func() bool {
		return len(stream.requests()) > 0
	})
	cancel()

	select {
	case code := <-done:
		assert.Equal(t, sessionFailed, code, "a session torn down under the operator did not exit 0")
	case <-time.After(30 * time.Second):
		t.Fatal("the session did not end when its context was cancelled")
	}
	assert.Equal(t, int32(1), term.restored.Load())
	assert.Contains(t, notes.String(), "session ended")
}

// ---------------------------------- path 3: a dropped connection

func TestShellSession_RestoresTheTerminalOnADroppedConnection(t *testing.T) {
	term := newFakeTerminal()
	stream := newFakeStream()
	stream.recvErr = errors.New("connection reset by peer")
	close(stream.responses)

	sess, _ := newSession(term, stream)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := sess.run(ctx, cancel, &sandboxdv1.ShellOpen{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection reset")
	assert.Equal(t, int32(1), term.restored.Load(), "a dropped connection left the terminal in raw mode")
}

// TestShellSession_ReportsAStreamThatEndedWithoutAStatus covers the other
// disconnection: a stream that closed cleanly but never delivered an exit.
//
// The session happened and its status did not survive. Saying so beats
// reporting a status nobody sent — and beats reporting success, which is what a
// missing terminal message would otherwise look like.
func TestShellSession_ReportsAStreamThatEndedWithoutAStatus(t *testing.T) {
	term := newFakeTerminal()
	stream := newFakeStream()
	close(stream.responses)

	sess, notes := newSession(term, stream)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	code, err := sess.run(ctx, cancel, &sandboxdv1.ShellOpen{})
	require.NoError(t, err)
	assert.Equal(t, sessionFailed, code)
	assert.Contains(t, notes.String(), "without reporting its exit status")
	assert.Equal(t, int32(1), term.restored.Load())
}

// TestShellSession_RestoresTheTerminalWhenRenderingFails is the exit path the
// other three do not reach: output arriving for a terminal that has gone away.
//
// A dropped connection is the far end going quiet. This is the near end going
// quiet while the far end is mid-sentence — the terminal emulator killed, the
// descriptor closed underneath the process — and it leaves the render loop
// returning from a write rather than from a receive. It is a different
// statement in a different branch, and it is the one that would put a terminal
// back into raw mode for whatever runs next in that shell.
func TestShellSession_RestoresTheTerminalWhenRenderingFails(t *testing.T) {
	term := newFakeTerminal()
	term.writeErr = errors.New("input/output error")
	stream := newFakeStream()
	stream.responses <- dataResponse("output nobody can render\n")

	sess, _ := newSession(term, stream)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := sess.run(ctx, cancel, &sandboxdv1.ShellOpen{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "input/output error")
	assert.Equal(t, int32(1), term.restored.Load(),
		"a terminal that failed mid-render was left in raw mode")
}

// ------------------------------------------------- path 4: a panic

// TestShellSession_RestoresTheTerminalWhenAPumpPanics is the path a deferred
// restore does not cover.
//
// A panic on the main goroutine unwinds through run, so its defer runs. A panic
// on a pump goroutine does not: the runtime prints the trace and kills the
// process, and the terminal the operator is left holding is in raw mode. So
// each pump restores and re-panics, which keeps the crash and its stack trace
// while handing back a terminal that works.
//
// Calling the pump directly rather than in a goroutine is what makes that
// assertable: a re-panic on a goroutine would take the test binary with it,
// which is precisely the production behaviour being preserved.
func TestShellSession_RestoresTheTerminalWhenAPumpPanics(t *testing.T) {
	term := newFakeTerminal()
	term.panicOnRead = true
	stream := newFakeStream()

	sess, _ := newSession(term, stream)
	undo, err := term.makeRaw()
	require.NoError(t, err)
	sess.restore = &restoreGuard{undo: undo, notes: sess.notes}

	assert.Panics(t, func() { sess.pumpInput() }, "the panic has to survive: losing it would hide the crash it came from")
	assert.Equal(t, int32(1), term.restored.Load(), "a panicking pump left the terminal in raw mode")
}

// ------------------------------------------------------------ Ctrl-C

// TestShellSession_SendsTheInterruptByteRatherThanDying is the client half of
// "Ctrl-C interrupts the remote foreground process rather than killing the
// client".
//
// In raw mode the local terminal generates no signal, so an interrupt is byte
// 0x03 travelling to the far end like any other. The assertion is that it goes
// on the wire *and* that the session is still running afterwards — the second
// half is what fails if a client ever grows a SIGINT handler that ends the
// session.
func TestShellSession_SendsTheInterruptByteRatherThanDying(t *testing.T) {
	term := newFakeTerminal()
	stream := newFakeStream()
	sess, _ := newSession(term, stream)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan int, 1)
	go func() {
		code, err := sess.run(ctx, cancel, &sandboxdv1.ShellOpen{})
		assert.NoError(t, err)
		done <- code
	}()

	term.input <- []byte("\x03")
	waitForCondition(t, "the interrupt byte to reach the wire", func() bool {
		return strings.Contains(stream.dataSent(), "\x03")
	})

	// Still running: nothing about an interrupt ends the session on this side.
	select {
	case code := <-done:
		t.Fatalf("the client exited on Ctrl-C with code %d; the byte should have gone to the far end and nothing else", code)
	case <-time.After(200 * time.Millisecond):
	}

	// And the session ends when the far end says so, with its own status.
	stream.responses <- exitResponse(0)
	select {
	case code := <-done:
		assert.Equal(t, 0, code)
	case <-time.After(30 * time.Second):
		t.Fatal("the session did not end when the far end reported its exit")
	}
}

// TestShellSession_ForwardsResizes covers the message a full-screen program
// cannot do without. A session whose remote terminal keeps the size it was
// opened with renders `top` and `vi` to the wrong width for the rest of its
// life.
func TestShellSession_ForwardsResizes(t *testing.T) {
	term := newFakeTerminal()
	stream := newFakeStream()
	sess, _ := newSession(term, stream)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	go func() { _, _ = sess.run(ctx, cancel, &sandboxdv1.ShellOpen{}) }()

	term.resizes <- [2]int{132, 50}
	waitForCondition(t, "the resize to reach the wire", func() bool {
		for _, req := range stream.requests() {
			if size := req.GetResize(); size != nil && size.GetColumns() == 132 && size.GetRows() == 50 {
				return true
			}
		}
		return false
	})

	stream.responses <- exitResponse(0)
}

// TestShellSession_HalfClosesWhenLocalInputEnds covers stdin closing under a
// session that is still producing output — the far end has to hear that no more
// input is coming without the session being torn down.
func TestShellSession_HalfClosesWhenLocalInputEnds(t *testing.T) {
	term := newFakeTerminal()
	stream := newFakeStream()
	sess, _ := newSession(term, stream)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan int, 1)
	go func() {
		code, _ := sess.run(ctx, cancel, &sandboxdv1.ShellOpen{})
		done <- code
	}()

	close(term.input)
	waitForCondition(t, "the write half to be closed", func() bool {
		stream.mu.Lock()
		defer stream.mu.Unlock()
		return stream.closed
	})

	// Output still arrives, and the session still ends with the far end's own
	// status.
	stream.responses <- dataResponse("output after stdin closed\n")
	stream.responses <- exitResponse(5)
	select {
	case code := <-done:
		assert.Equal(t, 5, code)
	case <-time.After(30 * time.Second):
		t.Fatal("the session did not end after its input closed")
	}
	assert.Contains(t, term.rendered(), "output after stdin closed")
}

// ------------------------------------------------------ the session's env

// TestSessionEnv_CarriesTheTerminalAndNothingElse pins both halves of what a
// session is opened with.
//
// The first half is a rendering bug that is invisible to every assertion about
// bytes: a session with no TERM renders as well as `TERM=dumb` allows, which
// is to say `vi` draws nothing, and the locale variables are what decide
// whether a box-drawing character arrives as one or as a question mark.
//
// The second half is the security one, and it is the reason this is a fixed
// list rather than a filter. This command runs a program on somebody else's
// machine, and an operator's own environment is full of credentials — AWS keys,
// tokens, whatever their shell profile exports. Forwarding it wholesale is one
// line away at any time, and nothing else in this package would notice.
func TestSessionEnv_CarriesTheTerminalAndNothingElse(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("LANG", "en_GB.UTF-8")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "not-for-somebody-elses-machine")
	t.Setenv("LC_ALL", "")

	env := sessionEnv([]string{"FOO=bar"})

	assert.Contains(t, env, "TERM=xterm-256color", "a session without TERM renders as well as TERM=dumb allows")
	assert.Contains(t, env, "LANG=en_GB.UTF-8")
	assert.Contains(t, env, "FOO=bar", "--env is what an operator sets deliberately, and it goes on top")
	assert.NotContains(t, env, "LC_ALL=", "an unset variable is not forwarded as an empty one; the agent would apply it over its own")

	for _, entry := range env {
		assert.NotContains(t, entry, "not-for-somebody-elses-machine",
			"the operator's own environment was forwarded to a remote host")
	}
}

// ------------------------------------------------- one sender at a time

// TestShellSession_NeverHasTwoSendsInFlight pins the property gRPC requires of
// every client stream and this session has two goroutines to break.
//
// "It is not safe to call SendMsg on the same stream in different goroutines.
// It is also not safe to call CloseSend concurrently with SendMsg." The input
// pump sends on every keystroke, the resize watcher sends on every SIGWINCH,
// and the input pump half-closes when stdin ends — so an operator who resizes
// their window while typing is the whole violation, and the half-close variant
// of it races the stream's own end-of-send flag rather than merely being
// undefined.
//
// The stream reports the overlap from inside Send rather than leaving it to be
// inferred afterwards, and holds the call open long enough that a second
// entrant would have to be caught: a counter read at the end could not tell an
// interleaving that happened from one that did not.
func TestShellSession_NeverHasTwoSendsInFlight(t *testing.T) {
	term := newFakeTerminal()
	stream := newOverlappingStream()
	sess, _ := newSession(term, stream)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = sess.run(ctx, cancel, &sandboxdv1.ShellOpen{})
	}()

	// Typing and resizing at once, for long enough that an unserialised pair
	// would have to collide: every send is held open, so two senders that are
	// not taking turns are overlapping by construction.
	var feeding sync.WaitGroup
	feeding.Add(2)
	go func() {
		defer feeding.Done()
		for range 40 {
			term.input <- []byte("x")
		}
		// And the half-close, which is the variant with a data race attached.
		close(term.input)
	}()
	go func() {
		defer feeding.Done()
		for i := range 40 {
			term.resizes <- [2]int{100 + i, 40}
		}
	}()
	feeding.Wait()

	waitForCondition(t, "the session to have carried the typing and the resizes", func() bool {
		return stream.completed() >= 40
	})

	stream.responses <- exitResponse(0)
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the session did not end when the far end reported its exit")
	}

	assert.Zero(t, stream.overlaps.Load(),
		"two goroutines were inside Send on the same stream at once; gRPC does not permit that, and the CloseSend case races the stream's own state")
}

// overlappingStream is a fakeStream that notices two senders at once.
//
// Send holds the stream for a moment rather than returning immediately, which
// is what makes the overlap observable: a real gRPC send marshals, takes the
// transport's write path and can block on flow control, so an unserialised
// pair overlaps in production for far longer than this.
type overlappingStream struct {
	*fakeStream

	inFlight atomic.Int32
	overlaps atomic.Int32
	sends    atomic.Int32
}

func newOverlappingStream() *overlappingStream {
	return &overlappingStream{fakeStream: newFakeStream()}
}

func (s *overlappingStream) Send(req *sandboxdv1.ShellRequest) error {
	if s.inFlight.Add(1) > 1 {
		s.overlaps.Add(1)
	}
	err := s.fakeStream.Send(req)
	time.Sleep(200 * time.Microsecond)
	s.inFlight.Add(-1)
	s.sends.Add(1)
	return err
}

func (s *overlappingStream) CloseSend() error {
	if s.inFlight.Add(1) > 1 {
		s.overlaps.Add(1)
	}
	err := s.fakeStream.CloseSend()
	time.Sleep(200 * time.Microsecond)
	s.inFlight.Add(-1)
	return err
}

func (s *overlappingStream) completed() int32 { return s.sends.Load() }

// ------------------------------------------------------ endings and codes

func TestShellSession_ReportsAnIdleReapingRatherThanAnExitCode(t *testing.T) {
	term := newFakeTerminal()
	stream := newFakeStream()

	// A notes writer that records the terminal's state at the moment it was
	// written to. Anything this command prints about a session has to land on a
	// terminal that is already back in cooked mode, or the line arrives without
	// carriage returns and staircases down the screen — the last thing the
	// operator sees, and the one that looks like the CLI is broken.
	notes := &orderedNotes{restored: &term.restored}
	sess := &shellSession{term: term, stream: stream, notes: notes}

	stream.responses <- &sandboxdv1.ShellResponse{Event: &sandboxdv1.ShellResponse_Exit{
		Exit: &sandboxdv1.ShellExit{IdleTimeout: true},
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	code, err := sess.run(ctx, cancel, &sandboxdv1.ShellOpen{})
	require.NoError(t, err)
	assert.Equal(t, sessionFailed, code, "a reaped session is not a shell that exited 0")
	assert.Contains(t, notes.String(), "idle")
	assert.Equal(t, int32(1), notes.restoredWhenWritten, "the note was printed onto a terminal still in raw mode")
}

// orderedNotes records what the terminal's restore count was when the first
// line was written to it.
type orderedNotes struct {
	restored            *atomic.Int32
	restoredWhenWritten int32
	buf                 bytes.Buffer
}

func (n *orderedNotes) Write(p []byte) (int, error) {
	if n.buf.Len() == 0 {
		n.restoredWhenWritten = n.restored.Load()
	}
	return n.buf.Write(p)
}

func (n *orderedNotes) String() string { return n.buf.String() }

func TestShellSession_ReportsASignalledShell(t *testing.T) {
	term := newFakeTerminal()
	stream := newFakeStream()
	sess, notes := newSession(term, stream)

	stream.responses <- &sandboxdv1.ShellResponse{Event: &sandboxdv1.ShellResponse_Exit{
		Exit: &sandboxdv1.ShellExit{Signaled: true, Signal: "SIGHUP", ExitCode: -1},
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	code, err := sess.run(ctx, cancel, &sandboxdv1.ShellOpen{})
	require.NoError(t, err)
	assert.Equal(t, sessionFailed, code, "a signalled shell reports -1, which is not a process exit code")
	assert.Contains(t, notes.String(), "SIGHUP")
}

// TestShellSession_ReportsAFailureToEnterRawMode: a terminal that could not be
// put into raw mode is a session that must not start. Half a session — the
// operator typing into a shell whose input is being line-buffered locally — is
// worse than none.
func TestShellSession_ReportsAFailureToEnterRawMode(t *testing.T) {
	term := newFakeTerminal()
	term.rawErr = errors.New("inappropriate ioctl for device")
	stream := newFakeStream()
	sess, _ := newSession(term, stream)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := sess.run(ctx, cancel, &sandboxdv1.ShellOpen{})
	require.Error(t, err)
	assert.Empty(t, stream.requests(), "nothing should have been sent for a session that never started")
	assert.Zero(t, term.restored.Load(), "there was nothing to restore")
}

// TestRestoreGuard_RestoresOnceHoweverManyPathsReachIt pins the property that
// lets every exit path restore unconditionally instead of each one reasoning
// about whether another already has.
func TestRestoreGuard_RestoresOnceHoweverManyPathsReachIt(t *testing.T) {
	var count atomic.Int32
	guard := &restoreGuard{undo: func() error { count.Add(1); return nil }}

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			guard.restore()
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), count.Load())
}

// TestRestoreGuard_SaysSoWhenItCannotRestore: a terminal that could not be put
// back is something the operator has to hear about, because the fix is theirs
// to type.
func TestRestoreGuard_SaysSoWhenItCannotRestore(t *testing.T) {
	notes := &bytes.Buffer{}
	guard := &restoreGuard{
		undo:  func() error { return errors.New("device not configured") },
		notes: notes,
	}
	guard.restore()

	assert.Contains(t, notes.String(), "could not restore the terminal")
	assert.Contains(t, notes.String(), "reset")
}

// waitForCondition polls until cond holds. Nothing here sleeps a fixed duration
// and then asserts: the session crosses two goroutines and a channel, and a
// test that asserted on how long that took would fail for reasons that have
// nothing to do with the product.
func waitForCondition(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
