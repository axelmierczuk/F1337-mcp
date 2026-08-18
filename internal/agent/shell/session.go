package shell

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/platform"
	"github.com/axelmierczuk/fleet-mcp/internal/security/policy"
)

const (
	// defaultColumns and defaultRows are what a session gets when the client
	// sent no size. They are the historic terminal default, and a wrong-but-
	// conventional size renders better than a zero one: a terminal told it has
	// no rows draws nothing at all.
	defaultColumns = 80
	defaultRows    = 24

	// maxDimension bounds a caller-supplied window size. TIOCSWINSZ takes
	// unsigned 16-bit fields, so anything larger cannot be applied anyway, and
	// a cap here means the truncation happens somewhere that can say so rather
	// than silently in a conversion.
	maxDimension = 1 << 14

	// readBuffer is how much terminal output one read may return. Big enough
	// that `cat` of a large file is not one gRPC message per line, small enough
	// that an idle session is not holding a megabyte per operator.
	readBuffer = 32 * 1024

	// drainAfterExit bounds the wait for the last of a finished session's
	// output before its exit status is sent.
	//
	// On Unix it is never actually waited out: the agent released its copy of
	// the child's end of the terminal at startup, so once the session's last
	// process exits the read returns what is left and then reports the hangup,
	// and the pump ends on its own in microseconds. It exists for Windows,
	// where a ConPTY's output pipe stays open until the pseudo-console is
	// closed and there is no other way to tell "nothing more is coming" from
	// "nothing yet". A quarter of a second is imperceptible at teardown and is
	// far longer than the console host needs to flush.
	drainAfterExit = 250 * time.Millisecond

	// hangupGrace is how long a session that is being reaped has between its
	// terminal hanging up and its process group being killed.
	//
	// The hangup is the polite half and does most of the work: on Unix, closing
	// the terminal sends SIGHUP to its foreground process group, which is what
	// makes an interactive shell tell its own jobs the session ended. The kill
	// is what makes the guarantee unconditional.
	hangupGrace = 2 * time.Second

	// sendStall bounds a send to a client that has stopped reading. See
	// [sender].
	sendStall = 5 * time.Second
)

// endReason is why a session stopped.
type endReason int

const (
	// endExited means the session's own command finished. Every other reason
	// is the agent ending a session that was still running.
	endExited endReason = iota
	endCancelled
	endIdle
)

// windowSize is a terminal window in character cells, already bounded.
type windowSize struct {
	columns int
	rows    int
}

// sizeOf reads a caller's window size, filling in the conventional default for
// a dimension it left out and clamping one it exaggerated.
//
// Neither is an error. A client that cannot read its own terminal size is
// better served by an 80x24 session it can resize than by a refusal, and a
// nonsense size is a client bug that should not cost the operator their shell.
func sizeOf(size *sandboxdv1.ShellSize) windowSize {
	return windowSize{
		columns: dimension(size.GetColumns(), defaultColumns),
		rows:    dimension(size.GetRows(), defaultRows),
	}
}

func dimension(requested uint32, fallback int) int {
	switch {
	case requested == 0:
		return fallback
	case requested > maxDimension:
		return maxDimension
	default:
		return int(requested) //nolint:gosec // bounded by maxDimension immediately above
	}
}

// errTerminalGone is what an operation gets when the session's terminal has
// already been released. It is not a failure of the session: the session is
// over, and this is the race being refused rather than a symptom of one.
var errTerminalGone = errors.New("shell: the session terminal has been closed")

// sessionTerminal is the session's pseudo-terminal, with the two guards its
// teardown needs.
//
// # It is closed exactly once
//
// A session is torn down by hanging the terminal up and then releasing it, and
// on Unix the second close is harmless because go-pty guards it. The ConPTY
// implementation does not: its Close calls ClosePseudoConsole unconditionally,
// so a second one destroys a console object that is already gone and corrupts
// the agent's own heap. CI found this as an 0xC0000374 with no stack, on the
// first Windows run where a session got far enough to be reaped.
//
// # And it is never resized afterwards
//
// Closing once is not enough on its own, because the close is not the only
// call that reaches the console object. go-pty's ConPTY Resize hands the
// pseudo-console handle straight to ResizePseudoConsole, and by then
// ClosePseudoConsole has freed what that names — the same use-after-free, one
// call along, with a handle value Windows is free to have reissued to
// something else in the meantime.
//
// It is reachable on an ordinary session rather than in theory.
// [session.pumpInput] runs on its own goroutine and is deliberately not joined
// before teardown — it is parked in Recv, and the only thing that unblocks it
// is the handler returning — so a resize that arrives while a session is being
// reaped is what a person dragging their window during a reconnect produces.
//
// Read and Write need no guard and deliberately do not take one. Both go to
// the *os.File ends of the pair, whose descriptors the runtime reference-
// counts: a read or write after the close reports a closed file rather than
// touching a handle value that now names something else. Guarding them would
// also be a liveness bug — a Write that blocks because the far end has stopped
// reading its console would hold the lock the teardown needs.
//
// The pty is embedded rather than held in a field, and that is load-bearing:
// Command is promoted, so the *go-pty* value is what ends up on the Cmd, and
// go-pty's Start type-asserts it back to its own concrete type. A wrapper
// passed in there would fail that assertion on both platforms. Override
// nothing else here without checking that.
type sessionTerminal struct {
	platform.PTY

	// mu orders a resize against the close that destroys the terminal: the
	// resize takes it for reading, the close for writing, so the two can never
	// overlap and a resize that lost the race sees closed rather than a freed
	// handle.
	mu     sync.RWMutex
	closed bool

	// closeOnce releases the terminal, exactly once however many paths reach
	// it. See the type comment.
	closeOnce func() error
}

func newSessionTerminal(p platform.PTY) *sessionTerminal {
	return &sessionTerminal{PTY: p, closeOnce: sync.OnceValue(p.Close)}
}

// Resize applies a new window size, unless the terminal has already gone.
func (t *sessionTerminal) Resize(columns, rows int) error {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.closed {
		return errTerminalGone
	}
	return t.PTY.Resize(columns, rows)
}

// Close hangs the terminal up and shuts the door behind it.
func (t *sessionTerminal) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	return t.closeOnce()
}

// session is one running terminal: the pseudo-terminal, the stream it is
// carried on, and the activity clock the idle timeout reads.
type session struct {
	svc  *Service
	tty  *sessionTerminal
	send *sender

	// activity is when a byte last moved in either direction, in Unix
	// nanoseconds.
	//
	// Either direction, deliberately: a session watching a long build produces
	// no keystrokes for an hour and is not abandoned. See ShellConfig.
	// IdleTimeout.
	activity atomic.Int64
}

func (s *session) touch() { s.activity.Store(time.Now().UnixNano()) }

func (s *session) idleFor() time.Duration {
	return time.Since(time.Unix(0, s.activity.Load()))
}

// run allocates the terminal, starts the command on it, and carries the session
// until something ends it.
//
// The returned error is the one the RPC ends with. A session whose command
// exited non-zero is not one of them: that status is a ShellExit on the stream,
// exactly as a non-zero exit is an ExecResult rather than an RPC error, because
// "the command failed" and "the call failed" are different facts and the caller
// acts on them differently.
func (s *Service) run(
	ctx context.Context,
	stream grpc.BidiStreamingServer[sandboxdv1.ShellRequest, sandboxdv1.ShellResponse],
	spec sessionSpec,
	rec *sessionAudit,
) error {
	raw, err := platform.OpenPTY()
	if err != nil {
		rec.outcome, rec.failure = policy.OutcomeError, "this host could not allocate a pseudo-terminal"
		if errors.Is(err, platform.ErrUnsupported) {
			return status.Errorf(codes.Unimplemented, "this host cannot allocate a pseudo-terminal: %s", err)
		}
		return status.Errorf(codes.Internal, "allocating a pseudo-terminal: %s", err)
	}
	// Closed on every path out, and it is not only cleanup: on Unix this is the
	// terminal hanging up, which is what tells the far end the session ended.
	// Once, and through the same guard the teardown and the input pump use —
	// see sessionTerminal.
	tty := newSessionTerminal(raw)
	defer func() { _ = tty.Close() }()

	// Before the command starts, so the shell's first prompt is drawn at the
	// operator's real width rather than at 80 columns and then reflowed.
	if err := tty.Resize(spec.size.columns, spec.size.rows); err != nil {
		s.log.Warn("could not set the initial terminal size; the session starts at the platform default",
			"columns", spec.size.columns, "rows", spec.size.rows, "error", err)
	}

	group, err := platform.NewProcessGroup(platform.GroupConfig{
		// The agent holds the only handle for the life of the RPC, so on
		// Windows the job object dies with it and takes the tree along. A shell
		// wants this for the same reason exec does, and more so: a shell exists
		// to start processes, and none of them is supposed to outlive the
		// session that started it.
		KillOnClose: true,
	})
	if err != nil {
		rec.outcome, rec.failure = policy.OutcomeError, "the session's process group could not be prepared"
		return status.Errorf(codes.Internal, "preparing the process group: %s", err)
	}
	defer func() {
		// The session takes its process tree with it. See exec's equivalent for
		// why the sweep is conditional on the child really leading its own
		// group, and sweepGroup for what it does on each platform.
		if group.Isolated() {
			if err := sweepGroup(group); err != nil && !errors.Is(err, platform.ErrProcessNotFound) {
				s.log.Warn("could not sweep the session's process group; a descendant may have outlived it", "error", err)
			}
		}
		if err := group.Close(); err != nil {
			s.log.Warn("could not release the session's process group; on Windows this is what kills the tree", "error", err)
		}
	}()

	cmd := tty.Command(spec.command.Path, spec.command.Argv[1:]...)
	cmd.Dir = spec.dir
	cmd.Env = spec.env
	// Interactive, not the ordinary PTY configuration: on Windows the console
	// process group flag the latter sets is also what disables Ctrl-C for
	// everything in it. See platform.ProcessGroup.ConfigureInteractivePTYCommand.
	group.ConfigureInteractivePTYCommand(cmd)

	started := time.Now()
	if err := cmd.Start(); err != nil {
		rec.outcome, rec.failure = policy.OutcomeError, "the session's command could not be started"
		rec.duration = time.Since(started)
		return status.Errorf(codes.Internal, "starting %s: %s", spec.command.Path, err)
	}
	if err := group.Adopt(cmd.Process); err != nil {
		// The shell is running and reachable; only its descendants are not
		// guaranteed to be. Saying so beats failing a session that has already
		// started.
		s.log.Warn("session is running outside its process group; descendants may survive its end",
			"pid", cmd.Process.Pid, "error", err)
	}
	// After Start, never before: this is the agent giving up its own copy of
	// the child's end of the terminal, which is what lets a read of the
	// terminal end when the session does. See platform.ReleasePTYChildEnd.
	if err := platform.ReleasePTYChildEnd(raw); err != nil {
		s.log.Warn("could not release the agent's copy of the session terminal; the session's last output may be delayed",
			"error", err)
	}

	// Wait on its own goroutine, so this handler is never stuck behind a
	// process that will not exit. The channel is buffered so that goroutine can
	// finish after this function has returned.
	//
	// Started here rather than beside the pumps below, and that is the fix to a
	// leak rather than a tidying: everything between Start and the pumps can
	// return, and a child this handler walks away from without ever waiting on
	// is a zombie for the life of the daemon. The teardown below kills it, and
	// this is what reaps it afterwards.
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()

	sess := &session{svc: s, tty: tty, send: newSender(stream)}
	sess.touch()

	if err := sess.send.within(sendStall, opened(tty, cmd.Process.Pid, spec.command.Argv)); err != nil {
		rec.outcome, rec.failure = policy.OutcomeError, "the session could not be reported as open"
		rec.duration = time.Since(started)
		return err
	}

	// Both pumps are started and neither is joined.
	//
	// The input pump is parked in Recv, and what ends it is this handler
	// returning — gRPC cancels the stream when it does, which is the only thing
	// that can unblock a receive from a client that is simply sitting there.
	// Waiting for it here would be waiting for the thing this return causes.
	//
	// The output pump ends when the last writer of the child's end of the
	// terminal is gone, which is what the teardown below is for. Closing the
	// terminal is *not* what ends it, tempting as that reading is: go-pty opens
	// the master in blocking mode, so a read already in flight sits in the
	// syscall and the runtime cannot interrupt it — the close is deferred until
	// the read returns rather than the other way round. What returns it is the
	// slave losing its last writer: the hangup, then the group kill. A process
	// that deliberately escaped the group with setsid and kept the terminal
	// open therefore keeps this pump alive with it, which is the same
	// "detached is detached" property docs/security.md documents for the tree
	// itself.
	go sess.pumpInput(stream)
	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		sess.pumpOutput()
	}()

	reason, reaped := s.await(ctx, sess, waited)
	if reason != endExited {
		reaped = s.reap(sess, group, waited)
	}
	rec.duration = time.Since(started)

	// ProcessState belongs to the Wait still running on the other goroutine
	// until it has produced a value, so it is read only when it has.
	if reaped && cmd.ProcessState != nil {
		code := int32(cmd.ProcessState.ExitCode()) //nolint:gosec // an exit code is 8 bits on every supported platform, or -1 for a signal
		rec.exitCode = &code
		if sig, ok := terminatingSignal(cmd.ProcessState); ok {
			rec.signal = sig
		}
	}

	switch reason {
	case endExited:
		// The output the session produced on its way out has to reach the
		// client before its exit status does, or a shell's farewell is a
		// message the operator never sees.
		select {
		case <-outputDone:
		case <-time.After(drainAfterExit):
		}
		rec.outcome = policy.OutcomeOK
	case endIdle:
		rec.outcome, rec.idle = policy.OutcomeTimedOut, true
		rec.failure = "the session carried no data in either direction for longer than shell.idle_timeout, so the agent ended it"
	case endCancelled:
		rec.outcome = policy.OutcomeCancelled
		rec.failure = "the caller went away, so the session and its process tree were killed"
		// Nothing is sent: there is no longer anybody on the other end of the
		// stream, and a send would only fail.
		return status.Error(codes.Canceled, rec.failure)
	}

	// The session happened, so the record says what it did; a result that could
	// not be delivered is a separate fact recorded beside it rather than one
	// that rewrites the outcome. The same reading exec's sink error gets.
	if err := sess.send.within(sendStall, exit(rec, reason == endIdle)); err != nil {
		if rec.failure == "" {
			rec.failure = status.Convert(err).Message()
		}
		return err
	}
	return nil
}

// await blocks until something ends the session, and reports which and whether
// the command was reaped.
//
// The idle check is a timer that re-arms rather than one reset on every byte:
// resetting from both pumps would mean a lock on the hot path of a stream that
// can carry megabytes, and the question being asked — "has anything happened in
// the last N minutes" — is answered exactly by reading a timestamp when the
// timer fires.
func (s *Service) await(ctx context.Context, sess *session, waited <-chan error) (endReason, bool) {
	idle := time.NewTimer(s.idleTimeout)
	defer idle.Stop()

	for {
		select {
		case <-waited:
			return endExited, true
		case <-ctx.Done():
			// The stream's context. Cancelled means the caller hung up or the
			// daemon is draining; either way nothing is left to render the
			// session, and it must not keep running.
			return endCancelled, false
		case <-idle.C:
			if remaining := s.idleTimeout - sess.idleFor(); remaining > 0 {
				idle.Reset(remaining)
				continue
			}
			return endIdle, false
		}
	}
}

// reap ends a session that is still running, and reports whether the command
// was waited for.
//
// Hang up, then kill the tree — both, always, and in that order.
//
// The hangup is what an interactive shell understands. On Unix, closing the
// terminal sends SIGHUP to its foreground process group, and a shell that
// receives one passes it on to its own jobs, which sit in process groups this
// agent cannot name. It is the only step that reaches them.
//
// The kill is unconditional even when the hangup already ended the session's
// own leader, and that is the correction to an earlier version of this
// function. Stopping there is defensible on Unix, where the deferred sweep
// signals the group anyway; on Windows it left the guarantee unmet. Closing a
// pseudo-console ends the processes attached to it, and a grandchild that never
// attached to one — anything the session started that is not a console
// application — has nothing to end it. The job object is what does, and
// skipping TerminateJobObject because the leader happened to exit first is
// exactly how "closing the stream kills the whole tree" becomes a claim rather
// than a fact.
//
// A job the operator deliberately detached — `nohup`, `disown`, `setsid` —
// survives, exactly as it does over ssh. That is a property of what they asked
// for rather than a gap in this teardown.
//
// What makes the close safe as the *first* step is that something is still
// draining the terminal while it runs: on Windows it does not return until the
// console host's remaining output has somewhere to go, and on macOS a process
// with output queued is held inside exit for the same reason. The only reader
// is [session.pumpOutput], which is why a failed send there stops the sending
// and not the reading. Read its comment before changing either.
func (s *Service) reap(sess *session, group *platform.ProcessGroup, waited <-chan error) bool {
	if err := sess.tty.Close(); err != nil {
		s.log.Debug("closing the session terminal reported an error; the session is being killed anyway", "error", err)
	}

	reaped := false
	select {
	case <-waited:
		reaped = true
	case <-time.After(hangupGrace):
	}

	// ErrProcessNotFound is the ordinary answer for a group the hangup already
	// emptied, and is not a failure.
	if err := group.Kill(); err != nil && !errors.Is(err, platform.ErrProcessNotFound) {
		s.log.Warn("could not kill the session's process group", "error", err)
	}
	if reaped {
		return true
	}

	select {
	case <-waited:
		return true
	case <-time.After(hangupGrace):
		// The process is gone or unreachable, and the handler gains nothing by
		// waiting: returning is what releases the stream, and the deferred
		// sweep is still ahead of it.
		s.log.Warn("a killed session did not report its exit status", "grace", hangupGrace)
		return false
	}
}

// pumpInput carries the client's keystrokes and resizes to the terminal.
//
// It is given the stream and the terminal and nothing else: no audit record, no
// logger that could be handed a buffer, no counter that would tempt anyone into
// keeping a sample. See the package comment — this function and pumpOutput are
// the only two in the package that touch what a session carries.
func (s *session) pumpInput(stream grpc.BidiStreamingServer[sandboxdv1.ShellRequest, sandboxdv1.ShellResponse]) {
	for {
		req, err := stream.Recv()
		if err != nil {
			// EOF is the client half-closing: it will send no more input. The
			// session is not over — the command keeps running and its output
			// keeps flowing — so this pump simply stops. Anything else is the
			// stream ending, which the handler is already dealing with.
			return
		}

		switch event := req.GetEvent().(type) {
		case *sandboxdv1.ShellRequest_Data:
			s.touch()
			if _, err := s.tty.Write(event.Data); err != nil {
				// The terminal is gone: the session has ended or is ending, and
				// the handler is the one reporting it.
				return
			}
		case *sandboxdv1.ShellRequest_Resize:
			s.touch()
			size := sizeOf(event.Resize)
			if err := s.tty.Resize(size.columns, size.rows); err != nil {
				s.svc.log.Debug("could not resize the session terminal",
					"columns", size.columns, "rows", size.rows, "error", err)
			}
		case *sandboxdv1.ShellRequest_Open:
			// A second open. There is one terminal per stream, and honouring
			// this would mean either a second one nobody can address or
			// silently ignoring a request the caller believes was applied.
			s.svc.log.Debug("ignoring a second ShellOpen on a stream that already has a session")
		}
	}
}

// pumpOutput carries the terminal's output to the client.
//
// One stream, not two: a pseudo-terminal has already merged stdout and stderr,
// and there is nothing left to label. See pumpInput for what this function is
// deliberately not given.
//
// # A send that fails stops the sending and not the reading
//
// That difference is what keeps a Windows teardown from wedging, and it is the
// fourth thing on this branch to come out of go-pty's ConPTY wrapper not
// defending its own lifetime.
//
// Closing a pseudo-console is not a handle release: ClosePseudoConsole asks the
// console host to flush what it still holds, and it does not return until that
// flush has somewhere to go. The only reader of that pipe is this loop. So a
// pump that returned the moment a send failed — which is what a caller hanging
// up mid-output produces, since the very next Send fails — left the teardown in
// [Service.reap] calling Close on a pseudo-console nobody was draining, with
// the session's own output still queued behind it. That call is the *first*
// statement of the teardown, so a handler parked in it never reaches the group
// kill either: the RPC never returns, its process-limit slot is never released,
// its audit record is never written, and the process tree the close was
// supposed to end is still running. One session per occurrence, for the life of
// the daemon.
//
// So the loop keeps reading until the terminal itself ends the read, which is
// the close, and the close can now complete. Nothing more is sent: the session
// is over for the caller either way, and [sender] refuses anything after the
// exit in any case.
//
// It cannot spin: once sending has stopped nothing calls touch, so a session
// whose client is merely wedged rather than gone goes idle and is reaped on
// shell.idle_timeout, and every other ending closes the terminal directly.
func (s *session) pumpOutput() {
	buf := make([]byte, readBuffer)
	sending := true
	for {
		n, readErr := s.tty.Read(buf)
		if n > 0 && sending {
			s.touch()
			if err := s.send.within(sendStall, data(buf[:n])); err != nil {
				// Nobody to send to any more — the stream is gone, or the exit
				// has already been reported. Stop sending; keep reading. See
				// the doc comment.
				sending = false
			}
		}
		if readErr != nil {
			return
		}
	}
}

// sender serialises writes to the response stream.
//
// gRPC permits one goroutine sending and another receiving, but not two
// sending, and this stream has two: the output pump, continuously, and the
// handler, for the opened and exit messages. A mutex would be enough for
// correctness and not enough for liveness — a client that is still connected
// but has stopped reading parks the pump inside Send, holding the lock, and the
// handler would then block behind it forever with a session that has already
// ended. So the lock is a channel, taken with a deadline, and a send that
// cannot get in gives up rather than wedging the RPC. Ending the RPC is what
// tears the stream down and releases whoever is parked.
//
// It is also where "a ShellExit is always the last message on the stream" — the
// wire contract, stated in shell.proto — is actually enforced. Serialising the
// two senders is not enough on its own: the output pump is not joined before
// the exit is sent, and on Windows it is still running by definition, because a
// ConPTY's output pipe does not end when the session's command does and the
// drain before the exit is therefore a bounded wait rather than a join. A
// terminal message with a data message behind it is a stream a conforming
// client is entitled to have stopped reading at.
type sender struct {
	stream grpc.BidiStreamingServer[sandboxdv1.ShellRequest, sandboxdv1.ShellResponse]
	lock   chan struct{}

	// finished records that the terminal message has gone out. Read and
	// written only while holding the token, which is what makes it safe
	// without a second lock.
	finished bool
}

// errAfterExit is what a send gets once the session has reported how it ended.
// It is not a failure: the message simply has nowhere to go, because the stream
// is finished as far as the contract is concerned.
var errAfterExit = errors.New("shell: the session has already reported its exit")

func newSender(stream grpc.BidiStreamingServer[sandboxdv1.ShellRequest, sandboxdv1.ShellResponse]) *sender {
	s := &sender{stream: stream, lock: make(chan struct{}, 1)}
	s.lock <- struct{}{}
	return s
}

// within sends msg, waiting no longer than timeout for the stream to be free.
//
// A message that arrives after the session's ShellExit is refused rather than
// sent. See [sender].
func (s *sender) within(timeout time.Duration, msg *sandboxdv1.ShellResponse) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case token := <-s.lock:
		defer func() { s.lock <- token }()
	case <-timer.C:
		return status.Error(codes.Aborted,
			"the caller stopped reading its session stream, so the session was ended and its result could not be delivered")
	}

	if s.finished {
		return errAfterExit
	}
	// Set whether or not the send succeeds: a terminal message that could not
	// be delivered still ends the stream, and following it with output would
	// be the same contract break with a worse excuse.
	if msg.GetExit() != nil {
		s.finished = true
	}
	return s.stream.Send(msg)
}

func data(b []byte) *sandboxdv1.ShellResponse {
	return &sandboxdv1.ShellResponse{Event: &sandboxdv1.ShellResponse_Data{Data: b}}
}

func opened(tty platform.PTY, pid int, argv []string) *sandboxdv1.ShellResponse {
	return &sandboxdv1.ShellResponse{Event: &sandboxdv1.ShellResponse_Opened{
		Opened: &sandboxdv1.ShellOpened{
			Terminal: tty.Name(),
			Pid:      int32(pid), //nolint:gosec // a pid fits in 32 bits on every supported platform
			Argv:     argv,
		},
	}}
}

// exit renders the session's ending from the same values the audit record
// carries, so the two cannot disagree about how a session finished.
func exit(rec *sessionAudit, idle bool) *sandboxdv1.ShellResponse {
	result := &sandboxdv1.ShellExit{
		Signaled:    rec.signal != "",
		Signal:      rec.signal,
		IdleTimeout: idle,
		Duration:    durationpb.New(rec.duration),
	}
	if rec.exitCode != nil {
		result.ExitCode = *rec.exitCode
	}
	return &sandboxdv1.ShellResponse{Event: &sandboxdv1.ShellResponse_Exit{Exit: result}}
}
