package shell

import (
	"context"
	"errors"
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

// session is one running terminal: the pseudo-terminal, the stream it is
// carried on, and the activity clock the idle timeout reads.
type session struct {
	svc  *Service
	tty  platform.PTY
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
	tty, err := platform.OpenPTY()
	if err != nil {
		rec.outcome, rec.failure = policy.OutcomeError, "this host could not allocate a pseudo-terminal"
		if errors.Is(err, platform.ErrUnsupported) {
			return status.Errorf(codes.Unimplemented, "this host cannot allocate a pseudo-terminal: %s", err)
		}
		return status.Errorf(codes.Internal, "allocating a pseudo-terminal: %s", err)
	}
	// Closed on every path out, and it is not only cleanup: on Unix this is the
	// terminal hanging up, which is what tells the far end the session ended.
	// A second Close from the teardown below is a no-op.
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
	if err := platform.ReleasePTYChildEnd(tty); err != nil {
		s.log.Warn("could not release the agent's copy of the session terminal; the session's last output may be delayed",
			"error", err)
	}

	sess := &session{svc: s, tty: tty, send: newSender(stream)}
	sess.touch()

	if err := sess.send.within(sendStall, opened(tty, cmd.Process.Pid, spec.command.Argv)); err != nil {
		rec.outcome, rec.failure = policy.OutcomeError, "the session could not be reported as open"
		rec.duration = time.Since(started)
		return err
	}

	// Both pumps are started and neither is joined. The output pump ends when
	// the terminal is closed, which the defer above guarantees; the input pump
	// is parked in Recv, and what ends it is this handler returning — gRPC
	// cancels the stream when it does, which is the only thing that can unblock
	// a receive from a client that is simply sitting there. Waiting for it here
	// would be waiting for the thing this return causes.
	go sess.pumpInput(stream)
	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		sess.pumpOutput()
	}()

	// Wait on its own goroutine, so this handler is never stuck behind a
	// process that will not exit. The channel is buffered so that goroutine can
	// finish after this function has returned.
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()

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
// Hang up first, then kill. The hangup is what an interactive shell understands
// — on Unix, closing the terminal sends SIGHUP to its foreground process group,
// and a shell that receives one passes it on to its own jobs, which are in
// process groups this agent cannot name. The kill is what makes the guarantee
// unconditional for everything still in the session's own group. Neither alone
// is enough: the hangup can be ignored, and the group signal cannot reach a job
// the shell put in a group of its own.
//
// A job the operator deliberately detached — `nohup`, `disown`, `setsid` —
// survives both, exactly as it does over ssh. That is a property of what they
// asked for rather than a gap in this teardown.
func (s *Service) reap(sess *session, group *platform.ProcessGroup, waited <-chan error) bool {
	if err := sess.tty.Close(); err != nil {
		s.log.Debug("closing the session terminal reported an error; the session is being killed anyway", "error", err)
	}

	select {
	case <-waited:
		return true
	case <-time.After(hangupGrace):
	}

	if err := group.Kill(); err != nil && !errors.Is(err, platform.ErrProcessNotFound) {
		s.log.Warn("could not kill the session's process group", "error", err)
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
func (s *session) pumpOutput() {
	buf := make([]byte, readBuffer)
	for {
		n, readErr := s.tty.Read(buf)
		if n > 0 {
			s.touch()
			if err := s.send.within(sendStall, data(buf[:n])); err != nil {
				return
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
type sender struct {
	stream grpc.BidiStreamingServer[sandboxdv1.ShellRequest, sandboxdv1.ShellResponse]
	lock   chan struct{}
}

func newSender(stream grpc.BidiStreamingServer[sandboxdv1.ShellRequest, sandboxdv1.ShellResponse]) *sender {
	s := &sender{stream: stream, lock: make(chan struct{}, 1)}
	s.lock <- struct{}{}
	return s
}

// within sends msg, waiting no longer than timeout for the stream to be free.
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
