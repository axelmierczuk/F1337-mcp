package exec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	osexec "os/exec"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	"github.com/axelmierczuk/fleet-mcp/internal/platform"
	"github.com/axelmierczuk/fleet-mcp/internal/security/policy"
)

// init registers ExecService with every fleet-agent daemon that links this
// package. See internal/cli/fleetagent/services.go for the import that does.
func init() {
	agent.Register("exec", New)
}

// execMethod is the RPC name written into every audit record.
const execMethod = "sandboxd.v1.ExecService/Exec"

// defaultKillGrace is how long a command has between SIGTERM and SIGKILL when
// it is killed for running too long or for losing its caller.
//
// It is a constant rather than a setting. Anything that handles SIGTERM at all
// handles it in milliseconds, and the alternative — an operator-tunable grace —
// is a knob whose only effect is to make an already-overrunning call take
// longer to return. The supervisor's process.default_grace_period is a
// different question: there the caller is asking a long-lived server to shut
// down cleanly, and waiting is the point.
//
// It buys nothing on Windows, which has no deliverable, catchable termination
// request for a process without a console: SignalTerm terminates the job object
// there, so the escalation ends at its first step and this grace is never
// waited out. That asymmetry belongs to the platform, not to this package —
// see internal/platform's ProcessGroup.Signal.
const defaultKillGrace = 5 * time.Second

// defaultIODrain bounds how long Wait keeps reading output after the process
// itself has exited.
//
// The case it exists for: a command spawns a child that inherits stdout and
// outlives it — `sh -c 'daemon &'` — so the read end never sees EOF even though
// the command finished. Without a bound, that call hangs until its timeout for
// a command that succeeded in a millisecond. With it, the pipes are closed, the
// result is reported, and the leftovers are killed with the rest of the group.
const defaultIODrain = 2 * time.Second

// errStreamStalled reports that the call was given up on because its output
// stream stopped accepting data.
//
// It is not a failure of the command — that was killed on schedule — but a
// failure to deliver its result, and the two are audited differently.
var errStreamStalled = errors.New("the caller stopped reading its output stream, so the command was killed and its result could not be delivered")

// Service implements sandboxd.v1.ExecService.
type Service struct {
	sandboxdv1.UnimplementedExecServiceServer

	log    *slog.Logger
	policy *policy.Policy
	audit  *policy.Audit

	// enabled mirrors exec.enabled. A disabled service is still registered so
	// that a caller gets an answer that names the setting rather than an
	// Unimplemented that reads like a version mismatch.
	enabled bool

	// baseEnv is the documented environment every command starts from,
	// computed once because it is derived from the daemon's own and that does
	// not change while it runs.
	baseEnv []string

	// defaultDir is where a command with no working_dir runs.
	defaultDir string

	killGrace time.Duration
	ioDrain   time.Duration
}

// New builds the exec service. It satisfies agent.Factory.
func New(deps agent.Deps) (agent.Service, error) {
	if deps.Policy == nil {
		return nil, errors.New("exec: agent.Deps.Policy is required; the caps and command lists are enforced centrally")
	}
	if deps.Audit == nil {
		return nil, errors.New("exec: agent.Deps.Audit is required")
	}

	log := deps.Log.With("service", "exec")
	base := BaseEnv()
	dir := defaultWorkingDir(base)

	s := &Service{
		log:        log,
		policy:     deps.Policy,
		audit:      deps.Audit,
		enabled:    deps.Config.Exec.IsEnabled(),
		baseEnv:    base,
		defaultDir: dir,
		killGrace:  defaultKillGrace,
		ioDrain:    defaultIODrain,
	}

	allow, deny := deps.Policy.Rules()
	log.Info("exec service ready",
		"enabled", s.enabled,
		"default_working_dir", dir,
		// Names only. A base environment logged with its values would put
		// whatever the daemon inherited into the daemon's own log, which is
		// the leak the base environment exists to prevent.
		"base_environment", sortedKeys(base),
		"allow_commands", allow,
		"deny_commands", deny,
		"command_policy", policyDescription(deps.Policy),
		"audit", deps.Audit.Enabled(),
		"audit_required", deps.Audit.Required(),
	)
	return s, nil
}

func policyDescription(p *policy.Policy) string {
	if !p.Restricted() {
		return "allow-all (the default; this agent runs whatever it is asked to)"
	}
	return "restricted by allow_commands/deny_commands, which are operational guardrails and not a security boundary"
}

// DefaultWorkingDir is where a command that names no directory runs on this
// host.
//
// Exported for ShellService, so a session that names no working directory
// starts in the same place a command would. See defaultWorkingDir for why it is
// the home directory rather than the daemon's own.
func DefaultWorkingDir() string { return defaultWorkingDir(BaseEnv()) }

// defaultWorkingDir is where a command with no working_dir runs.
//
// The account's home directory, because that is where a toolchain expects to
// find its caches and where a build that writes a stray file does the least
// damage. A daemon started by systemd or launchd has "/" as its working
// directory, which is the one place a build must not be able to scribble in, so
// inheriting the daemon's is not an option. The temp directory is the fallback
// for an account with no usable home.
func defaultWorkingDir(base []string) string {
	if home, ok := envValue(base, homeVar); ok && isDir(home) {
		return home
	}
	return os.TempDir()
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// Register attaches ExecService to the daemon's gRPC server.
func (s *Service) Register(r grpc.ServiceRegistrar) {
	sandboxdv1.RegisterExecServiceServer(r, s)
}

// Exec runs a command to completion, streaming its output, and ends the stream
// with an ExecResult.
//
// # A command that fails is a successful RPC
//
// A non-zero exit is reported in ExecResult.exit_code, never as an RPC error.
// The caller is a model trying to diagnose a build, and it needs the output and
// the status together; an error result throws the output away and leaves it
// with "the call failed" for a compiler that did exactly what it should have.
//
// RPC errors are reserved for requests this agent would not run at all: an
// argv that names nothing executable, a working directory that is not one, a
// timeout above the agent's maximum, a command the policy refuses, a full
// concurrency limit — and, when audit.required is set, a call whose record
// could not be written.
//
// # There is no path confinement here
//
// working_dir is an ordinary path. An agent that runs commands cannot be
// confined by a path check — the command runs whatever it likes with the
// account's full reach — so the path jail is wired in only on an agent with
// exec disabled, and this service does not pretend otherwise. See
// docs/security.md.
func (s *Service) Exec(req *sandboxdv1.ExecRequest, stream sandboxdv1.ExecService_ExecServer) error {
	ctx := stream.Context()
	principal, _ := agent.PrincipalFromContext(ctx)

	rec := policy.Record{
		Time: time.Now().UTC(),
		// Both, always together: the name and what established it. A record
		// carrying one without the other is one an operator cannot read — see
		// policy.Record.PrincipalSource.
		Principal:       principal.String(),
		PrincipalSource: principal.Source(),
		RPC:             execMethod,
		Argv:            req.GetArgv(),
		Shell:           req.GetShell(),
	}

	if !s.enabled {
		rec.Outcome = policy.OutcomeDenied
		rec.Rule = "exec.enabled: false"
		return s.finish(rec, status.Error(codes.FailedPrecondition,
			"this agent runs with exec.enabled: false, so ExecService is turned off; it is the configuration in which allowed_roots is a real boundary"))
	}
	if len(req.GetArgv()) == 0 || req.GetArgv()[0] == "" {
		return s.fail(rec, codes.InvalidArgument, "argv is empty: argv[0] must name the executable to run")
	}

	timeout, err := s.policy.Timeout(req.GetTimeout().AsDuration())
	if err != nil {
		return s.fail(rec, codes.InvalidArgument, "%s", err)
	}

	env, err := mergeEnv(s.baseEnv, req.GetEnv())
	if err != nil {
		// The entry is quoted to the caller and not to the log: "FOO" meaning
		// "FOO=bar" and "=bar" meaning "FOO=bar" are both ways for a value to
		// arrive inside a string this would otherwise write down.
		return s.failRedacted(rec,
			"a request environment entry was malformed; the entry itself is not recorded, because this log never carries environment data",
			codes.InvalidArgument, "%s", err)
	}

	dir, err := s.workingDir(req.GetWorkingDir())
	if err != nil {
		return s.fail(rec, codes.InvalidArgument, "%s", err)
	}
	rec.WorkingDir = dir

	argv := req.GetArgv()
	if req.GetShell() {
		argv = shellArgv(argv)
	}
	rec.Argv = argv

	pathEnv, _ := envValue(env, "PATH")
	pathExt, _ := envValue(env, "PATHEXT")
	cmd, lookupErr := policy.Resolve(argv, dir, pathEnv, pathExt)
	rec.Path = cmd.Path

	// Policy before the lookup failure, so that a denied command that also does
	// not exist is recorded as denied. The refusal is the fact worth keeping,
	// and it is the one the operator asked to be told about.
	if decision := s.policy.Evaluate(cmd); !decision.Allowed {
		rec.Outcome = policy.OutcomeDenied
		rec.Rule = decision.Rule
		rec.Error = decision.Reason
		return s.finish(rec, status.Errorf(codes.PermissionDenied, "%s", decision.Reason))
	}
	if lookupErr != nil {
		// The caller's error names the PATH that was searched, which is the
		// only thing that makes "not found" actionable. The record does not:
		// that PATH is an environment value, and on a request that set one it
		// is a value the caller chose.
		return s.failRedacted(rec,
			fmt.Sprintf("could not resolve %q to an executable; the PATH searched is an environment value and is not recorded", cmd.Requested),
			codes.NotFound, "%s", lookupErr)
	}

	// A slot in the agent-wide process limit. The wait for one is bounded by
	// the command's own timeout: waiting longer than the command was allowed to
	// run for turns a busy agent into a hung tool call, and a caller that set no
	// deadline of its own would otherwise wait indefinitely for a slot.
	//
	// The timeout bounds the queue wait and then the command separately, so a
	// call on a saturated agent can take up to twice it before returning. The
	// alternative — spending the queue wait out of the command's budget — hands
	// a command that waited its whole timeout no time at all to run, which
	// fails calls for a reason the caller cannot see or act on. docs/tools.md
	// says which one this is.
	acquireCtx, cancelAcquire := context.WithTimeout(ctx, timeout)
	release, err := s.policy.Acquire(acquireCtx)
	cancelAcquire()
	if err != nil {
		// Which context ended decides what happened. The caller hanging up
		// while queued is not the agent running out of capacity, and recording
		// it as one would put a capacity failure in the audit log for every
		// client that lost patience or lost its connection.
		if ctx.Err() != nil {
			rec.Outcome = policy.OutcomeCancelled
			rec.Error = "the caller went away while waiting for a free process slot"
			return s.finish(rec, status.Errorf(codes.Canceled, "%s", rec.Error))
		}
		return s.fail(rec, codes.ResourceExhausted, "%s", err)
	}
	defer release()

	sink := newSink(stream, s.policy.OutputCap(req.GetMaxOutputBytes()))
	outcome, err := s.run(ctx, runSpec{
		cmd:     cmd,
		dir:     dir,
		env:     env,
		stdin:   req.GetStdin(),
		timeout: timeout,
		shell:   req.GetShell(),
		sink:    sink,
	})

	// The command is over. run has waited for it, swept its group and closed
	// it, so the slot no longer stands for anything running on this host, and
	// everything left in this handler is delivery.
	//
	// Delivery is where a caller that has stopped reading parks the handler:
	// sendResult below is a plain Send, and grpc-go returns from one of those
	// only when the flow-control window opens or the stream ends — neither of
	// which a client that stays connected, stops calling Recv and set no
	// deadline will ever do. Holding the slot across that hands one such
	// caller a piece of the agent's capacity for the life of the daemon, one
	// piece per call, and the watchdog cannot take it back: by the time Wait
	// returns, done is closed and the path that bounds a stalled *output*
	// stream is over. So the slot goes back here instead, ahead of the audit
	// write and the result.
	//
	// This is a bound on the slot rather than on the send, and that is the
	// point: the command has already succeeded, so there is no deadline short
	// enough to protect capacity and long enough not to throw away the output
	// of a command that worked. A wedged caller now costs a goroutine and its
	// own stream, both of which end when its connection does, and costs the
	// next caller nothing. See the PR for the two options this was chosen
	// over.
	//
	// release is idempotent — see policy.Acquire — so the deferred call above
	// stays correct. What it still guards, and all it now guards, is a panic
	// between Acquire and this line: every ordinary path out of the handler is
	// below here. It is kept for that. A slot leaked by a panicking handler is
	// exactly the same permanent loss of capacity as the one this line fixes,
	// and the daemon survives a panicking handler by design — see
	// TestServer_PanickingHandlerDoesNotKillTheDaemon.
	release()

	if errors.Is(err, errStreamStalled) {
		// The command ran and was killed, so the record says what happened to
		// it rather than reporting a request that failed. Nothing here reads
		// the sink: its lock is held by the copier still parked in Send.
		rec.Outcome = outcome.auditOutcome()
		rec.TimedOut = outcome.timedOut
		rec.DurationMS = outcome.duration.Milliseconds()
		rec.Error = err.Error()
		return s.finish(rec, status.Errorf(codes.Aborted, "%s", err))
	}
	if err != nil {
		return s.fail(rec, codes.Internal, "%s", err)
	}

	trunc := sink.truncation()
	rec.Outcome = outcome.auditOutcome()
	rec.ExitCode = &outcome.exitCode
	rec.Signal = outcome.signal
	rec.TimedOut = outcome.timedOut
	rec.Truncated = trunc.GetTruncated()
	rec.DurationMS = outcome.duration.Milliseconds()

	// A stream that has already failed is reported as it is: the command ran,
	// the record says so, and the RPC ends with the send error rather than
	// with a result nobody can receive.
	if sendErr := sink.sendErr(); sendErr != nil {
		rec.Error = sendErr.Error()
		return s.finish(rec, sendErr)
	}

	// The audit record is written before the terminal result is sent, so that
	// audit.required can still withhold it. Output chunks are already on the
	// wire by now — they are streamed as the command produces them, which is
	// the point of the RPC — so "the call failed" here means the caller does
	// not learn the exit status, not that it saw nothing.
	if err := s.finish(rec, nil); err != nil {
		return err
	}

	return sink.sendResult(&sandboxdv1.ExecResult{
		ExitCode:   outcome.exitCode,
		Signaled:   outcome.signal != "",
		Signal:     outcome.signal,
		TimedOut:   outcome.timedOut,
		Duration:   durationpb.New(outcome.duration),
		Truncation: trunc,
	})
}

// workingDir resolves the directory a command runs in.
//
// There is no jail to resolve against — see the Exec doc comment — so this
// makes the path absolute, checks that it is a directory, and stops there. The
// check is worth doing because the alternative is os/exec reporting a chdir
// failure with the command's name in it, which reads like the command is
// missing.
func (s *Service) workingDir(requested string) (string, error) {
	if requested == "" {
		return s.defaultDir, nil
	}
	dir, err := platform.NormalizePath(s.defaultDir, requested)
	if err != nil {
		return "", fmt.Errorf("working_dir %q: %w", requested, err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("working_dir %q does not exist on this host", dir)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("working_dir %q is not a directory", dir)
	}
	return dir, nil
}

// runSpec is everything run needs that survived validation.
type runSpec struct {
	cmd     policy.Command
	dir     string
	env     []string
	stdin   []byte
	timeout time.Duration
	shell   bool
	sink    *sink
}

// outcome is how a command ended.
type outcome struct {
	exitCode int32
	signal   string
	timedOut bool
	// cancelled records that the caller went away rather than the command
	// overrunning. Both kill the process group; only one is the command's
	// fault, and the audit record distinguishes them.
	cancelled bool
	duration  time.Duration
}

func (o outcome) auditOutcome() policy.Outcome {
	switch {
	case o.timedOut:
		return policy.OutcomeTimedOut
	case o.cancelled:
		return policy.OutcomeCancelled
	default:
		return policy.OutcomeOK
	}
}

// run starts the command, streams its output, and waits for it.
//
// The returned error is for a failure to run the command at all. A command that
// ran and failed returns an outcome, not an error.
func (s *Service) run(ctx context.Context, spec runSpec) (outcome, error) {
	group, err := platform.NewProcessGroup(platform.GroupConfig{
		// The agent holds the only handle for the life of the call, so on
		// Windows the job object dies with it and takes the tree along. Exec
		// is the one caller that wants this: nothing it starts is supposed to
		// outlive the RPC. See platform.GroupConfig.
		KillOnClose: true,
	})
	if err != nil {
		return outcome{}, fmt.Errorf("preparing the process group: %w", err)
	}
	defer func() {
		// The call takes its process tree with it. A grandchild that outlived
		// its parent — `sh -c 'sleep 100 &'` leaves one behind — must not
		// outlive the RPC: exec is one-shot by contract, and docs/tools.md
		// points anything longer-lived at fleet_process_start.
		//
		// On Windows this is the whole of it: closing the last handle to the job
		// terminates every process still inside. On Unix the killing has
		// already happened, in waitForCommand, and deliberately not here — the
		// sweep is only safe to send while the leader is unreaped, and by the
		// time a deferred call runs it is not. See waitForCommand for what that
		// ordering is worth.
		if err := group.Close(); err != nil {
			s.log.Warn("could not release the process group after exec; on Windows this is what kills the tree",
				"error", err)
		}
	}()

	// Args carries argv[0] as the caller wrote it while Path carries the file
	// that was resolved from it. Rebuilding argv[0] from the resolved path
	// would change the command's own idea of its name, which busybox-style
	// multi-call binaries and anything printing usage read.
	cmd := &osexec.Cmd{
		Path:   spec.cmd.Path,
		Args:   spec.cmd.Argv,
		Dir:    spec.dir,
		Env:    spec.env,
		Stdout: spec.sink.writer(sandboxdv1.Stream_STREAM_STDOUT),
		Stderr: spec.sink.writer(sandboxdv1.Stream_STREAM_STDERR),
		// Bounds the wait for output after the process exits; see
		// defaultIODrain. Without a Context on the Cmd this is the only thing
		// WaitDelay does, which is exactly what is wanted: the kill escalation
		// below aims at the group, and os/exec's aims at the leader.
		WaitDelay: s.ioDrain,
	}
	if len(spec.stdin) > 0 {
		// os/exec copies this into the child's stdin pipe and closes it when
		// the copy finishes, which is the "written then closed" the request
		// documents. A command that never reads it does not wedge the call:
		// WaitDelay closes the pipe, and unlike the output copiers this one is
		// blocked on a pipe rather than on the caller's stream.
		cmd.Stdin = bytes.NewReader(spec.stdin)
	}
	group.ConfigureCommand(cmd)
	if spec.shell {
		// After ConfigureCommand, which is what allocates SysProcAttr.
		applyShellCommandLine(cmd, spec.cmd.Argv)
	}

	started := time.Now()
	if err := cmd.Start(); err != nil {
		return outcome{}, fmt.Errorf("starting %s: %w", spec.cmd.Path, err)
	}
	if err := group.Adopt(cmd.Process); err != nil {
		// The command is running and reachable; only its descendants are not
		// guaranteed to be. Saying so beats failing a call that has already
		// started a process.
		s.log.Warn("command is running outside its process group; descendants may survive a kill",
			"pid", cmd.Process.Pid, "error", err)
	}

	done := make(chan struct{})
	// Closed exactly once, on every path out of this function, so the watchdog
	// can never outlive the call it is watching.
	stopWatching := sync.OnceFunc(func() { close(done) })
	defer stopWatching()

	watcher := s.watch(ctx, group, spec.timeout, done)

	// Wait runs on its own goroutine because it is not always possible to
	// finish. os/exec's Wait waits for the output-copying goroutines
	// unconditionally once it has closed the pipes — awaitGoroutines does a
	// bare receive on their result — and a copier is not necessarily waiting on
	// a pipe: this one writes to a gRPC stream, and grpc-go's Send parks until
	// the stream's flow-control window opens. A caller that is still connected
	// but has stopped calling Recv never opens it. So the wait can outlive the
	// command by any amount, and the handler must not: the RPC ending is
	// precisely what tears the stream down and releases that Send. The channel
	// is buffered so the goroutine can finish and exit after this function has
	// returned.
	//
	// It is also where the post-exec sweep goes out, because the one moment it
	// is safe to send is between the leader exiting and this Wait collecting
	// it; see waitForCommand.
	waited := make(chan error, 1)
	go func() { waited <- waitForCommand(cmd, group, s.log) }()

	var waitErr error
	select {
	case waitErr = <-waited:
		stopWatching()
	case <-watcher.abandon:
		stopWatching()
		<-watcher.finished
		// Deliberately nothing from cmd or from the sink here. ProcessState
		// belongs to the Wait still running on the other goroutine, and the
		// sink's lock is held by the copier parked in Send — touching either
		// would trade a hung RPC for a data race or a deadlock.
		return outcome{
			duration:  time.Since(started),
			timedOut:  watcher.timedOut.Load(),
			cancelled: watcher.cancelled.Load(),
		}, errStreamStalled
	}
	<-watcher.finished

	result := outcome{
		duration:  time.Since(started),
		timedOut:  watcher.timedOut.Load(),
		cancelled: watcher.cancelled.Load(),
	}
	if cmd.ProcessState == nil {
		return outcome{}, fmt.Errorf("running %s: %w", spec.cmd.Path, waitErr)
	}
	result.exitCode = int32(cmd.ProcessState.ExitCode()) //nolint:gosec // an exit code is 8 bits on every supported platform, or -1 for a signal
	if sig, ok := terminatingSignal(cmd.ProcessState); ok {
		result.signal = sig
	}
	if errors.Is(waitErr, osexec.ErrWaitDelay) {
		// The process exited but something still held its output pipes — a
		// grandchild, usually. The exit status is real; the tail of the output
		// is whatever had already been read.
		s.log.Debug("stopped reading output after the process exited",
			"path", spec.cmd.Path, "drain", s.ioDrain)
	}
	return result, nil
}

// watcher is the goroutine that bounds a running command, and the state run
// reads back from it.
type watcher struct {
	// timedOut and cancelled record why the command was killed. run reads them
	// only after finished is closed, which is what publishes the writes.
	timedOut  atomic.Bool
	cancelled atomic.Bool

	// abandon is closed when waiting for the command has stopped being able to
	// end, and the handler must return without it. See run.
	abandon chan struct{}

	// finished is closed when the goroutine has returned. run waits for it
	// before returning, for two things it still buys and one it never did.
	//
	// It publishes the writes above: timedOut and cancelled are read only after
	// this is closed, which is what makes them the finished goroutine's answer
	// rather than a sample of one in progress. And it orders the watcher
	// against run's deferred group.Close(), which on Windows is what terminates
	// the job — a signal racing that would be a signal to a handle the deferred
	// call has closed.
	//
	// What it never did was order the watcher against the *collection*, which
	// is the thing that releases a process group id. It could not: run closes
	// done after Wait has already returned, so by the time this goroutine can
	// see anything the id is long gone. That ordering is [platform.ProcessGroup]'s
	// now, and it is enforced rather than arranged; see watch.
	finished chan struct{}
}

// watch kills the process group when the command runs out of time or its
// caller goes away, and gives up on the call when even that does not end it.
//
// SIGTERM to the group, then SIGKILL to the group after the grace period. The
// group and not the leader: signalling `sh -c 'make -j8'` alone leaves eight
// compilers running, and the caller who asked for the command to stop has no
// way to reach them. os/exec's own cancellation cannot do this — Cmd.Cancel
// kills Cmd.Process, and WaitDelay's escalation kills Cmd.Process — which is
// why the context is watched here instead of being handed to CommandContext.
//
// On Windows there is no grace step to speak of: the platform has no
// deliverable, catchable termination request for a process without a console,
// so SignalTerm terminates the job object outright and the escalation collapses
// into its first step.
//
// Every wait below selects on done, so closing it returns the goroutine
// promptly from wherever it is.
//
// # Neither signal below can reach anything but this command's group
//
// That is #105, and the guarantee is the group's rather than this function's.
// Both selects on done here are check-then-act: select picks at random between
// two ready cases, and done can close in the gap between the select returning
// and the next line running. Neither is a guard on the signal, and neither
// could be — done closes after waitForCommand has returned, which is after the
// collection that releases the group id, so a goroutine that consults it is
// reading an answer that went stale seconds ago. os/exec's Wait does not return
// until the output copiers do, and a grandchild that inherited the pipes holds
// them for the whole of Cmd.WaitDelay.
//
// What makes the signals safe is that the collection goes through the group:
// [platform.ProcessGroup.SweepAndCollect] marks the id released under the same
// lock these signals take, and does it before the leader is collected, so each
// of them either reaches a group whose leader is still holding its id or is
// refused with ErrGroupReleased. The selects on done are left where they are
// because they are still worth having — an early return costs nothing, and a
// kill nobody needs is a kill not sent — but nothing rests on them.
//
// The guard on the *reporting* below is a different question and is still load
// bearing: it decides what the audit record says happened, not what is sent.
func (s *Service) watch(ctx context.Context, group *platform.ProcessGroup, timeout time.Duration, done <-chan struct{}) *watcher {
	w := &watcher{abandon: make(chan struct{}), finished: make(chan struct{})}

	go func() {
		defer close(w.finished)

		timer := time.NewTimer(timeout)
		defer timer.Stop()

		select {
		case <-done:
			return
		case <-timer.C:
			w.timedOut.Store(true)
		case <-ctx.Done():
			// The stream's context. Cancelled means the caller hung up or the
			// daemon is draining; either way nothing is left to receive the
			// output, and the command must not keep running.
			w.cancelled.Store(true)
		}

		// A command that finished in the same instant is not a command that
		// was killed. select picks at random between two ready cases, so
		// without this a client that cancels as its command exits gets a
		// result marked cancelled — and the audit record says the agent killed
		// something it did not.
		//
		// About the record, and only about the record. It is not what keeps the
		// signals below aimed at this command's group; see the doc comment for
		// what is, and why nothing written here could be.
		select {
		case <-done:
			w.timedOut.Store(false)
			w.cancelled.Store(false)
			return
		default:
		}

		if s.signalTree(group.Signal(platform.SignalTerm), "TERM") {
			// The command had already been collected, so nothing was killed and
			// nothing is left to escalate to. Both halves of that matter: the
			// record must not say the agent killed a command that had finished
			// on its own — which is what the guard above is for and what it
			// cannot always see, because done closes only once Wait has
			// returned — and a second signal would be refused for the same
			// reason this one was.
			//
			// The drain below is still owed. A collected command is not a
			// finished call: Wait can still be parked on a copier inside the
			// caller's Send, and that is the one thing WaitDelay does not bound.
			w.timedOut.Store(false)
			w.cancelled.Store(false)
		} else {
			grace := time.NewTimer(s.killGrace)
			defer grace.Stop()
			select {
			case <-done:
				return
			case <-grace.C:
			}

			s.signalTree(group.Kill(), "KILL")
		}

		// The process is gone, so Wait returns in milliseconds — unless
		// something downstream of the output pipes is stuck, which is the case
		// this exists for: a caller that is still connected but has stopped
		// reading parks the copier inside grpc's Send, and os/exec's Wait waits
		// for that copier however long it takes. Past this point the handler
		// gains nothing by waiting and costs the agent a concurrency slot, an
		// audit record, and an RPC that never ends.
		drain := time.NewTimer(s.ioDrain)
		defer drain.Stop()
		select {
		case <-done:
		case <-drain.C:
			s.log.Warn("giving up on a command whose output stream stopped accepting data",
				"drain", s.ioDrain, "timed_out", w.timedOut.Load(), "cancelled", w.cancelled.Load())
			close(w.abandon)
		}
	}()

	return w
}

// signalTree reports what became of one of the watcher's signals to the
// command's process group.
//
// Three answers and only one of them is a failure:
//
//   - ErrGroupReleased: the command was collected while this goroutine was
//     deciding to signal it, so the signal was not sent. That is #105's
//     interleaving arriving and being refused rather than delivered to whatever
//     the kernel gave the group id to next — see watch. It is reported back
//     because it is also the answer to a question the watcher cannot settle for
//     itself: a command whose group has been released is a command that
//     finished, so nothing was killed and the record must not say otherwise.
//     Logged at DEBUG because it is the ordinary ending of a race rather than
//     something an operator has to act on.
//   - ErrProcessNotFound on its own: the group emptied between the decision and
//     the signal. Nothing to say and nothing to do.
//   - anything else: the command is still running and the agent could not stop
//     it, which is the caller's timeout not being honoured.
//
// ErrGroupReleased is tested for first because it wraps ErrProcessNotFound, and
// it is the one answer the caller acts on: released is what it reports.
func (s *Service) signalTree(err error, signal string) (released bool) {
	switch {
	case err == nil:
	case errors.Is(err, platform.ErrGroupReleased):
		s.log.Debug("the command had already been collected, so the timeout's signal was not sent",
			"signal", signal)
		return true
	case errors.Is(err, platform.ErrProcessNotFound):
	default:
		s.log.Warn("could not signal the process group", "signal", signal, "error", err)
	}
	return false
}

// fail records a refused request and returns the error the caller sees.
func (s *Service) fail(rec policy.Record, code codes.Code, format string, args ...any) error {
	err := status.Errorf(code, format, args...)
	rec.Outcome = policy.OutcomeError
	rec.Error = status.Convert(err).Message()
	return s.finish(rec, err)
}

// failRedacted is fail for a refusal whose message quotes something the record
// must not hold.
//
// Record's contract is that no environment value ever reaches it, and Record
// has no field that could carry one — but an error string can, and two of them
// did: the PATH a failed lookup searched, and a malformed environment entry
// quoted back at its sender. Both are environment data, and on a request that
// supplied its own env both are values the caller chose.
//
// The asymmetry is deliberate rather than a compromise. Telling the caller
// costs nothing: it sent the value, and an exec caller can read the agent's
// environment with a command anyway — this service is unconfined by design.
// Writing it down does cost something, and it is the whole reason the record
// has no env field: this file gets shipped off-box, read by people debugging
// something unrelated, and kept long after the credential in it should have
// been rotated. Everything an operator needs to act on — the command, the
// outcome, the rule, the working directory — is already in a field of its own.
func (s *Service) failRedacted(rec policy.Record, recorded string, code codes.Code, format string, args ...any) error {
	rec.Outcome = policy.OutcomeError
	rec.Error = recorded
	return s.finish(rec, status.Errorf(code, format, args...))
}

// finish writes the audit record and returns the error this RPC ends with.
//
// This is where audit.required is a real choice rather than a label. With it
// set, a record that could not be written fails the call — including a call
// that had otherwise succeeded, because an agent configured to act only when it
// can record what it did must not report success for an unrecorded command.
// Without it, the failure is logged at ERROR and the call proceeds, which is
// the other half of the same decision: an audit volume that fills must not take
// the fleet down with it.
func (s *Service) finish(rec policy.Record, rpcErr error) error {
	err := s.audit.Write(rec)
	if err == nil {
		return rpcErr
	}

	s.log.Error("audit record was not written",
		"path", s.audit.Path(),
		"required", s.audit.Required(),
		"rpc", rec.RPC,
		"outcome", rec.Outcome,
		"principal", rec.Principal,
		"error", err)

	if !s.audit.Required() {
		return rpcErr
	}
	if rpcErr != nil {
		return status.Errorf(codes.Internal,
			"audit.required is set and this call's record could not be written (%v); the call had already failed: %s",
			err, status.Convert(rpcErr).Message())
	}
	return status.Errorf(codes.Internal,
		"audit.required is set and this call's record could not be written, so its result is withheld: %v", err)
}
