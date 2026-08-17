package exec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	osexec "os/exec"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/agent"
	"github.com/axelmierczuk/sandboxd-mcp/internal/platform"
	"github.com/axelmierczuk/sandboxd-mcp/internal/security/policy"
)

// init registers ExecService with every sandboxd-agent daemon that links this
// package. See internal/cli/sandboxdagent/services.go for the import that does.
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
		Time:      time.Now().UTC(),
		Principal: principal,
		RPC:       execMethod,
		Argv:      req.GetArgv(),
		Shell:     req.GetShell(),
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
		return s.fail(rec, codes.InvalidArgument, "%s", err)
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
		return s.fail(rec, codes.NotFound, "%s", lookupErr)
	}

	// A slot in the agent-wide process limit. The wait for one is bounded by
	// the command's own timeout: waiting longer than the command was allowed to
	// run for turns a busy agent into a hung tool call, and a caller that set no
	// deadline of its own would otherwise wait indefinitely for a slot.
	acquireCtx, cancelAcquire := context.WithTimeout(ctx, timeout)
	release, err := s.policy.Acquire(acquireCtx)
	cancelAcquire()
	if err != nil {
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
		// Kill first, then close. On Windows closing the last handle is what
		// terminates the job, but on Unix a process group holds no resource
		// and nothing has yet reached a grandchild that outlived its parent —
		// `sh -c 'sleep 100 &'` leaves one behind on every platform. Exec is
		// one-shot by contract (docs/tools.md points anything longer-lived at
		// sandbox_process_start), so the call takes its tree with it.
		//
		// Only when the child really leads its own group, though. Without that
		// the group has degraded to "signal this one pid", and by this point
		// Wait has reaped it — so the pid may already belong to something
		// else, and the sweep would kill an unrelated process. There is
		// nothing left to sweep in that case anyway: a leader that never got
		// its own group had no group for its descendants to be in.
		if group.Isolated() {
			if err := group.Kill(); err != nil && !errors.Is(err, platform.ErrProcessNotFound) {
				s.log.Debug("sweeping the process group after exec", "error", err)
			}
		}
		if err := group.Close(); err != nil {
			s.log.Debug("closing the process group after exec", "error", err)
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
		// documents. A command that never reads it cannot wedge the call:
		// WaitDelay closes the pipe.
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
	watchdog := s.watch(ctx, group, spec.timeout, done)

	waitErr := cmd.Wait()
	close(done)
	killed := <-watchdog

	result := outcome{
		duration:  time.Since(started),
		timedOut:  killed.timedOut,
		cancelled: killed.cancelled,
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

// killOutcome reports why the watchdog killed the process, if it did.
type killOutcome struct {
	timedOut  bool
	cancelled bool
}

// watch kills the process group when the command runs out of time or its
// caller goes away.
//
// SIGTERM to the group, then SIGKILL to the group after the grace period. The
// group and not the leader: signalling `sh -c 'make -j8'` alone leaves eight
// compilers running, and the caller who asked for the command to stop has no
// way to reach them. os/exec's own cancellation cannot do this — Cmd.Cancel
// kills Cmd.Process, and WaitDelay's escalation kills Cmd.Process — which is
// why the context is watched here instead of being handed to CommandContext.
//
// The returned channel yields once, after done is closed.
func (s *Service) watch(ctx context.Context, group *platform.ProcessGroup, timeout time.Duration, done <-chan struct{}) <-chan killOutcome {
	result := make(chan killOutcome, 1)

	go func() {
		timer := time.NewTimer(timeout)
		defer timer.Stop()

		var killed killOutcome
		select {
		case <-done:
			result <- killed
			return
		case <-timer.C:
			killed.timedOut = true
		case <-ctx.Done():
			// The stream's context. Cancelled means the caller hung up or the
			// daemon is draining; either way nothing is left to receive the
			// output, and the command must not keep running.
			killed.cancelled = true
		}

		// A command that finished in the same instant is not a command that
		// was killed. select picks at random between two ready cases, so
		// without this a client that cancels as its command exits gets a
		// result marked cancelled — and the audit record says the agent killed
		// something it did not.
		select {
		case <-done:
			result <- killOutcome{}
			return
		default:
		}

		if err := group.Signal(platform.SignalTerm); err != nil && !errors.Is(err, platform.ErrProcessNotFound) {
			s.log.Warn("could not signal the process group", "signal", "TERM", "error", err)
		}

		grace := time.NewTimer(s.killGrace)
		defer grace.Stop()
		select {
		case <-done:
		case <-grace.C:
			if err := group.Kill(); err != nil && !errors.Is(err, platform.ErrProcessNotFound) {
				s.log.Warn("could not kill the process group", "error", err)
			}
			<-done
		}
		result <- killed
	}()

	return result
}

// fail records a refused request and returns the error the caller sees.
func (s *Service) fail(rec policy.Record, code codes.Code, format string, args ...any) error {
	err := status.Errorf(code, format, args...)
	rec.Outcome = policy.OutcomeError
	rec.Error = status.Convert(err).Message()
	return s.finish(rec, err)
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
