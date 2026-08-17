package shell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	"github.com/axelmierczuk/fleet-mcp/internal/agent/exec"
	"github.com/axelmierczuk/fleet-mcp/internal/platform"
	"github.com/axelmierczuk/fleet-mcp/internal/security/policy"
)

// init registers ShellService with every fleet-agent daemon that links this
// package. See internal/cli/fleetagent/services.go for the import that does.
func init() {
	agent.Register("shell", New)
}

// shellMethod is the RPC name written into every audit record.
const shellMethod = "sandboxd.v1.ShellService/Shell"

// acquireTimeout bounds the wait for a slot in the agent-wide process limit.
//
// Short, because the caller is a person at a terminal rather than a queued
// build. Exec waits up to its command's whole timeout for a slot, which is
// right for work that is going to take minutes anyway; a shell that takes two
// minutes to open reads as broken, and "this agent is running too many
// processes" is an answer the operator can act on immediately.
const acquireTimeout = 10 * time.Second

// Service implements sandboxd.v1.ShellService.
type Service struct {
	sandboxdv1.UnimplementedShellServiceServer

	log    *slog.Logger
	policy *policy.Policy
	audit  *policy.Audit

	// enabled mirrors shell.enabled, and execEnabled mirrors exec.enabled. Both
	// are refusals rather than an unregistered service, so a caller is told
	// which setting turned this off instead of getting an Unimplemented that
	// reads like a version mismatch.
	enabled     bool
	execEnabled bool

	// defaultDir is where a session with no working_dir starts, and
	// idleTimeout is how long one may carry nothing before it is reaped.
	defaultDir  string
	idleTimeout time.Duration

	// loginShell resolves the command a session with an empty argv runs. It is
	// a field so tests can pin it: what it returns depends on the environment
	// of the account the daemon happens to be running under, and a test that
	// asserted on the real one would assert something different on every
	// machine.
	loginShell func() []string
}

// New builds the shell service. It satisfies agent.Factory.
func New(deps agent.Deps) (agent.Service, error) {
	if deps.Policy == nil {
		return nil, errors.New("shell: agent.Deps.Policy is required; the caps and command lists are enforced centrally")
	}
	if deps.Audit == nil {
		return nil, errors.New("shell: agent.Deps.Audit is required")
	}

	log := deps.Log.With("service", "shell")
	s := &Service{
		log:         log,
		policy:      deps.Policy,
		audit:       deps.Audit,
		enabled:     deps.Config.Shell.IsEnabled(),
		execEnabled: deps.Config.Exec.IsEnabled(),
		defaultDir:  exec.DefaultWorkingDir(),
		idleTimeout: deps.Config.Shell.IdleTimeout.Duration(),
		loginShell:  loginShell,
	}

	// One line at every start, because this is the service that hands out a
	// terminal. An operator reading a daemon's log should be able to see that
	// it is on, and see it beside whether anything is recording the sessions.
	log.Info("shell service ready",
		"enabled", s.enabled,
		"exec_enabled", s.execEnabled,
		"pty_supported", platform.PTYSupported(),
		"default_working_dir", s.defaultDir,
		"idle_timeout", s.idleTimeout,
		"audit", deps.Audit.Enabled(),
		"audit_required", deps.Audit.Required(),
	)
	if s.enabled && !deps.Audit.Enabled() {
		// The two are only troubling together. Handing an operator a terminal
		// is a decision an operator may reasonably make; handing it out with no
		// record of who took one and when is one they should have had to make
		// on purpose.
		log.Warn("INTERACTIVE SHELL SESSIONS ARE AVAILABLE WITH NO AUDIT LOG",
			"reason", "shell.enabled is true and audit.enabled is false",
			"consequence", "this agent will hand out interactive terminals and record nothing about who took one")
	}
	return s, nil
}

// Register attaches ShellService to the daemon's gRPC server.
func (s *Service) Register(r grpc.ServiceRegistrar) {
	sandboxdv1.RegisterShellServiceServer(r, s)
}

// Shell carries one interactive session.
//
// The stream's shape is fixed: a ShellOpen, then bytes and resizes in any
// order, until the command exits or the stream ends. The first message must be
// the open, because there is no terminal to write to until it has arrived.
//
// # What ends a session
//
// Four things, and they are audited differently:
//
//   - The command exits. Its status is sent as a ShellExit and the record says
//     ok, whatever the exit code was — a shell exiting 1 is a shell that ran.
//   - The caller goes away, or the daemon drains. The stream's context is
//     cancelled, the tree is killed, and the record says cancelled.
//   - The session goes idle for longer than shell.idle_timeout. The tree is
//     killed and the record says timed_out.
//   - The request is refused before anything starts. Nothing runs and the
//     record says denied or error.
//
// # There is no path confinement here
//
// As with ExecService, and more obviously: this hands the caller a shell. The
// path jail is wired in only on an agent with exec disabled, and such an agent
// refuses this call outright. See docs/security.md.
func (s *Service) Shell(stream grpc.BidiStreamingServer[sandboxdv1.ShellRequest, sandboxdv1.ShellResponse]) error {
	ctx := stream.Context()
	principal, _ := agent.PrincipalFromContext(ctx)
	rec := sessionAudit{started: time.Now().UTC(), principal: principal}

	if !s.enabled {
		return s.deny(rec, "shell.enabled: false",
			"this agent runs with shell.enabled: false, so ShellService is turned off")
	}
	if !s.execEnabled {
		// The same reasoning ProcessService.StartProcess uses. exec.enabled:
		// false is the one configuration in which allowed_roots is a real
		// boundary, and it is that only because an agent that runs commands
		// reaches every path anyway. A terminal is the most direct way to run a
		// command there is, so a shell service that ignored the setting would
		// hand an operator a configured jail, report itself confined through
		// GetHostInfo, and then let a caller type `cat /etc/shadow`.
		return s.deny(rec, "exec.enabled: false",
			"this agent runs with exec.enabled: false, which turns off every way it can run a command, "+
				"including an interactive shell; it is the configuration in which allowed_roots is a real boundary")
	}

	first, err := stream.Recv()
	if err != nil {
		// Nothing was asked for, so there is nothing to record: a stream that
		// closed before naming a command started nothing.
		if errors.Is(err, io.EOF) {
			return status.Error(codes.InvalidArgument, "the stream closed before sending a ShellOpen")
		}
		return err
	}
	open := first.GetOpen()
	if open == nil {
		return status.Error(codes.InvalidArgument, "the first message on a Shell stream must be a ShellOpen")
	}

	spec, err := s.plan(open, &rec)
	if err != nil {
		// One place that cannot be forgotten. plan fills in the outcome for
		// every refusal it makes a judgement about — a denied command, a
		// malformed environment — and the plain validation failures have
		// nothing to add beyond the message the caller was given.
		if rec.outcome == "" {
			rec.outcome, rec.failure = policy.OutcomeError, status.Convert(err).Message()
		}
		return s.finish(rec, err)
	}

	// A slot in the agent-wide process limit, held for the life of the session.
	// A shell is one process by the agent's accounting and any number by the
	// host's — the cap bounds what this agent started, which is the quantity it
	// can answer for.
	acquireCtx, cancelAcquire := context.WithTimeout(ctx, acquireTimeout)
	release, err := s.policy.Acquire(acquireCtx)
	cancelAcquire()
	if err != nil {
		if ctx.Err() != nil {
			rec.outcome, rec.failure = policy.OutcomeCancelled, "the caller went away while waiting for a free process slot"
			return s.finish(rec, status.Error(codes.Canceled, rec.failure))
		}
		rec.outcome, rec.failure = policy.OutcomeError, err.Error()
		return s.finish(rec, status.Errorf(codes.ResourceExhausted, "%s", err))
	}
	defer release()

	runErr := s.run(ctx, stream, spec, &rec)
	return s.finish(rec, runErr)
}

// sessionSpec is everything a session needs that survived validation.
type sessionSpec struct {
	// command is the resolved executable and the argv it will be started with.
	command policy.Command
	dir     string
	env     []string
	size    windowSize
}

// plan validates a ShellOpen and resolves what it asks for.
//
// It fills the audit record as it goes, so that a refusal is recorded with the
// command it refused rather than with a blank line.
func (s *Service) plan(open *sandboxdv1.ShellOpen, rec *sessionAudit) (sessionSpec, error) {
	argv := open.GetArgv()
	if len(argv) == 0 {
		argv = s.loginShell()
	}
	if len(argv) == 0 || argv[0] == "" {
		return sessionSpec{}, status.Error(codes.InvalidArgument,
			"argv[0] must name the program to run, and this host reports no default shell to fall back on")
	}
	rec.argv = argv

	env, err := exec.Environment(open.GetEnv())
	if err != nil {
		// Quoted to the caller and not to the record: "FOO" meaning "FOO=bar"
		// and "=bar" meaning "FOO=bar" are both ways for a value to arrive
		// inside the string this would otherwise write down. Same decision, and
		// the same reasoning, as exec's failRedacted.
		rec.outcome = policy.OutcomeError
		rec.failure = "a request environment entry was malformed; the entry itself is not recorded, because this log never carries environment data"
		return sessionSpec{}, status.Errorf(codes.InvalidArgument, "%s", err)
	}

	dir, err := s.workingDir(open.GetWorkingDir())
	if err != nil {
		return sessionSpec{}, status.Errorf(codes.InvalidArgument, "%s", err)
	}
	rec.dir = dir

	pathEnv, _ := exec.EnvValue(env, "PATH")
	pathExt, _ := exec.EnvValue(env, "PATHEXT")
	cmd, lookupErr := policy.Resolve(argv, dir, pathEnv, pathExt)
	rec.path = cmd.Path

	// Policy before the lookup failure, so a refused command that also does not
	// exist is recorded as refused. That is the fact worth keeping.
	if decision := s.policy.Evaluate(cmd); !decision.Allowed {
		rec.outcome, rec.rule, rec.failure = policy.OutcomeDenied, decision.Rule, decision.Reason
		return sessionSpec{}, status.Errorf(codes.PermissionDenied, "%s", decision.Reason)
	}
	if lookupErr != nil {
		rec.outcome = policy.OutcomeError
		rec.failure = fmt.Sprintf("could not resolve %q to an executable; the PATH searched is an environment value and is not recorded", cmd.Requested)
		return sessionSpec{}, status.Errorf(codes.NotFound, "%s", lookupErr)
	}

	return sessionSpec{
		command: cmd,
		dir:     dir,
		env:     env,
		size:    sizeOf(open.GetSize()),
	}, nil
}

// workingDir resolves the directory a session starts in.
//
// There is no jail to resolve against — see Shell's doc comment — so this makes
// the path absolute, checks that it is a directory, and stops. The check earns
// its place because the alternative is the pty layer reporting a chdir failure
// with the shell's name in it, which reads like the shell is missing.
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

// deny records a refused request and returns the error the caller sees.
func (s *Service) deny(rec sessionAudit, rule, message string) error {
	rec.outcome, rec.rule = policy.OutcomeDenied, rule
	rec.failure = message
	return s.finish(rec, status.Error(codes.FailedPrecondition, message))
}

// loginShellFor picks the shell named by an environment lookup, or nothing.
//
// Split out from the platform files so the fallback order can be tested without
// changing the daemon's own environment, which a parallel test cannot do.
func loginShellFor(get func(string) string) []string {
	if named := strings.TrimSpace(get(loginShellVar)); named != "" {
		return []string{named}
	}
	return []string{fallbackShell}
}
