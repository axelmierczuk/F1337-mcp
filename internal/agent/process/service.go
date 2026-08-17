package process

import (
	"context"
	"errors"
	"regexp"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/agent"
	"github.com/axelmierczuk/sandboxd-mcp/internal/platform"
	"github.com/axelmierczuk/sandboxd-mcp/internal/security/jail"
)

// init registers ProcessService with every sandboxd-agent daemon that links
// this package. See internal/cli/sandboxdagent/services.go for the import that
// does.
func init() {
	agent.Register("process", New)
}

// Service implements sandboxd.v1.ProcessService.
//
// It is a thin translation layer: validate the request, resolve defaults, hand
// the work to the supervisor, project the result back onto the wire types. All
// the state lives in the supervisor, and none of it is reachable from an RPC
// context.
type Service struct {
	sandboxdv1.UnimplementedProcessServiceServer

	deps agent.Deps
	sup  *Supervisor
}

// New builds the process service and re-adopts whatever the state directory
// says survived the last agent. It satisfies agent.Factory.
func New(deps agent.Deps) (agent.Service, error) {
	log := deps.Log.With("service", "process")
	sup, err := newSupervisor(defaultSupervisorConfig(deps.Config), log)
	if err != nil {
		return nil, err
	}
	// Health reports the supervised process count. The function is an atomic
	// load, which is what that call path can afford.
	deps.Status.SetProcessCounter(sup.liveCount)
	return &Service{deps: deps, sup: sup}, nil
}

// Register attaches ProcessService to the daemon's gRPC server.
func (s *Service) Register(r grpc.ServiceRegistrar) {
	sandboxdv1.RegisterProcessServiceServer(r, s)
}

// Shutdown flushes the supervisor's state and stops its goroutines.
//
// It does not stop a single supervised process, and the daemon does not signal
// one on its behalf. Surviving an agent restart is the entire reason these
// processes exist: an upgrade must not take down every dev server in the fleet.
// See agent.Shutdowner, and the KillMode=process in the systemd unit this
// repository installs.
func (s *Service) Shutdown(context.Context) error {
	s.deps.Status.SetProcessCounter(nil)
	return s.sup.Close()
}

// StartProcess spawns a supervised process.
func (s *Service) StartProcess(ctx context.Context, req *sandboxdv1.StartProcessRequest) (*sandboxdv1.StartProcessResponse, error) {
	spec, err := s.resolveStart(req)
	if err != nil {
		return nil, err
	}

	r, err := s.sup.start(spec, req.GetReplaceExisting())
	if err != nil {
		// A record may exist even here — a spawn that failed leaves one behind
		// in CRASHED so its logs can be read — but the call still failed, and
		// reporting it as a success with a status attached would have the
		// caller poll a process that never started.
		return nil, status.Errorf(codes.FailedPrecondition, "could not start %q: %v", spec.name, err)
	}

	resp := &sandboxdv1.StartProcessResponse{}
	if req.GetWaitForReady() && spec.probe != nil {
		if err := s.sup.waitForReady(ctx, r); err != nil {
			// Not an RPC error. The process is running, its logs are readable,
			// and whether to stop it is the caller's decision — which is
			// exactly what ready_error is for.
			resp.ReadyError = err.Error()
		}
	}
	resp.Status = r.status()
	return resp, nil
}

// resolveStart validates a StartProcess request and fills in agent defaults.
func (s *Service) resolveStart(req *sandboxdv1.StartProcessRequest) (startSpec, error) {
	if len(req.GetArgv()) == 0 {
		return startSpec{}, status.Error(codes.InvalidArgument, "argv is required")
	}
	if req.GetArgv()[0] == "" {
		return startSpec{}, status.Error(codes.InvalidArgument, "argv[0] is empty; it must name the executable")
	}
	if req.GetName() == "" {
		return startSpec{}, status.Error(codes.InvalidArgument, "name is required: it is the label a caller uses to find this process again")
	}

	workingDir, err := s.resolveWorkingDir(req.GetWorkingDir())
	if err != nil {
		return startSpec{}, err
	}

	probe, err := probeFromProto(req.GetReadyProbe(), s.sup.cfg.probeTimeout, s.sup.cfg.probeInterval)
	if err != nil {
		return startSpec{}, status.Error(codes.InvalidArgument, err.Error())
	}

	maxRestarts := req.GetMaxRestarts()
	if maxRestarts == 0 {
		maxRestarts = s.sup.cfg.defaultMaxRestarts
	}
	backoff := req.GetRestartBackoff().AsDuration()
	if backoff <= 0 {
		backoff = s.sup.cfg.defaultRestartBackoff
	}
	maxLogBytes := int64(req.GetMaxLogBytes()) //nolint:gosec // clamped below
	if req.GetMaxLogBytes() == 0 || maxLogBytes <= 0 {
		maxLogBytes = s.sup.cfg.maxLogBytes
	}

	policy := req.GetRestartPolicy()
	if policy == sandboxdv1.RestartPolicy_RESTART_POLICY_UNSPECIFIED {
		// never, and deliberately. A default that restarts is a default that
		// resurrects a process someone stopped on purpose.
		policy = sandboxdv1.RestartPolicy_RESTART_POLICY_NEVER
	}

	return startSpec{
		argv:           req.GetArgv(),
		name:           req.GetName(),
		workingDir:     workingDir,
		env:            req.GetEnv(),
		shell:          req.GetShell(),
		probe:          probe,
		restartPolicy:  policy,
		maxRestarts:    maxRestarts,
		restartBackoff: backoff,
		maxLogBytes:    maxLogBytes,
	}, nil
}

// resolveWorkingDir puts the requested directory through the jail.
//
// The jail is never nil and is unconfined on an exec-enabled agent, so this is
// a normalisation on most hosts and a boundary on the ones where exec is off.
// Either way the resolved path is what gets used, never the one the caller sent.
func (s *Service) resolveWorkingDir(dir string) (string, error) {
	if dir == "" {
		return s.deps.Jail.WorkingDir(), nil
	}
	resolved, err := s.deps.Jail.Resolve(dir)
	if err != nil {
		if errors.Is(err, jail.ErrOutsideJail) {
			return "", status.Errorf(codes.PermissionDenied, "working_dir %s is outside the agent's allowed roots", dir)
		}
		return "", status.Errorf(codes.InvalidArgument, "working_dir %s: %v", dir, err)
	}
	return resolved, nil
}

// ListProcesses returns every tracked process, including exited ones that have
// not been reaped.
func (s *Service) ListProcesses(_ context.Context, req *sandboxdv1.ListProcessesRequest) (*sandboxdv1.ListProcessesResponse, error) {
	filter := listFilter{}
	if states := req.GetStates(); len(states) > 0 {
		filter.states = make(map[sandboxdv1.ProcessState]bool, len(states))
		for _, st := range states {
			filter.states[st] = true
		}
	}
	if pattern := req.GetNamePattern(); pattern != "" {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "name_pattern %q is not a valid RE2 pattern: %v", pattern, err)
		}
		filter.name = re
	}

	records := s.sup.snapshotRecords()
	out := make([]*sandboxdv1.ProcessStatus, 0, len(records))
	for _, r := range records {
		if filter.matches(r) {
			out = append(out, r.status())
		}
	}
	return &sandboxdv1.ListProcessesResponse{Processes: out}, nil
}

// GetProcessLogs returns buffered output and, when asked, follows new output to
// a deadline.
func (s *Service) GetProcessLogs(req *sandboxdv1.GetProcessLogsRequest, stream grpc.ServerStreamingServer[sandboxdv1.GetProcessLogsResponse]) error {
	r, err := s.record(req.GetProcessId())
	if err != nil {
		return err
	}

	sel := selector{
		stream: req.GetStream(),
		tail:   int(req.GetTailLines()), //nolint:gosec // bounded below
	}
	if sel.tail <= 0 {
		sel.tail = s.sup.cfg.defaultTailLines
	}
	if since := req.GetSince(); since != nil {
		sel.since = since.AsTime()
	}
	if pattern := req.GetFilterPattern(); pattern != "" {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "filter_pattern %q is not a valid RE2 pattern: %v", pattern, err)
		}
		sel.filter = re
	}

	return s.sup.streamLogs(stream.Context(), r, logRequest{
		sel:       sel,
		follow:    req.GetFollow(),
		followFor: req.GetFollowDuration().AsDuration(),
	}, stream)
}

// SignalProcess sends a signal or performs a graceful stop.
func (s *Service) SignalProcess(_ context.Context, req *sandboxdv1.SignalProcessRequest) (*sandboxdv1.SignalProcessResponse, error) {
	r, err := s.record(req.GetProcessId())
	if err != nil {
		return nil, err
	}

	// The default is the whole group, not the leader. Signalling the leader
	// alone routinely leaves orphans: killing `npm run dev` without its group
	// leaves the bundler holding the port, and the next start fails to bind.
	group := true
	if req.ProcessGroup != nil {
		group = req.GetProcessGroup()
	}

	if req.GetDisableRestart() {
		r.mu.Lock()
		r.restartsDisabled = true
		r.mu.Unlock()
		r.persist()
	}

	resp := &sandboxdv1.SignalProcessResponse{}
	if req.GetGracefulStop() {
		escalated, err := s.sup.gracefulStop(r, req.GetGracePeriod().AsDuration(), req.GetDisableRestart(), group)
		if err != nil {
			return nil, signalError(r, err)
		}
		resp.EscalatedToKill = escalated
		resp.Status = r.status()
		return resp, nil
	}

	sig, err := portableSignal(req.GetSignal())
	if err != nil {
		return nil, err
	}
	if err := s.sup.signalRecord(r, sig, group); err != nil {
		return nil, signalError(r, err)
	}
	resp.Status = r.status()
	return resp, nil
}

// signalError maps a supervisor signalling failure onto a gRPC code.
//
// "The process has already exited" is FailedPrecondition, not Internal: it is a
// normal outcome of a race the caller cannot avoid, and it is emphatically not
// a panic or a signal delivered to whatever reused the pid.
func signalError(r *record, err error) error {
	switch {
	case errors.Is(err, errAlreadyExited):
		return status.Errorf(codes.FailedPrecondition, "process %s has already exited", r.id)
	case errors.Is(err, platform.ErrSignalUnsupported):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Errorf(codes.Internal, "could not signal process %s: %v", r.id, err)
	}
}

// portableSignal translates the wire signal onto the platform vocabulary.
func portableSignal(sig sandboxdv1.SignalProcessRequest_Signal) (platform.Signal, error) {
	switch sig {
	case sandboxdv1.SignalProcessRequest_SIGNAL_TERM:
		return platform.SignalTerm, nil
	case sandboxdv1.SignalProcessRequest_SIGNAL_KILL:
		return platform.SignalKill, nil
	case sandboxdv1.SignalProcessRequest_SIGNAL_INT:
		return platform.SignalInt, nil
	case sandboxdv1.SignalProcessRequest_SIGNAL_HUP:
		return platform.SignalHup, nil
	case sandboxdv1.SignalProcessRequest_SIGNAL_USR1:
		return platform.SignalUSR1, nil
	case sandboxdv1.SignalProcessRequest_SIGNAL_USR2:
		return platform.SignalUSR2, nil
	case sandboxdv1.SignalProcessRequest_SIGNAL_UNSPECIFIED:
		return platform.SignalUnspecified, status.Error(codes.InvalidArgument,
			"signal is required unless graceful_stop is set")
	default:
		return platform.SignalUnspecified, status.Errorf(codes.InvalidArgument, "unknown signal %v", sig)
	}
}

// RestartProcess stops a process and starts it again from the same spec,
// keeping its process id and its log history.
func (s *Service) RestartProcess(ctx context.Context, req *sandboxdv1.RestartProcessRequest) (*sandboxdv1.RestartProcessResponse, error) {
	r, err := s.record(req.GetProcessId())
	if err != nil {
		return nil, err
	}

	if err := s.sup.restart(r, req.GetGracePeriod().AsDuration()); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "could not restart process %s: %v", r.id, err)
	}

	resp := &sandboxdv1.RestartProcessResponse{}
	r.mu.Lock()
	probe := r.probe
	r.mu.Unlock()
	if req.GetWaitForReady() && probe != nil {
		if err := s.sup.waitForReady(ctx, r); err != nil {
			resp.ReadyError = err.Error()
		}
	}
	resp.Status = r.status()
	return resp, nil
}

// RemoveProcess reaps a record, and optionally its logs.
func (s *Service) RemoveProcess(_ context.Context, req *sandboxdv1.RemoveProcessRequest) (*sandboxdv1.RemoveProcessResponse, error) {
	r, err := s.record(req.GetProcessId())
	if err != nil {
		return nil, err
	}
	if err := s.sup.remove(r, req.GetForce(), req.GetDeleteLogs()); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	return &sandboxdv1.RemoveProcessResponse{ProcessId: r.id}, nil
}

// record looks up a process id, reporting NotFound as a gRPC status.
func (s *Service) record(id string) (*record, error) {
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "process_id is required")
	}
	r, ok := s.sup.lookup(id)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no process with id %s", id)
	}
	return r, nil
}
