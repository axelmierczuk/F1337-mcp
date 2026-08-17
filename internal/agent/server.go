package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/client"
	"github.com/axelmierczuk/sandboxd-mcp/internal/security/jail"
	"github.com/axelmierczuk/sandboxd-mcp/internal/security/policy"
)

// DefaultDrainTimeout bounds how long shutdown waits for in-flight RPCs.
//
// It is generous because the calls it is waiting on are real work — a build
// streaming output, a large file transfer — and cutting those off costs the
// caller the whole call. It is bounded because a stuck stream must not stop
// the daemon exiting: systemd's own TimeoutStopSec is what would kill it next,
// far less politely.
const DefaultDrainTimeout = 30 * time.Second

// stopGrace is how long shutdown waits after cancelling in-flight RPCs before
// giving up on them entirely. A handler that respects its context unwinds in
// microseconds; one that does not is never going to.
const stopGrace = 2 * time.Second

// Options configures a Server.
type Options struct {
	// Config is the loaded, validated agent configuration. Required.
	Config *Config

	// Log is the daemon logger. Required.
	Log *slog.Logger

	// Version is the agent binary's version, reported by HostService.
	Version string

	// Services are the service registrations to host. Nil means Registered(),
	// which is every service package linked into the binary. Tests pass an
	// explicit slice.
	Services []Registration

	// Listener overrides the socket the server accepts on. Nil means listen on
	// Config.Listen. Tests pass a bufconn listener, which is the only way to
	// exercise the real TLS stack without binding a port.
	Listener net.Listener

	// DrainTimeout bounds the wait for in-flight RPCs during shutdown. Zero
	// uses DefaultDrainTimeout.
	DrainTimeout time.Duration

	// Jail overrides the path jail built from Config.AllowedRoots. Nil builds
	// one from the config.
	Jail *jail.Jail

	// GRPCOptions are appended to the server options this package builds.
	GRPCOptions []grpc.ServerOption
}

// Server is the agent daemon: an mTLS gRPC listener hosting every registered
// service, with a shutdown path that drains RPCs without disturbing supervised
// background processes.
type Server struct {
	cfg      *Config
	log      *slog.Logger
	grpc     *grpc.Server
	lis      net.Listener
	deps     Deps
	services []builtService
	drain    time.Duration
}

// New builds the server: it loads the TLS material, constructs every
// registered service, registers their handlers, and opens the listener.
//
// Everything that can fail does so here, before the daemon claims to be
// serving. Nothing is accepted until Serve is called.
func New(opts Options) (srv *Server, err error) {
	if opts.Config == nil {
		return nil, errors.New("agent: Options.Config is required")
	}
	if opts.Log == nil {
		return nil, errors.New("agent: Options.Log is required")
	}

	// Load applies the documented defaults, but a Config built in memory has
	// never been through it — and the caps are the part that matters: a zero
	// max_output_bytes is not "no output" but "no cap", and a zero
	// default_timeout is a command with no wall-clock limit at all. Applying
	// them here means every daemon enforces the same limits however its config
	// was assembled. It only ever fills in a field the config left unset.
	opts.Config.applyDefaults()

	tlsConf, err := ServerTLSConfig(opts.Config)
	if err != nil {
		return nil, err
	}

	jailed := opts.Jail
	if jailed == nil {
		if jailed, err = jailFor(opts.Config, opts.Log); err != nil {
			return nil, err
		}
	}

	drain := opts.DrainTimeout
	if drain <= 0 {
		drain = DefaultDrainTimeout
	}

	commandPolicy, err := policyFor(opts.Config)
	if err != nil {
		return nil, err
	}
	auditLog := auditFor(opts.Config, opts.Log)
	// Preflight has the log open by now. Every later failure here returns
	// before anything owns it, and a handle nobody will close is a file that
	// cannot be removed or renamed on Windows for as long as the process
	// lives — including by the test that created it.
	defer func() {
		if err != nil {
			_ = auditLog.Close()
		}
	}()

	deps := Deps{
		Config:    opts.Config,
		Jail:      jailed,
		Policy:    commandPolicy,
		Audit:     auditLog,
		Log:       opts.Log,
		Status:    NewStatus(),
		Version:   opts.Version,
		StartedAt: time.Now().UTC(),
	}

	regs := opts.Services
	if regs == nil {
		regs = Registered()
	}
	services, err := buildServices(regs, deps)
	if err != nil {
		return nil, err
	}

	serverOpts := []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(tlsConf)),
		// Matched to internal/client's limits. A mismatch surfaces as an
		// opaque ResourceExhausted on whichever side is stricter, with nothing
		// to say it was a configured cap rather than a real failure.
		grpc.MaxRecvMsgSize(client.DefaultMaxMessageSize),
		grpc.MaxSendMsgSize(client.DefaultMaxMessageSize),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			// The MCP server health-probes every 15s and holds long-lived
			// streams for process logs. Tolerating pings on an idle connection
			// is what keeps a NAT from silently dropping one of those.
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.ChainUnaryInterceptor(principalUnaryInterceptor, recoveryUnaryInterceptor(opts.Log)),
		grpc.ChainStreamInterceptor(principalStreamInterceptor, recoveryStreamInterceptor(opts.Log)),
	}
	serverOpts = append(serverOpts, opts.GRPCOptions...)

	grpcServer := grpc.NewServer(serverOpts...)
	for _, svc := range services {
		svc.svc.Register(grpcServer)
	}

	lis := opts.Listener
	if lis == nil {
		lis, err = net.Listen("tcp", opts.Config.Listen)
		if err != nil {
			return nil, fmt.Errorf("agent: listen on %s: %w", opts.Config.Listen, err)
		}
	}

	return &Server{
		cfg:      opts.Config,
		log:      opts.Log,
		grpc:     grpcServer,
		lis:      lis,
		deps:     deps,
		services: services,
		drain:    drain,
	}, nil
}

// policyFor builds the one command policy every service shares.
//
// A malformed rule aborts startup rather than being dropped. An operator who
// wrote `deny_commands: ["rm[")` believes rm is denied, and a daemon that came
// up healthy having silently discarded the entry would be running exactly the
// commands they thought they had refused.
func policyFor(cfg *Config) (*policy.Policy, error) {
	p, err := policy.New(policy.Config{
		Allow: cfg.Exec.AllowCommands,
		Deny:  cfg.Exec.DenyCommands,
		Caps: policy.Caps{
			DefaultTimeout: cfg.Exec.DefaultTimeout.Duration(),
			MaxTimeout:     cfg.Exec.MaxTimeout.Duration(),
			MaxOutputBytes: cfg.Exec.MaxOutputBytes,
			// One number for every process this agent starts, whichever
			// service starts it: ExecService takes a slot per call, the
			// supervisor takes one per live record. It is spelled under
			// process.* for historical reasons and is not the supervisor's
			// alone — a cap each service counted for itself would let an agent
			// set to 32 run 32 of each, which is how it read before this was
			// wired through.
			MaxConcurrent: cfg.Process.MaxConcurrent,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("agent: %w", err)
	}
	return p, nil
}

// auditFor builds the daemon's single audit log and opens it once, so a path
// that cannot be written is a startup log line rather than a surprise at the
// first RPC.
//
// A failure here does not stop the daemon. The record is forensic: it prevents
// nothing, and an agent that refused to serve because a log directory was
// missing would have traded a gap in the record for an outage. When the
// operator has set audit.required, every affected RPC fails on its own — that
// is the same refusal, delivered where the caller can see it.
func auditFor(cfg *Config, log *slog.Logger) *policy.Audit {
	auditLog := policy.NewAudit(policy.AuditConfig{
		Path:           cfg.Audit.Path,
		Enabled:        cfg.Audit.Enabled,
		Required:       cfg.Audit.Required,
		MaxBytes:       cfg.Audit.MaxBytes,
		RetainSegments: cfg.Audit.RetainSegments,
	})

	if !auditLog.Enabled() {
		log.Warn("AUDIT LOG IS OFF",
			"reason", "audit.enabled is false",
			"consequence", "this agent records nothing about the commands it runs or the files it writes")
		return auditLog
	}
	if err := auditLog.Preflight(); err != nil {
		level := "commands will run unrecorded"
		if auditLog.Required() {
			level = "audit.required is set, so every affected RPC will fail until this is fixed"
		}
		log.Error("AUDIT LOG IS NOT WRITABLE",
			"path", auditLog.Path(), "error", err, "consequence", level)
	}
	return auditLog
}

// jailFor builds the jail the daemon hands its services, and announces which
// of the three states it ended up in.
//
// The states are not symmetrical and the logging is not decoration. An agent
// that ignores configured roots must say so at every start: an operator who
// wrote allowed_roots into their config and never heard otherwise reasonably
// concludes the agent is confined to them, and that belief is the thing this
// wiring exists to remove.
//
// This is the single place that decides whether the jail is in force. Nothing
// downstream reads Config.AllowedRoots to answer that question — they ask the
// jail, which is why an exec-enabled agent reports itself unconfined all the
// way out to sandbox_select.
func jailFor(cfg *Config, log *slog.Logger) (*jail.Jail, error) {
	if !cfg.JailEnforced() {
		if len(cfg.AllowedRoots) > 0 {
			log.Warn("ALLOWED_ROOTS ARE IGNORED",
				"roots", cfg.AllowedRoots,
				"reason", `exec is enabled, and a caller with ExecService reaches any path without FileService: argv ["sh","-c","echo x > /etc/passwd"] needs no shell flag and no write RPC`,
				"consequence", "this agent can read and write every path its account can, and reports itself as unconfined",
				"remedy", "set exec.enabled: false to make allowed_roots a boundary rather than a decoration")
		} else {
			log.Warn("STARTING WITHOUT A PATH JAIL",
				"reason", "exec is enabled, and an agent that runs arbitrary commands cannot be confined by a path check",
				"consequence", "every path this account can reach is reachable through this agent")
		}
		return jail.Unconfined(), nil
	}

	if len(cfg.AllowedRoots) == 0 {
		// Config.Validate refuses this unless the operator passed --no-jail, so
		// reaching here means they did. It is named rather than left to fall
		// out of an empty slice, and logged every start, because a jail that
		// was disabled for one afternoon of debugging and never re-enabled is
		// exactly what this line exists to keep visible.
		log.Warn("STARTING WITHOUT A PATH JAIL",
			"reason", "exec is disabled but allowed_roots is empty and --no-jail was passed",
			"consequence", "every path on this host is reachable through FileService")
		return jail.Unconfined(), nil
	}

	confined, err := jail.New(jail.Config{Roots: cfg.AllowedRoots})
	if err != nil {
		// A root that does not exist is a configuration error the jail refuses
		// rather than tolerates, and the reason is worth repeating where an
		// operator will read it: a path that is missing now can be created
		// later, as a symlink to anywhere, and the jail would then confine to
		// whatever it pointed at.
		return nil, fmt.Errorf("agent: build path jail: %w\n\nEvery allowed root must already exist and be a directory. Create it, or start with exec enabled, where the roots are not a boundary anyway", err)
	}
	return confined, nil
}

// Addr returns the address the server accepts on.
func (s *Server) Addr() net.Addr { return s.lis.Addr() }

// Deps returns the dependencies handed to every service, for a caller that
// needs the same jail, status, or logger the services got.
func (s *Server) Deps() Deps { return s.deps }

// ServiceNames returns the names of the hosted services, in registration
// order.
func (s *Server) ServiceNames() []string {
	names := make([]string, 0, len(s.services))
	for _, svc := range s.services {
		names = append(names, svc.name)
	}
	return names
}

// Serve accepts connections until ctx is cancelled, then shuts down
// gracefully and returns.
//
// Shutdown, in order:
//
//  1. Health flips to DRAINING, so a control plane polling the fleet sees the
//     agent going away rather than a connection error it has to guess about.
//  2. The listener stops accepting and in-flight RPCs are given DrainTimeout
//     to finish. A call still running when that expires is cut.
//  3. Each service implementing Shutdowner is given what remains of the
//     deadline to flush its own state.
//
// What does not happen at any point is the daemon touching a supervised
// process. Those are owned by the host and outlive the daemon deliberately;
// see Shutdowner.
func (s *Server) Serve(ctx context.Context) error {
	s.log.Info("serving",
		"address", s.lis.Addr().String(),
		"services", s.ServiceNames(),
		"exec_enabled", s.cfg.Exec.IsEnabled(),
		"jail", s.deps.Jail.Confined(),
		// The jail's roots, not the config's: with exec enabled those differ,
		// and this line should say what is in force rather than what was
		// written down.
		"allowed_roots", s.deps.Jail.Roots(),
		// Whether a path check and the open that follows it are one operation
		// or two. It is false off Linux and on kernels without openat2, and
		// saying so beats letting an operator assume the stronger guarantee.
		"jail_atomic", s.deps.Jail.Atomic(),
		"require_client_ou", s.cfg.TLS.RequireClientOU,
		"version", s.deps.Version,
	)

	errCh := make(chan error, 1)
	go func() {
		err := s.grpc.Serve(s.lis)
		// Serve returns ErrServerStopped from a concurrent Stop, which is the
		// normal end of a graceful shutdown rather than a failure.
		if errors.Is(err, grpc.ErrServerStopped) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case err := <-errCh:
		// The accept loop stopped on its own: a listener closed from outside,
		// or an accept failure gRPC judged permanent. The services still get
		// their shutdown hook. Persisting the supervisor's process records is
		// what that hook is for, and losing them because a socket died is a
		// worse outcome than the dead socket.
		s.shutdown()
		if err != nil {
			return fmt.Errorf("agent: serve: %w", err)
		}
		return nil
	case <-ctx.Done():
	}

	s.shutdown()

	// Serve returns as soon as its listener is closed, which shutdown does
	// first, so collecting its result here does not extend the exit. It is
	// collected at all so that a real accept-loop failure is not swallowed by
	// the shutdown path.
	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("agent: serve: %w", err)
		}
	case <-time.After(stopGrace):
		s.log.Warn("accept loop did not report its result before exit")
	}
	return nil
}

// shutdown drains and stops the gRPC server, then runs the shutdown
// participants.
func (s *Server) shutdown() {
	s.deps.Status.Set(sandboxdv1.HealthResponse_STATUS_DRAINING, "agent is shutting down")
	s.log.Info("draining", "timeout", s.drain)

	deadline := time.Now().Add(s.drain)

	drained := make(chan struct{})
	go func() {
		// GracefulStop closes the listener immediately, then blocks until
		// every in-flight RPC has returned.
		s.grpc.GracefulStop()
		close(drained)
	}()

	timer := time.NewTimer(s.drain)
	defer timer.Stop()
	select {
	case <-drained:
		s.log.Info("drained")
	case <-timer.C:
		s.log.Warn("drain deadline expired, cancelling in-flight RPCs", "timeout", s.drain)
		// Stop cancels every in-flight stream's context, but it does not — and
		// cannot — force a handler goroutine to return: gRPC waits on those
		// goroutines itself. A handler that ignores its context would hold the
		// daemon open forever, which is precisely what the deadline exists to
		// prevent, so the wait after cancelling is bounded too and the daemon
		// exits regardless.
		go s.grpc.Stop()
		select {
		case <-drained:
			s.log.Info("drained after cancellation")
		case <-time.After(stopGrace):
			s.log.Warn("in-flight RPCs did not return after cancellation; exiting anyway")
		}
	}

	// Whatever is left of the budget goes to the participants. A minimum
	// keeps a fully consumed drain from handing them an already-expired
	// context, which would lose process state that takes milliseconds to write.
	remaining := max(time.Until(deadline), 5*time.Second)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), remaining)
	defer cancel()

	for _, svc := range s.services {
		participant, ok := svc.svc.(Shutdowner)
		if !ok {
			continue
		}
		if err := participant.Shutdown(shutdownCtx); err != nil {
			s.log.Error("service shutdown failed", "service", svc.name, "error", err)
		}
	}

	// Last, after every participant has had its chance to write a final
	// record. Each write is already durable at the file layer — the log is
	// opened with O_APPEND and written whole — so this releases the handle
	// rather than flushing a buffer, and a write arriving afterwards simply
	// reopens it.
	if err := s.deps.Audit.Close(); err != nil {
		s.log.Error("closing the audit log failed", "error", err)
	}
	s.log.Info("stopped")
}

// Stop closes the listener and drops in-flight RPCs without draining. It
// exists for tests and for a caller that has already lost patience; the normal
// path is cancelling the context passed to Serve.
//
// It skips the shutdown participants deliberately — that is what "without
// draining" means — but it does release the audit log, because that is an OS
// handle rather than a participant's state. A handle nobody will close is a
// file that cannot be renamed or removed on Windows for as long as the process
// lives, which would make the impatient path leave the log undeletable by the
// very caller that gave up on the server. Closing is idempotent and a later
// write reopens the file, so this costs a shutdown nothing.
func (s *Server) Stop() {
	s.grpc.Stop()
	if err := s.deps.Audit.Close(); err != nil {
		s.log.Error("closing the audit log failed", "error", err)
	}
}

// recoveryUnaryInterceptor turns a panic in a handler into an Internal error.
//
// Without it, one nil map write in any service takes down the daemon — and
// with it the supervisor that is the only thing tracking the fleet's
// background processes. Losing one RPC is a far better outcome than losing
// that.
func recoveryUnaryInterceptor(log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Error("panic in handler", "method", info.FullMethod, "panic", r, "stack", string(debug.Stack()))
				err = status.Errorf(codes.Internal, "internal error handling %s", info.FullMethod)
			}
		}()
		return handler(ctx, req)
	}
}

// recoveryStreamInterceptor is recoveryUnaryInterceptor for streaming RPCs.
func recoveryStreamInterceptor(log *slog.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Error("panic in stream handler", "method", info.FullMethod, "panic", r, "stack", string(debug.Stack()))
				err = status.Errorf(codes.Internal, "internal error handling %s", info.FullMethod)
			}
		}()
		return handler(srv, ss)
	}
}
