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
	Jail Jail

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
func New(opts Options) (*Server, error) {
	if opts.Config == nil {
		return nil, errors.New("agent: Options.Config is required")
	}
	if opts.Log == nil {
		return nil, errors.New("agent: Options.Log is required")
	}

	tlsConf, err := ServerTLSConfig(opts.Config)
	if err != nil {
		return nil, err
	}

	jailed := opts.Jail
	if jailed == nil {
		jailed, err = NewJail(opts.Config.AllowedRoots)
		if err != nil {
			return nil, err
		}
	}

	drain := opts.DrainTimeout
	if drain <= 0 {
		drain = DefaultDrainTimeout
	}

	deps := Deps{
		Config:    opts.Config,
		Jail:      jailed,
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
		"jail", s.deps.Jail.Enabled(),
		"allowed_roots", s.deps.Jail.Roots(),
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
	s.log.Info("stopped")
}

// Stop closes the listener and drops in-flight RPCs without draining. It
// exists for tests and for a caller that has already lost patience; the normal
// path is cancelling the context passed to Serve.
func (s *Server) Stop() { s.grpc.Stop() }

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
