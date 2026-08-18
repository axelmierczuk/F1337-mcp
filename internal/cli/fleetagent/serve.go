package fleetagent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"

	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	"github.com/axelmierczuk/fleet-mcp/internal/version"
)

func newServeCommand() *cobra.Command {
	var (
		configPath  string
		listen      string
		logLevel    string
		noJail      bool
		allowPublic bool
		drain       time.Duration
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the agent daemon",
		Long: "serve loads the agent config, opens the gRPC listener, and hosts every\n" +
			"registered service until it is signalled.\n\n" +
			"With tls.enabled true — which is what `fleet-agent enroll` writes — clients\n" +
			"must present a certificate issued by the fleet CA carrying the configured\n" +
			"organisational unit, and the agent presents its own.\n\n" +
			"With tls.enabled false the agent serves plaintext and authenticates nobody:\n" +
			"whatever the network provides is the whole of it. That is a posture for a\n" +
			"network that authenticates its peers — a tailnet, a WireGuard mesh, a tight\n" +
			"VPC — and the daemon refuses to serve it on an address that is neither\n" +
			"loopback nor private unless --allow-unauthenticated-public says otherwise.\n\n" +
			"allowed_roots is enforced only when exec.enabled is false. A caller that can\n" +
			"run commands reaches any path without FileService, so on an exec-enabled\n" +
			"agent the roots are ignored and the daemon says so at every start.\n\n" +
			"On SIGTERM or SIGINT the listener stops accepting, in-flight RPCs are given\n" +
			"the drain deadline to finish, and the daemon exits. Supervised background\n" +
			"processes are not touched: they belong to the host, not to the daemon.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context(), serveOptions{
				configPath:  configPath,
				listen:      listen,
				logLevel:    logLevel,
				noJail:      noJail,
				allowPublic: allowPublic,
				drain:       drain,
			})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to agent.yaml (default: $"+agent.EnvConfig+", the system config, or the enrollment directory)")
	cmd.Flags().StringVar(&listen, "listen", "", "override the config's listen address")
	cmd.Flags().StringVar(&logLevel, "log-level", "", "override the config's log level: debug, info, warn, error")
	cmd.Flags().BoolVar(&noJail, "no-jail", false, "with exec.enabled false, start anyway when allowed_roots is empty (with exec enabled there is no jail to disable)")
	cmd.Flags().BoolVar(&allowPublic, "allow-unauthenticated-public", false,
		"with tls.enabled false, serve on an address that is neither loopback nor private; anyone who can reach the port can run commands on this host")
	cmd.Flags().DurationVar(&drain, "drain-timeout", 0, "how long to wait for in-flight RPCs on shutdown (default "+agent.DefaultDrainTimeout.String()+")")
	return cmd
}

type serveOptions struct {
	configPath string
	listen     string
	logLevel   string
	noJail     bool
	// allowPublic is --allow-unauthenticated-public. It reaches both
	// [agent.Config.Validate] and [agent.New]: the command checks first so the
	// refusal is a clean message, and the daemon checks again because it is
	// what actually binds the socket.
	allowPublic bool
	drain       time.Duration
}

// serverOptions is what the daemon is built from.
//
// Extracted for the same reason enrollRequest is: the version the running
// daemon reports and the version enrollment records are one fact, and a test
// can only hold them to that if both are reachable without starting a daemon
// or dialling a control plane. See reportedVersion and #61.
func serverOptions(cfg *agent.Config, log *slog.Logger, opts serveOptions) agent.Options {
	return agent.Options{
		Config:                     cfg,
		Log:                        log,
		Version:                    reportedVersion(),
		DrainTimeout:               opts.drain,
		AllowUnauthenticatedPublic: opts.allowPublic,
	}
}

func runServe(ctx context.Context, opts serveOptions) error {
	path, err := agent.ResolveConfigPath(opts.configPath)
	if err != nil {
		return err
	}
	cfg, err := agent.Load(path)
	if err != nil {
		return fmt.Errorf("%w\n\nRun `fleet-agent enroll` to create one, or pass --config", err)
	}
	if opts.listen != "" {
		cfg.Listen = opts.listen
	}
	if opts.logLevel != "" {
		cfg.Log.Level = opts.logLevel
	}

	if err := cfg.Validate(agent.ValidateOptions{
		AllowNoJail:                opts.noJail,
		AllowUnauthenticatedPublic: opts.allowPublic,
	}); err != nil {
		if errors.Is(err, agent.ErrNoAllowedRoots) {
			return fmt.Errorf("%w\n\nconfig: %s", err, path)
		}
		if errors.Is(err, agent.ErrUnauthenticatedPublicListen) {
			// The remedy, and the file to edit. This is the one refusal an
			// operator meets while trying to start an agent that works fine on
			// their laptop, so it has to say what to do rather than only what
			// was wrong.
			return fmt.Errorf("%w%s\n\nconfig: %s", err, agent.UnauthenticatedListenRemedy, path)
		}
		return err
	}

	// Logs go to stderr so that stdout stays available for anything a future
	// subcommand wants to write, and because every service manager this agent
	// is installed under captures stderr: journald, launchd's
	// StandardErrorPath, and the Windows event log.
	log, err := cfg.Logger(os.Stderr)
	if err != nil {
		return err
	}

	log.Info("agent starting",
		"config", path,
		"version", version.String(),
		"name", cfg.Name,
	)

	// Before agent.New, which binds the listener.
	//
	// That ordering is the whole reason anything can assert on the record this
	// writes: once the socket is open a client can dial, and a test — or an
	// operator running `service status` the moment a start returns — would be
	// reading whatever the *previous* daemon left in the state directory. Doing
	// it first makes "the port is open" imply "the report describes this
	// process", which is a happens-before rather than a guess about how long a
	// probe takes. Moving this below agent.New reintroduces exactly that race.
	recordRuntime(ctx, cfg, log)

	// The jail state is announced by agent.New, which is the one place that
	// decides it — see jailFor. Doing it here as well would let the two drift.
	srv, err := agent.New(serverOptions(cfg, log, opts))
	if err != nil {
		return err
	}
	return run(ctx, srv, log.Error)
}

// recordRuntime works out what this daemon can actually reach, says so when the
// answer is "not the operator's toolchains", and writes it where `service
// status` will look.
//
// This is the half of #74 that no amount of care at install time can cover.
// `service status` runs as the operator, in the operator's session; everything
// that decides whether the daemon can do its job — the session it landed in,
// the home directory it was given, whether the PATH a spawned command gets
// reaches anything installed per-user — is observable only from in here. So the
// daemon writes it down, once, at start.
//
// Failing to write it is not a reason to refuse to serve. An agent that works
// and cannot be reported on is strictly better than no agent, and the report
// being absent is itself something `status` says.
func recordRuntime(ctx context.Context, cfg *agent.Config, log *slog.Logger) {
	report := collectRuntimeReport(ctx)

	if confinement := confinementFor(report); confinement != nil {
		log.Warn("this agent cannot reach the toolchains installed on this host",
			"account", report.Account,
			"home", report.Home,
			"session_zero", report.SessionZero,
			"unreachable", report.Profile.Unreachable,
			"summary", confinement.Summary,
		)
	} else if report.Profile.Ran != "" {
		// The positive half, and the only evidence anywhere that a command this
		// daemon spawns can run something installed only under a home
		// directory: it was resolved by name off the PATH those commands get,
		// and it ran.
		log.Info("a per-user toolchain resolves and runs", "program", report.Profile.Ran)
	}

	if cfg.StateDir == "" {
		return
	}
	if err := writeRuntimeReport(cfg.StateDir, report); err != nil {
		log.Warn("could not record what `fleet-agent service status` reads to report on this daemon", "error", err)
	}
}

// program adapts the daemon to kardianos/service's lifecycle: Start must
// return promptly and Stop must block until the daemon has finished draining.
type program struct {
	serve  func(context.Context) error
	onErr  func(msg string, args ...any)
	cancel context.CancelFunc
	done   chan error
}

func (p *program) Start(service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan error, 1)
	go func() { p.done <- p.serve(ctx) }()
	return nil
}

func (p *program) Stop(service.Service) error {
	if p.cancel == nil {
		return nil
	}
	p.cancel()
	// Blocking here is the point: kardianos returns from Run as soon as Stop
	// does, and the process exits immediately after. Returning early would cut
	// the drain the daemon was just asked to perform.
	err := <-p.done
	if err != nil && p.onErr != nil {
		p.onErr("daemon exited with an error", "error", err)
	}
	return err
}

// run hosts the server, through the platform's service manager when there is
// one to speak to.
//
// The indirection earns its keep on Windows, where a service must implement
// the SCM control protocol or the manager kills it for failing to report
// started. Elsewhere kardianos waits on SIGTERM and SIGINT exactly as the
// fallback below does, so the two paths agree on behaviour and differ only in
// who owns the signal handler.
func run(ctx context.Context, srv *agent.Server, onErr func(string, ...any)) error {
	prg := &program{serve: srv.Serve, onErr: onErr}

	svc, err := service.New(prg, minimalServiceConfig())
	if err != nil {
		return runWithSignals(ctx, srv)
	}
	if service.Interactive() {
		// Run from a terminal: kardianos would install its own signal handler
		// and ignore the command's context, which is what tests and `serve`
		// under a shell need to be able to cancel.
		return runWithSignals(ctx, srv)
	}
	return svc.Run()
}

// runWithSignals is the plain path: serve until the context is cancelled or a
// termination signal arrives.
func runWithSignals(ctx context.Context, srv *agent.Server) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	return srv.Serve(ctx)
}
