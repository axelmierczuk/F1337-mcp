package sandboxdagent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"

	"github.com/axelmierczuk/sandboxd-mcp/internal/agent"
	"github.com/axelmierczuk/sandboxd-mcp/internal/version"
)

func newServeCommand() *cobra.Command {
	var (
		configPath string
		listen     string
		logLevel   string
		noJail     bool
		drain      time.Duration
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the agent daemon",
		Long: "serve loads the agent config, opens an mTLS gRPC listener, and hosts every\n" +
			"registered service until it is signalled.\n\n" +
			"mTLS is mandatory. Clients must present a certificate issued by the fleet CA\n" +
			"carrying the configured organisational unit; there is no plaintext mode.\n\n" +
			"On SIGTERM or SIGINT the listener stops accepting, in-flight RPCs are given\n" +
			"the drain deadline to finish, and the daemon exits. Supervised background\n" +
			"processes are not touched: they belong to the host, not to the daemon.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context(), serveOptions{
				configPath: configPath,
				listen:     listen,
				logLevel:   logLevel,
				noJail:     noJail,
				drain:      drain,
			})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to agent.yaml (default: $"+agent.EnvConfig+", the system config, or the enrollment directory)")
	cmd.Flags().StringVar(&listen, "listen", "", "override the config's listen address")
	cmd.Flags().StringVar(&logLevel, "log-level", "", "override the config's log level: debug, info, warn, error")
	cmd.Flags().BoolVar(&noJail, "no-jail", false, "start with no filesystem confinement when allowed_roots is empty")
	cmd.Flags().DurationVar(&drain, "drain-timeout", 0, "how long to wait for in-flight RPCs on shutdown (default "+agent.DefaultDrainTimeout.String()+")")
	return cmd
}

type serveOptions struct {
	configPath string
	listen     string
	logLevel   string
	noJail     bool
	drain      time.Duration
}

func runServe(ctx context.Context, opts serveOptions) error {
	path, err := agent.ResolveConfigPath(opts.configPath)
	if err != nil {
		return err
	}
	cfg, err := agent.Load(path)
	if err != nil {
		return fmt.Errorf("%w\n\nRun `sandboxd-agent enroll` to create one, or pass --config", err)
	}
	if opts.listen != "" {
		cfg.Listen = opts.listen
	}
	if opts.logLevel != "" {
		cfg.Log.Level = opts.logLevel
	}

	if err := cfg.Validate(agent.ValidateOptions{AllowNoJail: opts.noJail}); err != nil {
		if errors.Is(err, agent.ErrNoAllowedRoots) {
			return fmt.Errorf("%w\n\nconfig: %s", err, path)
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

	if len(cfg.AllowedRoots) == 0 {
		// Loud, every start, at WARN. A jail that was disabled for one
		// afternoon of debugging and never re-enabled is exactly the failure
		// this line exists to keep visible.
		log.Warn("STARTING WITHOUT A PATH JAIL",
			"reason", "allowed_roots is empty and --no-jail was passed",
			"consequence", "every path on this host is reachable through FileService and ExecService",
			"config", path)
	}

	srv, err := agent.New(agent.Options{
		Config:       cfg,
		Log:          log,
		Version:      version.Version,
		DrainTimeout: opts.drain,
	})
	if err != nil {
		return err
	}

	log.Info("agent starting",
		"config", path,
		"version", version.String(),
		"name", cfg.Name,
	)
	return run(ctx, srv, log.Error)
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
