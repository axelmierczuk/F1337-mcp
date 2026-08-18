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

// runServe hosts the daemon, through the platform's service manager when one
// started this process.
//
// The order is the whole of #98. Everything that can fail — resolving the
// config, refusing a posture the agent must not serve, opening the log, binding
// the listener — now happens *inside* the manager's own start callback, which
// kardianos calls after it has reported SERVICE_START_PENDING to the SCM. Before
// this it happened first, so a daemon that refused to serve exited before it
// could perform the handshake at all: the SCM waited its 30 seconds and reported
// the silence as "Error 1053: the service did not respond to the start or
// control request in a timely fashion", and the four lines naming the listen
// address went to a stderr nobody was reading. From inside the callback the same
// refusal is a service that stopped with a service-specific error, reported in
// milliseconds, with the reason in the event log and in the record `service
// status` reads.
func runServe(ctx context.Context, opts serveOptions) error {
	prg := &program{
		start: func(c context.Context) (*agent.Server, *slog.Logger, error) {
			return startAgent(c, opts)
		},
	}

	host, managed := serviceManagerHost(prg)
	if !managed {
		// An operator started this: no manager to hand a failure to, and a
		// stderr they are looking at. `serve` under a shell and every test take
		// this path, and kardianos is deliberately not in it — it installs its
		// own signal handler and ignores the command's context, which is what a
		// caller cancelling MainContext needs.
		srv, _, err := prg.start(ctx)
		if err != nil {
			return err
		}
		return runWithSignals(ctx, srv)
	}

	err := host.run()
	if err != nil && host.log != nil {
		// The one place the reason can still reach the operator. A service's
		// stderr is discarded by the SCM, so this is what puts it in
		// services.msc and in `Get-EventLog -LogName Application -Source
		// fleet-agent`; on the other two platforms the manager's log is
		// journald and launchd's error path, which already have the same text
		// from stderr.
		host.log(startupFailureMessage(err))
	}
	return err
}

// startAgent does everything that can fail before the daemon is serving, and
// records why when something does.
//
// The record is the half of #98 that no amount of care in the service manager
// covers. A Scheduled Task is started by `schtasks /Run`, which succeeds
// whatever the daemon then does, and its stderr goes to the scheduler rather
// than to a log; a service under an account that cannot read its own config
// fails at a moment no operator is watching. `service status` is the command an
// operator runs next in both cases, and until now the only thing it could say
// about a daemon that never started was that the service was installed and
// stopped.
func startAgent(ctx context.Context, opts serveOptions) (srv *agent.Server, log *slog.Logger, err error) {
	// Where the failure below would be recorded, narrowed by each step that
	// learns more about this host. Deferred so that every return in this
	// function is recorded, including the ones added after it.
	site := startFailureSite{configPath: opts.configPath}
	defer func() {
		if err != nil {
			site.record(err)
		}
	}()

	path, err := agent.ResolveConfigPath(opts.configPath)
	if err != nil {
		return nil, nil, err
	}
	site.configPath = path
	cfg, err := agent.Load(path)
	if err != nil {
		return nil, nil, fmt.Errorf("%w\n\nRun `fleet-agent enroll` to create one, or pass --config", err)
	}
	site.stateDir = cfg.StateDir
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
			return nil, nil, fmt.Errorf("%w\n\nconfig: %s", err, path)
		}
		if errors.Is(err, agent.ErrUnauthenticatedPublicListen) {
			// The remedy, and the file to edit. This is the one refusal an
			// operator meets while trying to start an agent that works fine on
			// their laptop, so it has to say what to do rather than only what
			// was wrong.
			return nil, nil, fmt.Errorf("%w%s\n\nconfig: %s", err, agent.UnauthenticatedListenRemedy, path)
		}
		return nil, nil, err
	}

	// Logs go to stderr so that stdout stays available for anything a future
	// subcommand wants to write, and because every service manager this agent
	// is installed under captures stderr: journald, launchd's
	// StandardErrorPath, and the Windows event log.
	log, err = cfg.Logger(os.Stderr)
	if err != nil {
		return nil, nil, err
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
	srv, err = agent.New(serverOptions(cfg, log, opts))
	if err != nil {
		return nil, nil, err
	}

	// The listener is open, so this start is not a failed one. Anything the last
	// failure left behind would otherwise have `service status` reporting a
	// fault an operator has already fixed.
	site.clear()
	return srv, log, nil
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

// program adapts the daemon to kardianos/service's lifecycle: Start does
// everything that can fail and must return promptly, and Stop must block until
// the daemon has finished draining.
//
// Start builds the daemon rather than being handed one. That is what puts the
// startup inside the manager's own callback — see runServe — and it is why a
// failure to start is now something the manager is *told* rather than something
// it infers from a process that vanished.
type program struct {
	// start builds the daemon. nil in the several places that need a
	// service.Interface only to address an already-installed registration by
	// name; those never call Run, and Start refuses rather than panicking if a
	// future one does.
	start  func(context.Context) (*agent.Server, *slog.Logger, error)
	onErr  func(msg string, args ...any)
	cancel context.CancelFunc
	done   chan error
}

func (p *program) Start(service.Service) error {
	if p.start == nil {
		return errors.New("this registration was built to address an installed service, not to run one")
	}
	// Not the command's context: kardianos owns the lifecycle here, and Stop is
	// what ends this one.
	ctx, cancel := context.WithCancel(context.Background())
	srv, log, err := p.start(ctx)
	if err != nil {
		cancel()
		// Returned, not logged and swallowed. kardianos hands this back out of
		// Run — and on Windows reports the service as stopped with a
		// service-specific exit code — which is the difference between an
		// operator seeing a reason and an operator seeing error 1053.
		return err
	}
	p.onErr = log.Error
	p.cancel = cancel
	p.done = make(chan error, 1)
	go func() { p.done <- srv.Serve(ctx) }()
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

// managedHost is what the platform's service manager gives a daemon it started:
// somewhere to run, and somewhere to report a failure that stderr will not
// carry.
type managedHost struct {
	// run performs the manager's start handshake, calls the program's Start, and
	// blocks until the manager asks the daemon to stop. It returns whatever
	// Start or Stop returned.
	run func() error
	// log writes one message where the platform's service manager collects a
	// daemon's own account of itself: the Windows event log, journald, launchd's
	// error path. nil when there is nothing to write to.
	log func(string)
}

// serviceManagerHost reports how this process was started, and is the seam every
// test drives #98 through.
//
// It is indirected for the reason controlRegistration is: no runner here is a
// service manager, and on Windows the log it returns is an event-log handle that
// only exists inside a real service — kardianos opens it with eventlog.Open
// against the source its own Install registered. The decisions built on both —
// that startup happens inside the manager's handshake, and that a daemon which
// cannot start says why somewhere the operator can read it rather than exiting
// into a discarded stderr — are the whole of #98 and would otherwise be reachable
// by nothing.
//
// Assigned only by a test, and only for the duration of one.
var serviceManagerHost = hostServiceManagerHost

// hostServiceManagerHost answers for the real host: a manager when one started
// this process, and nothing when an operator did.
func hostServiceManagerHost(prg *program) (*managedHost, bool) {
	if service.Interactive() {
		// A terminal, a test, or anything else an operator started. kardianos
		// would install its own signal handler and ignore the command's
		// context, which is what a cancellable MainContext needs.
		return nil, false
	}
	svc, err := service.New(prg, minimalServiceConfig())
	if err != nil {
		// No init system this library recognises — a bare container, most
		// likely. There is nothing to hand a failure to and nothing to perform a
		// handshake with, so the plain path is the whole of what this host can
		// do.
		return nil, false
	}
	host := &managedHost{run: svc.Run}
	if logger, err := svc.Logger(nil); err == nil {
		// Not fatal when it fails. A daemon that cannot open the event log or
		// the syslog socket still has to start, and a failure to start still has
		// the record `service status` reads.
		host.log = func(msg string) { _ = logger.Error(msg) }
	}
	return host, true
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
