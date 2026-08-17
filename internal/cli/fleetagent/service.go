package fleetagent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"

	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	"github.com/axelmierczuk/fleet-mcp/internal/cli"
)

const (
	// defaultRestartDelay is how long the service manager waits before
	// restarting a failed daemon.
	defaultRestartDelay = 5 * time.Second
	// defaultStopTimeout must exceed agent.DefaultDrainTimeout, or the service
	// manager SIGKILLs the daemon partway through the drain it was asked to
	// perform.
	defaultStopTimeout = agent.DefaultDrainTimeout + 15*time.Second
)

// ErrNotInstalled reports that the service is not registered with the
// platform's service manager.
var ErrNotInstalled = errors.New("service is not installed")

func newServiceCommand(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Register the agent with the platform's service manager",
		Long: "service manages the systemd unit, launchd job, or Windows service that\n" +
			"starts the agent at boot.\n\n" +
			"install and uninstall need elevation. uninstall deliberately leaves the\n" +
			"enrollment credentials and the process state directory in place, so\n" +
			"re-installing rejoins the fleet without enrolling again.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error { return c.Help() },
	}
	cmd.AddCommand(
		newServiceInstallCommand(out),
		newServiceUninstallCommand(out),
		newServiceControlCommand(out, "start", "Start the installed service"),
		newServiceControlCommand(out, "stop", "Stop the installed service"),
		newServiceControlCommand(out, "restart", "Restart the installed service"),
		newServiceStatusCommand(out),
	)
	return cmd
}

func newServiceInstallCommand(out io.Writer) *cobra.Command {
	var (
		configPath string
		userName   string
		hardening  string
		createUser bool
	)
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Register the agent to start at boot",
		Long: "install writes the platform's service definition with the config path baked\n" +
			"in, creates the state and log directories, and enables the service.\n\n" +
			"Running it a second time rewrites the definition rather than failing, so an\n" +
			"installer can be re-run safely.",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			level, err := ParseHardening(hardening)
			if err != nil {
				return err
			}
			return runServiceInstall(out, configPath, userName, level, createUser)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "agent config to bake into the service definition (default: the discovered config)")
	cmd.Flags().StringVar(&userName, "user", "", "account the daemon runs as (default: "+describeDefaultUser()+")")
	cmd.Flags().StringVar(&hardening, "hardening", string(HardeningStandard), "service confinement: standard, strict, or none")
	cmd.Flags().BoolVar(&createUser, "create-user", true, "create the service account when it does not exist")
	return cmd
}

func runServiceInstall(out io.Writer, configPath, userName string, level Hardening, createUser bool) error {
	if err := requireElevation("install"); err != nil {
		return err
	}

	p := cli.NewPrinter(out)

	// Before anything is created, chowned or registered, so an operator who did
	// not read the migration steps can still stop here having changed nothing.
	noteLegacyService(p)

	params, cfg, err := buildUnitParams(configPath, userName, level)
	if err != nil {
		return err
	}

	if isSuperuser(params.User) {
		// Not refused: an operator who means it is allowed to mean it. Said
		// loudly, because it is not a property of the daemon — it is a
		// property of every command any model ever runs through it.
		p.Printf("WARNING: installing to run as %s. Every command this agent executes,\n", params.User)
		p.Printf("         and every file it writes, will run as %s.\n", params.User)
	}
	if err := ensureServiceUser(params.User, createUser); err != nil {
		return err
	}

	// The state directory holds supervised process records and outlives both
	// uninstall and reinstall, so it is created before the service exists and
	// never removed with it.
	for _, dir := range []string{params.StateDir, params.LogDir} {
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		if err := chownToServiceUser(dir, params.User); err != nil {
			return fmt.Errorf("set ownership of %s to %s: %w", dir, params.User, err)
		}
	}

	// The account the daemon runs as also has to be able to read what it was
	// enrolled with. `enroll` writes agent.yaml and the private key at 0600,
	// into a 0700 directory when it runs elevated, owned by whoever ran it —
	// and `install` is what changes the account underneath them. Without this
	// step the advertised one-line install (enroll as root, install, start)
	// registers a service cleanly and then fails every start on "permission
	// denied" opening its own certificate.
	configDir := filepath.Dir(params.ConfigPath)
	grantDir := ""
	if enrollmentDirIsOurs(configDir) {
		grantDir = configDir
	}
	if err := grantServiceUserAccess(params.User, grantDir, enrollmentMaterial(cfg, params.ConfigPath)); err != nil {
		return err
	}
	if grantDir == "" && serviceAccessByOwnership {
		// Handing over a directory the operator chose is not this command's
		// call to make: --config /etc/agent.yaml would make that directory
		// /etc. The files inside it were given away individually; the
		// traversal has to be granted by whoever owns the directory.
		p.Printf("NOTE: %s is not a directory fleet created, so its ownership was left\n", configDir)
		p.Printf("      alone — the files inside it were handed over, but %s still has to\n", params.User)
		p.Println("      be able to traverse it. If the daemon cannot read its config, run:")
		p.Printf("        chown %s %s\n", params.User, configDir)
	}

	svc, err := service.New(&program{}, params.ServiceConfig())
	if err != nil {
		return fmt.Errorf("prepare service definition: %w", err)
	}

	// Idempotency. kardianos/service refuses to install over an existing unit
	// on every platform, so a second `install` would fail with "already
	// exists" — which turns re-running an installer, the most ordinary thing
	// an operator does, into an error. Replacing the definition is both
	// idempotent and what an operator re-running install actually wants: the
	// config path or the hardening level may have changed.
	installed := isInstalled(svc)
	wasRunning := false
	if installed {
		if status, err := svc.Status(); err == nil && status == service.StatusRunning {
			wasRunning = true
		}
		if err := svc.Uninstall(); err != nil {
			return fmt.Errorf("replace existing service definition: %w", err)
		}
		p.Println("existing service definition removed for replacement")
	}

	if err := svc.Install(); err != nil {
		if installed {
			// The replacement is not atomic on any of the three service
			// managers, so a failure here leaves the host with no service at
			// all. Say that, rather than letting an operator read "install
			// failed" as "nothing happened".
			return fmt.Errorf("install service: %w\n\nThe previous definition was already removed, so %s is now not installed. Re-run `service install` once the cause above is fixed",
				err, ServiceName)
		}
		return fmt.Errorf("install service: %w", err)
	}

	if installed {
		p.Printf("service %s reinstalled\n", ServiceName)
	} else {
		p.Printf("service %s installed\n", ServiceName)
	}
	p.Printf("  runs as:   %s\n", params.User)
	p.Printf("  config:    %s\n", params.ConfigPath)
	p.Printf("  state:     %s (left in place by uninstall)\n", params.StateDir)
	p.Printf("  logs:      %s\n", params.LogDir)
	p.Printf("  hardening: %s\n", params.Hardening)
	switch {
	case !cfg.JailEnforced():
		p.Println("  NOTE: exec is enabled, so allowed_roots is not enforced. This agent")
		p.Println("        can read and write every path the account above can.")
	case len(cfg.AllowedRoots) == 0:
		p.Println("  WARNING: exec is disabled and the config has no allowed_roots, so the")
		p.Println("           agent will refuse to start unless serve is given --no-jail.")
	}

	if wasRunning {
		if err := svc.Restart(); err != nil {
			p.Printf("note: the service was running but could not be restarted: %v\n", err)
		} else {
			p.Println("service restarted with the new definition")
		}
	}
	return p.Err()
}

func newServiceUninstallCommand(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the service definition, keeping credentials and process state",
		Long: "uninstall removes the unit, job, or service registration. It deliberately\n" +
			"leaves the enrollment certificate, key, CA bundle, config, and process state\n" +
			"directory in place: re-installing then rejoins the fleet without minting and\n" +
			"redeeming a new enrollment token.",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error { return runServiceUninstall(out) },
	}
	return cmd
}

func runServiceUninstall(out io.Writer) error {
	if err := requireElevation("uninstall"); err != nil {
		return err
	}
	p := cli.NewPrinter(out)

	// The unit's own parameters do not matter for removal — only its name —
	// so uninstall does not require a loadable config. An agent whose config
	// was hand-edited into something invalid must still be removable.
	svc, err := service.New(&program{}, minimalServiceConfig())
	if err != nil {
		return fmt.Errorf("prepare service definition: %w", err)
	}
	if !isInstalled(svc) {
		p.Printf("service %s is not installed; nothing to remove\n", ServiceName)
		// "Nothing to remove" is false on a host whose service is still
		// registered under the old name, and that is exactly the host most
		// likely to be running this command.
		noteLegacyService(p)
		return p.Err()
	}

	// Stopping first is best-effort: on some managers uninstalling a running
	// service leaves it running until reboot, and a stop failure is not a
	// reason to refuse to remove the definition.
	if err := svc.Stop(); err != nil {
		p.Printf("note: could not stop the service before removing it: %v\n", err)
	}
	if err := svc.Uninstall(); err != nil {
		return fmt.Errorf("uninstall service: %w", err)
	}

	p.Printf("service %s removed\n", ServiceName)
	p.Println("left in place:")
	if path, err := agent.DefaultConfigPath(); err == nil {
		p.Printf("  %s and the certificate, key, and CA bundle beside it\n", path)
	}
	p.Printf("  %s (supervised process state)\n", agent.DefaultStateDir())
	p.Println("re-run `fleet-agent service install` to rejoin without enrolling again")
	return p.Err()
}

func newServiceControlCommand(out io.Writer, verb, short string) *cobra.Command {
	return &cobra.Command{
		Use:   verb,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			svc, err := service.New(&program{}, minimalServiceConfig())
			if err != nil {
				return fmt.Errorf("prepare service definition: %w", err)
			}
			if !isInstalled(svc) {
				return fmt.Errorf("%w; run `fleet-agent service install` first", ErrNotInstalled)
			}
			switch verb {
			case "start":
				err = svc.Start()
			case "stop":
				err = svc.Stop()
			case "restart":
				err = svc.Restart()
			}
			if err != nil {
				return fmt.Errorf("%s service: %w", verb, err)
			}
			p := cli.NewPrinter(out)
			p.Printf("service %s: %s requested\n", ServiceName, verb)
			return p.Err()
		},
	}
}

func newServiceStatusCommand(out io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report whether the service is installed, running, and its PID",
		Args:  cobra.NoArgs,
		RunE:  func(*cobra.Command, []string) error { return runServiceStatus(out) },
	}
}

func runServiceStatus(out io.Writer) error {
	p := cli.NewPrinter(out)

	svc, err := service.New(&program{}, minimalServiceConfig())
	if err != nil {
		// No init system this library recognises — a bare container, most
		// likely. That is an answer about the host, not a failure of the
		// command, and reporting it as one makes `status` unusable in exactly
		// the environments where an operator most needs to ask.
		p.Printf("service %s: no service manager detected on this host (%v)\n", ServiceName, err)
		return p.Err()
	}

	status, statusErr := svc.Status()
	// Not being installed is an answer, not a failure. `service status` is what
	// an operator runs to find out, and what an installer script branches on;
	// exiting non-zero there makes both of them harder to write.
	if errors.Is(statusErr, service.ErrNotInstalled) || status == service.StatusUnknown && statusErr != nil {
		p.Printf("service %s: not installed\n", ServiceName)
		p.Printf("platform:   %s\n", service.Platform())
		p.Println("run `fleet-agent service install` to register it")
		// The answer above is the one an operator misreads as "the agent is not
		// running" on a host whose service is still registered as sandboxd-agent
		// and running fine.
		noteLegacyService(p)
		return p.Err()
	}

	p.Printf("service %s: %s\n", ServiceName, describeStatus(status))
	p.Printf("platform:   %s\n", service.Platform())
	if status == service.StatusRunning {
		if pid, ok := servicePID(); ok {
			p.Printf("pid:        %d\n", pid)
		} else {
			p.Println("pid:        unavailable")
		}
	}
	if path, err := agent.DefaultConfigPath(); err == nil {
		p.Printf("config:     %s\n", path)
	}
	return p.Err()
}

func describeStatus(s service.Status) string {
	switch s {
	case service.StatusRunning:
		return "running"
	case service.StatusStopped:
		return "installed, stopped"
	default:
		return "installed, state unknown"
	}
}

// isInstalled reports whether the service is registered.
//
// kardianos/service signals "not installed" as ErrNotInstalled on some
// platforms and as a wrapped manager-specific error on others, so this treats
// any status failure as "not installed" — which is the conservative reading
// for the two callers that matter: install, which would otherwise skip a
// replacement it should have made, and status, which reports it.
func isInstalled(svc service.Service) bool {
	status, err := svc.Status()
	if err == nil {
		return status != service.StatusUnknown
	}
	return false
}

// minimalServiceConfig is enough to address an installed service by name, for
// the commands that only control one.
func minimalServiceConfig() *service.Config {
	return &service.Config{
		Name:        ServiceName,
		DisplayName: "fleet agent",
		Description: "Runs commands and serves files for a fleet over mTLS gRPC.",
	}
}

// buildUnitParams resolves everything the service definition needs, and loads
// the config so that install fails on a broken one rather than registering a
// service that cannot start.
func buildUnitParams(configPath, userName string, level Hardening) (UnitParams, *agent.Config, error) {
	resolved, err := agent.ResolveConfigPath(configPath)
	if err != nil {
		return UnitParams{}, nil, err
	}
	cfg, err := agent.Load(resolved)
	if err != nil {
		return UnitParams{}, nil, fmt.Errorf("%w\n\nRun `fleet-agent enroll` first, or pass --config with the path to an existing config", err)
	}

	exe, err := os.Executable()
	if err != nil {
		return UnitParams{}, nil, fmt.Errorf("determine this binary's path: %w", err)
	}
	// A service definition must name a stable path. Resolving symlinks here
	// means a unit installed from a versioned path keeps pointing at the
	// binary that was installed, not at whatever a symlink is repointed to.
	if target, err := filepath.EvalSymlinks(exe); err == nil {
		exe = target
	}

	if userName == "" {
		userName, err = defaultServiceUser()
		if err != nil {
			return UnitParams{}, nil, err
		}
	}

	logDir := agent.DefaultLogDir()
	if cfg.Audit.Path != "" {
		// Keep the audit log and the service logs in one directory, so an
		// operator who moved one does not have to remember the other.
		logDir = filepath.Dir(cfg.Audit.Path)
	}

	return UnitParams{
		Executable:   exe,
		ConfigPath:   resolved,
		User:         userName,
		AllowedRoots: cfg.AllowedRoots,
		StateDir:     cfg.StateDir,
		LogDir:       logDir,
		RestartDelay: defaultRestartDelay,
		StopTimeout:  defaultStopTimeout,
		Hardening:    level,
	}, cfg, nil
}

// enrollmentMaterial is every file the daemon must be able to read as whichever
// account it ends up running as: its config, and the three TLS files the config
// names.
//
// `enroll` writes all four with the permissions of whoever ran it — 0600 for
// the config and the private key — and `install` is the step that decides the
// daemon will run as somebody else. Nothing else reconciles the two.
func enrollmentMaterial(cfg *agent.Config, configPath string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, 4)
	for _, path := range []string{configPath, cfg.TLS.Certificate, cfg.TLS.PrivateKey, cfg.TLS.CABundle} {
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	return out
}

// enrollmentDirIsOurs reports whether dir is a directory `enroll` created for
// the agent, and which `install` may therefore hand to the service account.
//
// Individual files can be given away wherever they live. The directory holding
// them cannot: making it traversable means changing its ownership, and
// `--config /etc/agent.yaml` would make that directory /etc. So only the two
// locations enroll writes to are eligible, and anything else is reported to the
// operator instead of quietly reassigned.
func enrollmentDirIsOurs(dir string) bool {
	dir = filepath.Clean(dir)
	if dir == filepath.Clean(agent.SystemConfigDir()) {
		return true
	}
	userDir, err := agent.UserConfigDir()
	return err == nil && dir == filepath.Clean(userDir)
}

// isSuperuser reports whether name is the platform's all-powerful account.
func isSuperuser(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "root", "localsystem", "system", `nt authority\system`:
		return true
	default:
		return false
	}
}
