package fleetagent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
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

// ErrUnusable reports an agent that is installed, running, and confined in a
// way that stops it doing the one thing it exists for.
//
// It is what `service status` exits with, and it is separate from every other
// failure because the operator's experience of it is not a failure at all: the
// daemon is up, health checks pass, and every command a model runs through it
// cannot find a toolchain. Something has to say so.
var ErrUnusable = errors.New("the agent is running but cannot run the operator's toolchain; see the report above")

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
		configPath    string
		userName      string
		hardening     string
		mechanism     string
		createUser    bool
		passwordStdin bool
		dryRun        bool
	)
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Register the agent to start at boot",
		Long: "install writes the platform's service definition with the config path baked\n" +
			"in, creates the state and log directories, and enables the service.\n\n" +
			"Running it a second time rewrites the definition rather than failing, so an\n" +
			"installer can be re-run safely.\n\n" +
			"On Windows there are two mechanisms and the difference decides whether the\n" +
			"agent can work at all. A Windows service runs in session 0, isolated from\n" +
			"every interactive session, so it sees no per-user toolchain: no nvm, rustup,\n" +
			"pyenv, cargo, scoop or npm globals, and none of the credentials in %APPDATA%.\n" +
			"A logon-triggered Scheduled Task runs in the operator's own session and sees\n" +
			"all of it, and stops when they log off. The default is the task; --mechanism\n" +
			"service with --user is the headless answer.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			level, err := ParseHardening(hardening)
			if err != nil {
				return err
			}
			mech, err := ParseMechanism(mechanism)
			if err != nil {
				return err
			}
			return runServiceInstall(out, c.InOrStdin(), installOptions{
				configPath:    configPath,
				userName:      userName,
				hardening:     level,
				mechanism:     mech,
				createUser:    createUser,
				passwordStdin: passwordStdin,
				dryRun:        dryRun,
			})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "agent config to bake into the service definition (default: the discovered config)")
	cmd.Flags().StringVar(&userName, "user", "", "account the daemon runs as (default: "+describeDefaultUser()+")")
	cmd.Flags().StringVar(&hardening, "hardening", string(HardeningStandard), "service confinement: standard, strict, or none")
	cmd.Flags().StringVar(&mechanism, "mechanism", string(MechanismAuto), "how to register: auto, service, or task (Windows only)")
	cmd.Flags().BoolVar(&createUser, "create-user", true, "create the service account when it does not exist")
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "read the service account's password from stdin instead of prompting (Windows services under a named account)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "resolve and print what would be registered, changing nothing and needing no elevation")
	return cmd
}

// installOptions is what `service install` was asked for, before any of it is
// resolved against the host.
type installOptions struct {
	configPath    string
	userName      string
	hardening     Hardening
	mechanism     Mechanism
	createUser    bool
	passwordStdin bool
	// dryRun resolves everything and registers nothing.
	//
	// It is the only way to find out which mechanism a host will get, under
	// which account, and whether the binary is somewhere that account can read
	// it, without running an elevated command that changes the machine. On
	// Windows the answer to the first of those decides whether the agent can do
	// its job at all, which is too large a thing to learn afterwards.
	dryRun bool
}

func runServiceInstall(out io.Writer, in io.Reader, opts installOptions) error {
	// A dry run changes nothing, so it needs nothing. Everything below it does,
	// and refuses here rather than halfway through — half of `install` is
	// creating directories and an account, and discovering the missing
	// privilege at the point the definition is written leaves those behind.
	if !opts.dryRun {
		if err := requireElevated("install"); err != nil {
			return err
		}
	}

	p := cli.NewPrinter(out)

	// Before anything is created, chowned or registered, so an operator who did
	// not read the migration steps can still stop here having changed nothing.
	noteLegacyService(p)

	params, cfg, err := buildUnitParams(opts.configPath, opts.userName, opts.hardening)
	if err != nil {
		return err
	}

	mechanism, err := resolveMechanism(opts.mechanism, runtime.GOOS, params.User)
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
	if !opts.dryRun {
		if err := ensureServiceUser(params.User, opts.createUser); err != nil {
			return err
		}
	}

	// The path the definition will name, checked against the account it will
	// name, before either exists. `install` registers os.Executable() and never
	// copies it, so a binary sitting where the service account cannot read it —
	// a Desktop, a /root — produces a registration that succeeds and a service
	// that fails every start for a reason neither the operator nor this program
	// is present to explain.
	if problem := executableAccessProblem(params.Executable, params.User); problem != "" {
		advice := executableAccessAdvice(problem, params.Executable, params.User, runtime.GOOS)
		if executableAccessIsFatal(runtime.GOOS) {
			return fmt.Errorf("refusing to install a service that cannot start: %s", advice)
		}
		p.Printf("WARNING: %s\n", advice)
	}

	if opts.dryRun {
		for _, m := range otherMechanisms(mechanism) {
			p.Printf("dry run: install would first remove the existing %s registered on this\n", m.Describe())
			p.Println("         host, which would otherwise start a second daemon against the same")
			p.Println("         state directory.")
		}
		p.Printf("dry run: %s would be registered as follows. Nothing has been created,\n", ServiceName)
		p.Println("         granted, or registered.")
		p.Printf("  mechanism: %s\n", mechanism.Describe())
		p.Printf("  runs as:   %s\n", params.User)
		p.Printf("  command:   %s %s\n", params.Executable, strings.Join(params.Arguments(), " "))
		p.Printf("  config:    %s\n", params.ConfigPath)
		p.Printf("  state:     %s\n", params.StateDir)
		p.Printf("  logs:      %s\n", params.LogDir)
		p.Printf("  hardening: %s\n", params.Hardening)
		if serviceNeedsPassword(mechanism, runtime.GOOS, params.User) {
			p.Printf("  install would prompt for %s's password and hand it to the SCM.\n", params.User)
		}
		for _, line := range mechanismNotes(mechanism, runtime.GOOS, params.User) {
			p.Println(line)
		}
		return p.Err()
	}

	// Only the Windows SCM asks, and only for a named account: a built-in
	// service identity has no password and a Scheduled Task with an interactive
	// logon type does not need one. Read before anything is created, so a
	// mistyped password does not leave directories and ACLs behind.
	password := ""
	if serviceNeedsPassword(mechanism, runtime.GOOS, params.User) {
		password, err = servicePassword(in, out, params.User, opts.passwordStdin)
		if err != nil {
			return err
		}
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

	// Remove the registration this one replaces; see otherMechanisms.
	if err := removeOtherMechanism(p, mechanism); err != nil {
		return err
	}

	svc, err := newRegistration(mechanism, params, password)
	if err != nil {
		return err
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
	p.Printf("  mechanism: %s\n", mechanism.Describe())
	p.Printf("  runs as:   %s\n", params.User)
	p.Printf("  config:    %s\n", params.ConfigPath)
	p.Printf("  state:     %s (left in place by uninstall)\n", params.StateDir)
	p.Printf("  logs:      %s\n", params.LogDir)
	p.Printf("  hardening: %s\n", params.Hardening)
	for _, line := range mechanismNotes(mechanism, runtime.GOOS, params.User) {
		p.Println(line)
	}
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

// mechanismNotes is what an operator has to know about the mechanism they just
// got, said at the moment they got it rather than only in a document.
//
// Every entry is something that will otherwise be discovered as a surprise: an
// agent that vanishes at logout, a `service stop` that takes every supervised
// background process with it, a built-in identity that cannot see a toolchain,
// and a named account the SCM will refuse to log on.
//
// goos is a parameter for the same reason resolveMechanism's is: what an
// operator is told is decided by the rule, not by which runner is asking, and
// this is the only place either of the Windows-only notes is composed.
func mechanismNotes(m Mechanism, goos, account string) []string {
	if m == MechanismTask {
		return []string{
			"  NOTE: a logon-triggered task runs while " + account + " is logged on, and stops",
			"        when they log off. For a machine nobody signs into, install with",
			"        --mechanism service --user <account> instead.",
			"  NOTE: `service stop` ends the task, and Task Scheduler terminates what the",
			"        task started — including the background processes this agent",
			"        supervises. A service manager stop leaves them alone.",
		}
	}
	if runsInSessionZero(account) {
		return []string{
			"  WARNING: " + account + " runs in session 0 and has no operator profile, so this",
			"           agent cannot see nvm, rustup, pyenv, cargo, scoop, npm globals, or",
			"           the credentials in %APPDATA% that git and the registries read.",
			"           `service status` will report it as unusable. If that is not what",
			"           you meant, re-install with --mechanism task.",
		}
	}
	if serviceNeedsPassword(m, goos, account) {
		// The other half of the credentials the SCM needs, and the one nothing
		// here can supply. CreateService takes the password and stores it; it
		// does not grant the account the right to be logged on with it, which
		// the Services MMC does and the API does not. Without it the service
		// installs cleanly and every start fails with error 1069, "the service
		// did not start due to a logon failure" — the same shape as the error 5
		// this command now refuses, from the other direction, and granting it
		// means LsaAddAccountRights, which is not a thing to hand-roll here.
		return []string{
			"  NOTE: " + account + " also needs the \"Log on as a service\" right, which the SCM",
			"        stores the password for but does not grant. Without it every start",
			"        fails with error 1069, a logon failure. Grant it with:",
			"          secedit /export /cfg C:\\Windows\\Temp\\sec.cfg",
			"          # add " + account + " to SeServiceLogonRight in that file, then",
			"          secedit /configure /db secedit.sdb /cfg C:\\Windows\\Temp\\sec.cfg /areas USER_RIGHTS",
			"        or add it under Local Security Policy > User Rights Assignment.",
		}
	}
	return nil
}

// servicePassword obtains the account's password for the SCM, and nothing else
// ever sees it.
func servicePassword(in io.Reader, out io.Writer, account string, fromStdin bool) (string, error) {
	if fromStdin {
		return readPassword(in, io.Discard, "")
	}
	password, err := readPassword(in, out, fmt.Sprintf("Password for %s (stored by the SCM as a machine-bound LSA secret): ", account))
	if err != nil {
		return "", fmt.Errorf("read the password for %s: %w\n\nPass --password-stdin to supply it from a pipe instead", account, err)
	}
	return password, nil
}

// otherMechanisms is every registration on this host that is not the one being
// installed.
//
// A host can carry both, and an operator switching between them is exactly how
// that happens. Two registrations means two daemons starting against the same
// state directory, both re-adopting the same supervised processes — the outcome
// the pre-rebrand-service warning describes, from a different cause.
func otherMechanisms(keeping Mechanism) []Mechanism {
	var others []Mechanism
	for _, m := range installedMechanisms() {
		if m != keeping {
			others = append(others, m)
		}
	}
	return others
}

// removeOtherMechanism uninstalls the registration this install is replacing,
// when the host carries one under the other mechanism.
func removeOtherMechanism(p *cli.Printer, keeping Mechanism) error {
	for _, m := range otherMechanisms(keeping) {
		other, err := controlRegistration(m)
		if err != nil {
			return err
		}
		if err := other.Stop(); err != nil {
			p.Printf("note: could not stop the existing %s before removing it: %v\n", m.Describe(), err)
		}
		if err := other.Uninstall(); err != nil {
			return fmt.Errorf("remove the existing %s, which would otherwise start a second daemon against the same state directory: %w", m.Describe(), err)
		}
		p.Printf("removed the existing %s: one host, one agent\n", m.Describe())
	}
	return nil
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
	if err := requireElevated("uninstall"); err != nil {
		return err
	}
	p := cli.NewPrinter(out)

	// The unit's own parameters do not matter for removal — only its name —
	// so uninstall does not require a loadable config. An agent whose config
	// was hand-edited into something invalid must still be removable.
	mechanisms := installedMechanisms()
	if len(mechanisms) == 0 {
		p.Printf("service %s is not installed; nothing to remove\n", ServiceName)
		// "Nothing to remove" is false on a host whose service is still
		// registered under the old name, and that is exactly the host most
		// likely to be running this command.
		noteLegacyService(p)
		return p.Err()
	}

	// Every mechanism, not the first one found, and not up to the first
	// failure. A host that carries both has two daemons to remove; removing one
	// of them is the outcome an operator is least able to detect, and returning
	// at the first error leaves the other one registered for a reason that has
	// nothing to do with it.
	var failures []error
	for _, mechanism := range mechanisms {
		svc, err := controlRegistration(mechanism)
		if err != nil {
			return err
		}
		// Stopping first is best-effort: on some managers uninstalling a
		// running service leaves it running until reboot, and a stop failure is
		// not a reason to refuse to remove the definition.
		if err := svc.Stop(); err != nil {
			p.Printf("note: could not stop the %s before removing it: %v\n", mechanism.Describe(), err)
		}
		if err := svc.Uninstall(); err != nil {
			failures = append(failures, fmt.Errorf("uninstall %s: %w", mechanism.Describe(), err))
			continue
		}
		p.Printf("service %s removed (%s)\n", ServiceName, mechanism.Describe())
	}
	if err := errors.Join(failures...); err != nil {
		return err
	}

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
		RunE:  func(*cobra.Command, []string) error { return runServiceControl(out, verb) },
	}
}

func runServiceControl(out io.Writer, verb string) error {
	mechanisms := installedMechanisms()
	if len(mechanisms) == 0 {
		return fmt.Errorf("%w; run `fleet-agent service install` first", ErrNotInstalled)
	}
	p := cli.NewPrinter(out)
	// Every registration this host carries, and not up to the first failure.
	// The host that carries two is the one this command exists to put right,
	// and a `service stop` that stops the service and returns before it reaches
	// the task leaves the daemon an operator just asked to stop still running —
	// with an error naming the other mechanism as the reason.
	var failures []error
	for _, mechanism := range mechanisms {
		svc, err := controlRegistration(mechanism)
		if err != nil {
			return err
		}
		// Said before it happens, not after. Task Scheduler ends a task by
		// terminating what the task started, which is every background process
		// this agent supervises — the thing KillMode=process and
		// AbandonProcessGroup exist to prevent on the other two platforms, and
		// the one Windows offers no setting for.
		if mechanism == MechanismTask && (verb == "stop" || verb == "restart") {
			p.Println("NOTE: ending a Scheduled Task terminates the processes it started, so the")
			p.Println("      background processes this agent supervises stop with it.")
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
			failures = append(failures, fmt.Errorf("%s %s: %w", verb, mechanism.Describe(), err))
			continue
		}
		p.Printf("service %s: %s requested (%s)\n", ServiceName, verb, mechanism.Describe())
	}
	if err := errors.Join(failures...); err != nil {
		return err
	}
	return p.Err()
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

	mechanisms := installedMechanisms()
	if len(mechanisms) == 0 {
		if _, err := service.New(&program{}, minimalServiceConfig()); err != nil {
			// No init system this library recognises — a bare container, most
			// likely. That is an answer about the host, not a failure of the
			// command, and reporting it as one makes `status` unusable in
			// exactly the environments where an operator most needs to ask.
			//
			// Asked only once nothing is registered: a host that has the agent
			// registered plainly has somewhere to register it, and the library
			// failing to name the manager is then not the interesting fact.
			p.Printf("service %s: no service manager detected on this host (%v)\n", ServiceName, err)
			return p.Err()
		}
		// Not being installed is an answer, not a failure. `service status` is
		// what an operator runs to find out, and what an installer script
		// branches on; exiting non-zero there makes both of them harder to
		// write.
		p.Printf("service %s: not installed\n", ServiceName)
		p.Printf("platform:   %s\n", service.Platform())
		p.Println("run `fleet-agent service install` to register it")
		// The answer above is the one an operator misreads as "the agent is not
		// running" on a host whose service is still registered as sandboxd-agent
		// and running fine.
		noteLegacyService(p)
		return p.Err()
	}
	if len(mechanisms) > 1 {
		names := make([]string, 0, len(mechanisms))
		for _, m := range mechanisms {
			names = append(names, "a "+m.Describe())
		}
		p.Printf("WARNING: this host has the agent registered twice, as %s.\n", strings.Join(names, " and as "))
		p.Println("         Each starts a daemon against the same state directory, and each")
		p.Println("         re-adopts the same supervised processes.")
		p.Println("         Run `fleet-agent service install` to leave exactly one.")
	}

	// The report the running daemon wrote about the environment it was actually
	// started in, and the judgement drawn from it. Everything that decides
	// whether an agent can do its job is observable only from inside the
	// daemon; this command runs outside it.
	stateDir := stateDirForStatus()
	report, reportErr := readLiveRuntimeReport(stateDir)
	confinement := confinementFor(report)

	unusable := false
	for _, mechanism := range mechanisms {
		svc, err := controlRegistration(mechanism)
		if err != nil {
			return err
		}
		status, _ := svc.Status()

		headline := describeStatus(status)
		if status == service.StatusRunning && confinement != nil {
			headline = confinement.Summary
			unusable = true
		}
		p.Printf("service %s: %s\n", ServiceName, headline)
		p.Printf("mechanism:  %s\n", mechanism.Describe())
		p.Printf("platform:   %s\n", service.Platform())
		if status == service.StatusRunning {
			if pid, ok := runningPID(report); ok {
				p.Printf("pid:        %d\n", pid)
			} else {
				p.Println("pid:        unavailable")
			}
			if report != nil {
				p.Printf("runs as:    %s\n", report.Account)
				p.Printf("home:       %s\n", report.Home)
				p.Printf("per-user toolchains: %s\n", describeProfile(report.Profile))
			}
		}
	}
	if path, err := agent.DefaultConfigPath(); err == nil {
		p.Printf("config:     %s\n", path)
	}
	if reportErr != nil {
		// Not a failure of the command, and not silence either. Every answer
		// above about a confined agent comes out of that one file, and an
		// operator who cannot read it is being told "running" by a command that
		// never got to ask the question.
		p.Println("NOTE: could not read the record the daemon writes of what it can reach:")
		p.Printf("        %v\n", reportErr)
		p.Println("      Until this command can read it, `status` cannot tell a confined")
		p.Println("      agent from a working one. Re-run it as the account the agent runs")
		p.Println("      as, or elevated: `install` gives the state directory to that")
		p.Println("      account, and `status` is not an elevated command.")
	}

	if confinement != nil && unusable {
		p.Println("")
		p.Println("UNUSABLE")
		for _, line := range confinement.Detail {
			p.Println(indented("  ", line))
		}
		if len(confinement.Remedy) > 0 {
			p.Println("")
			p.Println(indented("  ", confinement.RemedyIntro))
			for _, line := range confinement.Remedy {
				p.Println(indented("    ", line))
			}
		}
		if err := p.Err(); err != nil {
			return err
		}
		// Non-zero, unlike "not installed". "Not installed" is the answer to a
		// question; an agent that is registered, running and cannot execute
		// anything the operator has installed is a fault, and a script that
		// branches on this command should not read it as success.
		return ErrUnusable
	}
	return p.Err()
}

// runningPID is the daemon's process id: the service manager's answer where
// there is one, and the daemon's own record otherwise.
//
// A Scheduled Task has no SCM entry to query, and every human-readable field
// the task scheduler prints is localised. The report is the daemon saying which
// process it is, which is a better source than either.
func runningPID(report *runtimeReport) (int, bool) {
	if pid, ok := servicePID(); ok {
		return pid, true
	}
	if report != nil && report.PID > 0 {
		return report.PID, true
	}
	return 0, false
}

// indented prefixes a line, leaving an empty one empty rather than turning it
// into trailing whitespace.
func indented(prefix, line string) string {
	if line == "" {
		return ""
	}
	return prefix + line
}

// plural picks the noun for a count.
func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// describeProfile puts the probe's answer in one line.
func describeProfile(result profileResult) string {
	switch result.Visibility {
	case profileVisible:
		if result.Ran != "" {
			return fmt.Sprintf("visible (ran %s)", result.Ran)
		}
		return "visible"
	case profileHidden:
		return fmt.Sprintf("HIDDEN (%s installed and not on its PATH)", plural(len(result.Unreachable), "directory", "directories"))
	default:
		return "unknown (none installed under the home directory it was started with)"
	}
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

// isInstalled reports whether the registration exists.
//
// kardianos/service signals "not installed" as ErrNotInstalled on some
// platforms and as a wrapped manager-specific error on others, so this treats
// any status failure as "not installed" — which is the conservative reading
// for the two callers that matter: install, which would otherwise skip a
// replacement it should have made, and status, which reports it.
func isInstalled(svc registration) bool {
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
