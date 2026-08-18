package fleetagent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
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
			"service with --user is the headless answer.\n\n" +
			"--mechanism service asks which account it should run as when --user does not\n" +
			"say, and asks for that account's password without echoing it. The password is\n" +
			"handed to the SCM and nothing else: it is not written to a file, an environment\n" +
			"variable, the service definition, or a log. Before registering anything,\n" +
			"install performs the same logon the SCM performs at every start, so a mistyped\n" +
			"password or a missing \"Log on as a service\" right is refused at the prompt\n" +
			"rather than producing a service that fails every start. For an unattended\n" +
			"install, pass --user and --password-stdin.",
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
	cmd.Flags().StringVar(&userName, "user", "", "account the daemon runs as (default: "+describeDefaultUser()+"; asked for by --mechanism service)")
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

	// Which account a Windows service runs as is asked for rather than
	// resolved; see resolveAccountChoice.
	//
	// Handed to buildUnitParams as a closure rather than resolved here, so the
	// question is put *after* the config has loaded and the binary has been
	// found. Being asked which account to register under and then told there is
	// no config to register is a question that should never have been asked,
	// and the operator this whole prompt exists for is exactly the one likeliest
	// to hit it.
	//
	// A dry run neither asks nor refuses — it changes nothing, so it has
	// nothing to ask about — and says in the plan that install would. That is
	// the line executableAccessOutcome already draws: a dry run fails only when
	// it cannot produce a plan, and reports, in the plan, what install would
	// refuse to act on.
	choice := resolveAccountChoice(opts.mechanism, runtime.GOOS, opts.userName, opts.passwordStdin)
	resolveAccount := func() (string, error) {
		switch {
		case choice == accountFromFlag:
			return opts.userName, nil
		case opts.dryRun:
			return defaultServiceUser()
		case choice == accountUnaskable:
			return "", errors.New(noAccountToAskRefusal("--password-stdin makes stdin the password, so there is nothing left to ask with"))
		case choice == accountFromPrompt:
			return promptServiceAccount(in, out, suggestedServiceAccount())
		default:
			return defaultServiceUser()
		}
	}

	params, cfg, err := buildUnitParams(opts.configPath, resolveAccount, opts.hardening)
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
		headline, refuse := executableAccessOutcome(runtime.GOOS, opts.dryRun)
		if refuse {
			return fmt.Errorf("%s %s", headline, advice)
		}
		p.Printf("%s %s\n", headline, advice)
	}

	if opts.dryRun {
		for _, m := range otherMechanisms(mechanism) {
			p.Printf("dry run: install would first remove the existing %s registered on this\n", m.Describe())
			p.Println("         host, which would otherwise start a second daemon against the same")
			p.Println("         state directory.")
			// The largest thing that removal does, said by the preview of the
			// command as well as by the command. Removing a task means ending
			// it, and a dry run exists to say what install will do before it
			// does it.
			for _, line := range taskStopNote(m) {
				p.Println(line)
			}
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
		for _, line := range dryRunAccountNotes(params.User, runtime.GOOS, opts.createUser, accountExists(params.User)) {
			p.Println(line)
		}
		for _, line := range dryRunNotes(mechanism, runtime.GOOS, params.User, choice) {
			p.Println(line)
		}
		// Nothing was checked, so nothing may be reported as checked.
		for _, line := range mechanismNotes(mechanism, runtime.GOOS, params.User, false) {
			p.Println(line)
		}
		return p.Err()
	}

	// Only the Windows SCM asks, and only for a named account: a built-in
	// service identity has no password and a Scheduled Task with an interactive
	// logon type does not need one. Read *and checked* before anything is
	// created, so a mistyped password is retyped at the prompt rather than
	// leaving directories, ACLs and a service that fails every start behind.
	password, logonVerified := "", false
	if serviceNeedsPassword(mechanism, runtime.GOOS, params.User) {
		password, logonVerified, err = serviceCredential(in, out, p, params.User, opts.passwordStdin)
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
	if grantDir == "" {
		for _, line := range foreignConfigDirNote(configDir, params.User, runtime.GOOS) {
			p.Println(line)
		}
	}

	// Assembled before anything is removed. newRegistration only builds a
	// definition — it writes nothing to the host — and building it after
	// removeOtherMechanism meant a failure here arrived with the host's only
	// registration already taken off it, reported as "prepare service
	// definition" and reading like nothing had happened.
	svc, err := newRegistration(mechanism, params, password)
	if err != nil {
		return err
	}

	// Remove the registration this one replaces; see otherMechanisms.
	replaced, err := removeOtherMechanism(p, mechanism)
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
	// The agent was running before this command if the registration being
	// replaced was running — and switching mechanism is a replacement. Only
	// the same-mechanism half of that was counted, so the one flow #74 exists
	// to produce — `status` printing "re-register it with --mechanism task" and
	// the operator doing exactly that — stopped a running daemon, registered
	// the new mechanism, started nothing, and said so nowhere.
	wasRunning := replaced.running
	if installed {
		if status, err := svc.Status(); err == nil && status == service.StatusRunning {
			wasRunning = true
			for _, line := range taskStopNote(mechanism) {
				p.Println(line)
			}
			// Stopped before it is removed, which removeOtherMechanism has
			// always done and this path did not.
			//
			// It is not tidiness. DeleteService only *marks* a running service
			// for deletion: the entry stays in the SCM database until the
			// process exits, OpenService keeps finding it, and the
			// CreateService that comes next fails — kardianos reports it as
			// "service fleet-agent already exists". So re-running `install`
			// over its own running Windows service, which this command
			// advertises as safe and which is what an upgrade does, failed and
			// left the host with a definition marked for deletion and no
			// replacement: an agent that disappears at the next reboot. The
			// other two managers are unaffected — launchd's Uninstall stops the
			// job itself, and systemd's disables a unit whose process keeps
			// running — which is why this was invisible everywhere but on the
			// one platform.
			//
			// Best-effort for the reason removeOtherMechanism's is: a stop that
			// fails is not a reason to refuse to replace the definition, and
			// the restart below is what puts the agent back.
			if err := svc.Stop(); err != nil {
				p.Printf("note: could not stop the running %s before replacing it: %v\n", mechanism.Describe(), err)
			}
		}
		if err := svc.Uninstall(); err != nil {
			return fmt.Errorf("replace existing service definition: %w%s", err, stoppedItNote(wasRunning))
		}
		p.Println("existing service definition removed for replacement")
	}

	if err := svc.Install(); err != nil {
		if installed || len(replaced.removed) > 0 {
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
	for _, line := range mechanismNotes(mechanism, runtime.GOOS, params.User, logonVerified) {
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
		// Restart only what is still running, and Start what is not.
		//
		// Not interchangeable, and the difference is decided by the state of
		// the host at this line rather than by what it carried when the command
		// began. The SCM's Restart and launchd's are stop-then-start and give
		// up when the stop fails, and stopping something that is not running
		// fails — ERROR_SERVICE_NOT_ACTIVE on Windows.
		//
		// Deciding it on `installed` was right while the same-mechanism
		// replacement left the old daemon running through it. It stopped being
		// right the moment that path learned to stop the service first, which
		// it has to on Windows because DeleteService only marks a *running*
		// service for deletion. So the definition is now written moments
		// earlier and nothing is running under it — and Restart, on the one
		// platform the stop was added for, reports "could not be started" and
		// never calls Start. `service install` over its own running Windows
		// service would replace the definition correctly and leave the agent
		// down, which is what an upgrade does and what docs/service.md tells an
		// operator is safe to re-run.
		//
		// Asking is cheap, is the same question `install` already asked to
		// decide the replacement, and is right on all three managers: systemd
		// keeps the old process alive across a unit replacement and answers
		// active, so Linux still restarts.
		running := false
		if status, err := svc.Status(); err == nil && status == service.StatusRunning {
			running = true
		}
		resume, moved := svc.Restart, false
		if !running {
			resume, moved = svc.Start, !installed
		}
		switch err := resume(); {
		case err != nil:
			p.Println("note: the agent was running before this command and could not be started")
			p.Printf("      again under the %s: %v\n", mechanism.Describe(), err)
			p.Println("      Run `fleet-agent service start` once the cause above is fixed.")
		case moved:
			// The mechanism changed underneath a running daemon. What happened
			// is a move, and an operator who is not told will read the removal
			// above as the end of it.
			p.Printf("service started under the %s: it was running under the %s this command removed\n",
				mechanism.Describe(), replaced.describe())
		default:
			p.Println("service restarted with the new definition")
		}
	}
	return p.Err()
}

// dryRunNotes is every step the real command would take that nothing in the
// resolved plan above shows: the two prompts, and the one combination install
// refuses to guess at.
//
// A function of the rule rather than a branch inside the command, for the
// reason mechanismNotes is one. Only the Windows SCM asks, so the branch fires
// on one runner in three and — being composed inline — was checked on none of
// them: it is the same shape as the `service stop` warning round 1 found
// composed by a branch nothing reached. What a dry run is *for* is finding out
// what install will do before it does it, and "it will stop and ask you two
// questions" is the part an operator most needs in advance.
//
// The account line matters more than the password one. A dry run resolves the
// account it would have prompted for and prints it as `runs as:`, which is only
// true if the operator presses return; saying so is the difference between a
// preview and a wrong answer.
func dryRunNotes(m Mechanism, goos, account string, choice accountChoice) []string {
	var notes []string
	switch choice {
	case accountFromPrompt:
		notes = append(notes,
			"  install would ask which account the Windows service runs as. The account",
			"     above is the default it would offer; pass --user to choose it up front.")
	case accountUnaskable:
		notes = append(notes,
			"  install would refuse: --password-stdin makes stdin the password, so there is",
			"     nothing left to ask which account to use. Pass --user with it.")
	case accountFromFlag, accountFromDefault:
	}
	if serviceNeedsPassword(m, goos, account) {
		notes = append(notes, fmt.Sprintf("  install would prompt for %s's password, check it against the logon the SCM", account),
			"     performs at every start, and hand it to the SCM.")
	}
	return notes
}

// executableAccessOutcome is what `install` says about a binary the service
// account will not be able to read, and whether saying it ends the command.
//
// executableAccessIsFatal answers the platform half: Windows refuses, because a
// path inside somebody else's profile is one the account provably cannot read,
// and Unix warns, because a supplementary group can grant what the mode bits
// appear to deny. What it does not answer is whether this command is an install
// at all — and the check sits above the dry-run branch, so on the one platform
// that refuses, `install --dry-run` returned the refusal and printed nothing
// else: no mechanism, no account, no state directory, no log directory.
//
// That is the opposite of what a dry run is for. docs/service.md sells it as
// the way to see "which mechanism a host will get, under which account, and
// whether the binary is somewhere that account can read — before running the
// command that acts on it"; answering only the third, by failing, withholds the
// two an operator has no other way to get. The line is: a dry run fails when it
// cannot produce a plan — `--mechanism task` under a built-in identity has no
// plan to print — and reports, in the plan, one that install would refuse to
// act on. This is the second kind.
//
// The Unix half was already right and already driven from the command: it
// warns, prints the plan, and exits zero for the identical condition. Only the
// fatal half was reachable by nobody, and it disagreed. A dry run exits zero
// here for the same reason it does there, and because the two platforms
// disagreeing about the same condition is the shape this branch keeps finding.
//
// goos and dryRun are parameters for the reason resolveMechanism's goos is: the
// rule decides what an operator is told and whether their command stops, and a
// rule only one runner can reach is a rule only that runner checks.
func executableAccessOutcome(goos string, dryRun bool) (headline string, refuse bool) {
	switch {
	case !executableAccessIsFatal(goos):
		return "WARNING:", false
	case dryRun:
		return "dry run: install would refuse this and register nothing:", false
	default:
		return "refusing to install a service that cannot start:", true
	}
}

// foreignConfigDirNote is what an operator is told when the directory holding
// the enrollment material is not one `enroll` created.
//
// Handing over a directory the operator chose is not this command's call to
// make — `--config /etc/agent.yaml` must not turn into `chown fleet /etc` — so
// the files inside it are given away individually and the traversal is left to
// whoever owns the directory. That has to be said, because without it the
// daemon fails every start on a config it cannot reach and nothing names the
// directory as the reason.
//
// It used to be gated on the constant recording that Unix grants access by
// ownership, which turned the message off on Windows: the same `--config`
// outside %ProgramData% left the account with no traverse and printed nothing
// at all — the error-5 shape the executable-access check exists to stop,
// arriving from the config's direction. What differs by platform is the command
// that fixes it, not whether there is anything to say. goos is a parameter for
// the reason resolveMechanism's is, and this is now the only place either
// wording is composed.
func foreignConfigDirNote(dir, account, goos string) []string {
	fix := fmt.Sprintf("chown %s %s", account, dir)
	if goos == "windows" {
		fix = fmt.Sprintf("icacls %s /grant %s", winQuote(dir), winQuote(account+":(RX)"))
	}
	return []string{
		fmt.Sprintf("NOTE: %s is not a directory fleet created, so it was left alone. The", dir),
		fmt.Sprintf("      files inside it were handed over, but %s still has to be able to", account),
		"      traverse it. If the daemon cannot read its config, run:",
		"        " + fix,
	}
}

// winQuote wraps a command-line argument for an operator to paste into a
// Windows shell.
//
// Not %q, which is Go string syntax: it escapes a backslash as two, and every
// interesting value here has backslashes in it. A doubled path is survivable —
// Win32 collapses repeated separators — but a doubled *account* is not, because
// an account name is not a path and nothing collapses anything: `icacls ...
// /grant "CORP\\build:(RX)"` fails with "No mapping between account names and
// security IDs was done", which is a remedy that does not work handed to an
// operator whose daemon cannot read its config. Neither cmd.exe nor PowerShell
// treats a backslash as an escape inside double quotes, so the quotes alone are
// what is wanted, and Windows admits neither a quote nor a newline in a path or
// an account name.
//
// The rule was invisible because the only inputs it was ever given were a Unix
// path and a bare account name, on the platform where neither shape occurs.
func winQuote(arg string) string { return `"` + arg + `"` }

// dryRunAccountNotes is what a dry run says about an account this host does not
// have.
//
// Which account the daemon will run as is one of the three things a dry run
// exists to answer, and whether the host has that account is checked in
// ensureServiceUser — one of the two steps a dry run deliberately does not
// reach. So `install --dry-run --user build` printed a clean plan naming an
// account that does not exist, and the install it was previewing refused. The
// answer differs by platform, so this is a function of the platform rather than
// a branch only one runner ever walks: Linux creates a system account, nothing
// else creates anything.
//
// A built-in Windows service identity is not looked up at all, for the reason
// ensureServiceUser does not look one up: it has no account database entry and
// needs none.
func dryRunAccountNotes(account, goos string, create, exists bool) []string {
	if account == "" || exists || runsInSessionZero(account) {
		return nil
	}
	if goos == "linux" {
		if create {
			return []string{fmt.Sprintf("  install would create the system account %s, which this host does not have.", account)}
		}
		return []string{
			fmt.Sprintf("  WARNING: %s does not exist and --create-user=false, so `service install`", account),
			"           will refuse. Create it, or pass --user with an existing account.",
		}
	}
	return []string{
		fmt.Sprintf("  WARNING: %s does not exist on this host, and fleet does not create accounts", account),
		fmt.Sprintf("           on %s, so `service install` will refuse. Create it, or pass --user", goos),
		"           with an existing account.",
	}
}

// accountExists reports whether name resolves to an account on this host.
//
// Not in either platform file: the lookup is os/user's on all three, and the
// one rule built on it — what a dry run says about an account that is missing —
// has to be reachable from every runner.
func accountExists(name string) bool {
	_, err := user.Lookup(name)
	return err == nil
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
//
// logonVerified is the same kind of parameter and answers the same kind of
// question. `install` now performs the SCM's own logon before it registers
// anything, so on most Windows installs the "you still need
// SeServiceLogonRight" note is not merely redundant — it contradicts what the
// command just proved. It is printed when, and only when, nothing established
// otherwise.
func mechanismNotes(m Mechanism, goos, account string, logonVerified bool) []string {
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
	if serviceNeedsPassword(m, goos, account) && !logonVerified {
		// The other half of the credentials the SCM needs, and the one
		// CreateService does not supply. It takes the password and stores it;
		// it does not grant the account the right to be logged on with it,
		// which the Services MMC does and the API does not. Without it the
		// service installs cleanly and every start fails with error 1069, "the
		// service did not start due to a logon failure" — the same shape as the
		// error 5 this command refuses, from the other direction.
		//
		// #84 turned that from advice into a check: the logon the SCM performs
		// is performed first, and an account without the right is refused
		// before anything is registered. This note is what is left over — the
		// case where the check could not run at all — and it is deliberately
		// the same text as the refusal, composed once in
		// serviceLogonRightAdvice.
		return serviceLogonRightNote(account)
	}
	return nil
}

// suggestedServiceAccount is the account the prompt offers, and pressing return
// accepts.
//
// It is the platform default — with the same refusals, so an elevated shell
// does not get to suggest SYSTEM — and an empty string when there is no
// defensible one, which makes the prompt insist on an answer rather than
// inventing one.
func suggestedServiceAccount() string {
	name, err := defaultServiceUser()
	if err != nil {
		return ""
	}
	return name
}

// taskStopNote is what an operator is told before a command ends a Scheduled
// Task.
//
// Ending a task is not a service manager stop. Task Scheduler terminates the
// processes the task started, which is every background process this agent
// supervises — the thing KillMode=process and AbandonProcessGroup exist to
// prevent on the other two platforms, and the one Windows offers no setting
// for. Losing them is the largest thing any of these commands does, and it is
// invisible until an operator goes looking for a dev server that is gone.
//
// A function rather than a branch inside `service stop`, because `stop` is not
// the only command that ends the task. `uninstall` stops every registration it
// removes, and `install` stops the one it replaces — the same termination, from
// commands whose output said nothing about it, while the command that warned
// was the one an operator was least likely to run by accident.
func taskStopNote(m Mechanism) []string {
	if m != MechanismTask {
		return nil
	}
	return []string{
		"NOTE: ending a Scheduled Task terminates the processes it started, so the",
		"      background processes this agent supervises stop with it.",
	}
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

// stoppedItNote is what has to be said when `install` fails after it has
// already stopped the daemon it was replacing.
//
// Both removals stop first, and on Windows they have to: DeleteService only
// *marks* a running service for deletion, so the entry survives and the
// CreateService that follows fails with "already exists". That makes a failure
// between the stop and the new definition a different event from a failure
// before it — the agent is down, and it is down because of this command. The
// error alone reads as "nothing happened", which is round 4's finding about the
// failed *write* arriving one step earlier, through the stop round 5 added.
//
// It says the agent is stopped rather than guessing at what the manager did
// with the definition, because that is the part an operator can act on and the
// part that is true whatever DeleteService managed.
func stoppedItNote(wasRunning bool) string {
	if !wasRunning {
		return ""
	}
	return fmt.Sprintf("\n\nThe agent was running and was stopped so its definition could be replaced, so %s is not running now. Re-run `service install` once the cause above is fixed, or `service start` to bring back what is still registered",
		ServiceName)
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

// replacedRegistrations is what removeOtherMechanism took off this host, and
// both halves of it decide something the operator sees.
//
// removed being non-empty means a failed install leaves the host with no
// registration at all — the same outcome the same-mechanism replacement below
// already warned about and this one did not, so an operator read "install
// failed" as "nothing happened" while their agent was gone.
//
// running means the daemon was up when the command started. install restarts
// what it replaces; switching mechanism *is* a replacement, and counting only
// the same-mechanism half is what left the agent stopped.
type replacedRegistrations struct {
	removed []Mechanism
	running bool
}

// describe names what was removed, the way the output and the docs do.
func (r replacedRegistrations) describe() string {
	names := make([]string, 0, len(r.removed))
	for _, m := range r.removed {
		names = append(names, m.Describe())
	}
	return strings.Join(names, " and the ")
}

// removeOtherMechanism uninstalls the registration this install is replacing,
// when the host carries one under the other mechanism.
func removeOtherMechanism(p *cli.Printer, keeping Mechanism) (replacedRegistrations, error) {
	var replaced replacedRegistrations
	for _, m := range otherMechanisms(keeping) {
		other, err := controlRegistration(m)
		if err != nil {
			return replaced, err
		}
		// Asked before it is stopped, which is the only moment the answer
		// still exists.
		if status, err := other.Status(); err == nil && status == service.StatusRunning {
			replaced.running = true
			// Only when it is running, unlike `stop` and `uninstall`: install
			// is a command an operator runs on a host in any state, and a task
			// that is not running has nothing to take with it.
			for _, line := range taskStopNote(m) {
				p.Println(line)
			}
		}
		if err := other.Stop(); err != nil {
			p.Printf("note: could not stop the existing %s before removing it: %v\n", m.Describe(), err)
		}
		if err := other.Uninstall(); err != nil {
			return replaced, fmt.Errorf("remove the existing %s, which would otherwise start a second daemon against the same state directory: %w%s",
				m.Describe(), err, stoppedItNote(replaced.running))
		}
		replaced.removed = append(replaced.removed, m)
		p.Printf("removed the existing %s: one host, one agent\n", m.Describe())
	}
	return replaced, nil
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
		// The same warning `service stop` prints, because this is the same
		// termination: uninstall stops every registration it removes, and an
		// operator removing a task loses every process it supervises.
		for _, line := range taskStopNote(mechanism) {
			p.Println(line)
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
	// The directory this host actually uses, not the built-in default.
	// state_dir is configurable and `install` prints the resolved one; naming
	// the default here told an operator with a moved state directory that the
	// thing uninstall keeps is somewhere it is not. stateDirForStatus falls
	// back to the default on a config that will not load, which is the case
	// this command deliberately still works for.
	p.Printf("  %s (supervised process state)\n", stateDirForStatus())
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
		// Said before it happens, not after; see taskStopNote.
		if verb == "stop" || verb == "restart" {
			for _, line := range taskStopNote(mechanism) {
				p.Println(line)
			}
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

	unusable, running := false, false
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
			running = true
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
	switch {
	case reportErr != nil:
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

	case running && report == nil:
		// A daemon that is up has already written this file: `serve` writes it
		// before agent.New binds the listener, so "something is running here"
		// and "there is no record of it" cannot both be true of the same
		// daemon. They can both be true of this command, and there is one way
		// that happens: `install --config` bakes a config path into the service
		// definition, `status` re-discovers a config of its own, and state_dir
		// is read from whichever it found. Looking in the wrong directory then
		// produces the answer this whole issue exists to stop — a confined
		// agent reported as `running`, exiting zero, with nothing said.
		//
		// Silence used to be the answer here on the grounds that an agent which
		// has never started is an ordinary state. It is — but that agent is not
		// running, and this branch is only reached when something says one is.
		p.Println("NOTE: this agent is reported as running and has left no record of what it")
		p.Println("      can reach:")
		p.Printf("        %s\n", runtimeReportPath(stateDir))
		p.Println("      The daemon writes that file at every start, into the state directory")
		p.Println("      of the config it was started with. Until there is one, `status`")
		p.Println("      cannot tell a confined agent from a working one — if `install` was")
		p.Println("      given a --config other than the one above, this command is looking")
		p.Println("      in the wrong place.")
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
func buildUnitParams(configPath string, resolveAccount func() (string, error), level Hardening) (UnitParams, *agent.Config, error) {
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

	// After the config and the executable, and before anything else needs it.
	// On Windows this is where the operator is asked; see runServiceInstall.
	userName, err := resolveAccount()
	if err != nil {
		return UnitParams{}, nil, err
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
//
// Compared through sessionZeroKey, the same normalisation runsInSessionZero
// uses, so the two rules cannot disagree about one account. They did: this one
// matched four literal spellings while the other folded spaces and knew the
// well-known SIDs, so `--user S-1-5-18` — what a report carries when the name
// lookup fails — was refused as a session-0 identity by one rule and passed as
// an ordinary account by this one, printing no warning that every command the
// agent runs would run as the machine.
func isSuperuser(name string) bool {
	switch sessionZeroKey(name) {
	case "root", "localsystem", "system", `ntauthority\system`, `ntauthority\localsystem`, "s-1-5-18":
		return true
	default:
		return false
	}
}
