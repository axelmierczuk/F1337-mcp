package fleetagent_test

import (
	"bytes"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/cli/fleetagent"
)

// `service install` as a sequence, driven from the argv an operator types.
//
// Everything in here is production code that only runs once a definition
// reaches a real service manager, so until #79's fourth audit round none of it
// was reached by anything: removing the registration being replaced, noticing
// the daemon was running, restarting it afterwards, and saying what a failed
// write left behind could each be deleted with the whole suite still green.
// The seam is at newRegistration — see PinInstallForTest — and the command
// above it is the real one.

// installConfig writes a config whose state and log directories are inside a
// directory the test owns, and points the agent's own discovery at it.
//
// Both matter: `install` creates and takes ownership of both directories, and
// with the shipped defaults those are /var/lib/fleet and /var/log/fleet. The
// log directory follows audit.path, which agent.Load defaults into the shipped
// log directory when the config leaves it out.
func installConfig(t *testing.T, tls string) (configPath, stateDir, logDir string) {
	t.Helper()
	dir := t.TempDir()
	stateDir = filepath.Join(dir, "state")
	logDir = filepath.Join(dir, "logs")
	configPath = filepath.Join(dir, "agent.yaml")

	body := "name: test-host\nlisten: 127.0.0.1:0\n" +
		"state_dir: " + filepath.ToSlash(stateDir) + "\n" +
		"audit:\n  path: " + filepath.ToSlash(filepath.Join(logDir, "audit.jsonl")) + "\n" + tls
	require.NoError(t, os.WriteFile(configPath, []byte(body), 0o600))
	t.Setenv("FLEET_AGENT_CONFIG", configPath)
	return configPath, stateDir, logDir
}

// installAccount is an account this host will let `service install` register
// under without touching an ACL, an account database or a password prompt.
//
// On Unix that is the invoking user: chowning to one's own account needs no
// privilege. On Windows it is a built-in service identity, which install grants
// nothing at all — and %USERPROFILE% is moved somewhere the test binary is not
// under, because the executable-access rule refuses a built-in identity a
// binary inside somebody's profile and the test binary lives in one.
//
// It also makes the resolved mechanism the same on every runner — a built-in
// identity can only be a service, and off Windows a service is the only
// mechanism there is — so the registration these scenarios replace is the
// Scheduled Task everywhere.
func installAccount(t *testing.T) []string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", filepath.Join(t.TempDir(), "profile"))
		return []string{"--user", `NT AUTHORITY\NetworkService`}
	}
	current, err := user.Current()
	require.NoError(t, err)
	return []string{"--user", current.Username}
}

// installArgs is `service install` with the config and account pinned.
func installArgs(t *testing.T) []string {
	t.Helper()
	configPath, _, _ := installConfig(t, "")
	return append([]string{"service", "install", "--config", configPath}, installAccount(t)...)
}

// Switching mechanism on a host whose daemon is running leaves it running.
//
// This is the flow #74 exists to produce: `service status` reports the agent
// unusable and prints `service install --mechanism task` as the remedy, and an
// operator runs it. install removed the registration it was replacing — which
// stops the daemon — registered the new one, and started nothing, so following
// the advice `status` gives took the agent down and nothing in the output said
// so. The same command replacing its *own* mechanism restarted it, which is the
// promise this had to keep and did not.
func TestServiceInstall_SwitchingMechanismKeepsTheAgentRunning(t *testing.T) {
	args := installArgs(t)
	calls, _, restore := fleetagent.PinInstallForTest(fleetagent.InstallHostForTest{
		Installed: []fleetagent.Mechanism{fleetagent.MechanismTask},
		Running:   map[fleetagent.Mechanism]bool{fleetagent.MechanismTask: true},
	})
	defer restore()

	out := &bytes.Buffer{}
	code := fleetagent.Main(args, out)
	text := out.String()
	require.Equal(t, 0, code, "%s", text)

	assert.Equal(t, []string{"task:stop", "task:uninstall", "new:install", "new:start"}, calls(),
		"the daemon was running before this command, so it has to be running after it — and started, "+
			"not restarted: the SCM and launchd give up on a restart whose stop failed, and stopping a "+
			"definition written moments ago always fails")
	assert.Contains(t, text, "removed the existing "+fleetagent.MechanismTask.Describe())
	assert.Contains(t, text, "it was running under the "+fleetagent.MechanismTask.Describe(),
		"and the operator has to be told the agent was moved rather than only that something was removed")
}

// The same host with the daemon *not* running is left not running.
//
// Without this, "always start it" would pass the scenario above — and starting
// an agent an operator had deliberately stopped is its own surprise. `install`
// registers; `service start` starts.
func TestServiceInstall_SwitchingMechanismDoesNotStartAStoppedAgent(t *testing.T) {
	args := installArgs(t)
	calls, _, restore := fleetagent.PinInstallForTest(fleetagent.InstallHostForTest{
		Installed: []fleetagent.Mechanism{fleetagent.MechanismTask},
	})
	defer restore()

	out := &bytes.Buffer{}
	require.Equal(t, 0, fleetagent.Main(args, out), "%s", out.String())
	assert.Equal(t, []string{"task:stop", "task:uninstall", "new:install"}, calls())
	assert.NotContains(t, out.String(), "it was running under")
}

// Re-running install over its own registration replaces the definition and
// leaves the agent running, which is what makes re-running an installer safe.
//
// Two steps are load-bearing and they arrived one audit round apart.
//
// The stop was missing. removeOtherMechanism stops the registration it removes;
// this path — the same command, replacing its own definition rather than the
// other mechanism's — went straight to Uninstall. On Windows DeleteService only
// *marks* a running service for deletion, so the entry stays in the SCM
// database, the CreateService that follows fails with "service fleet-agent
// already exists", and the host is left with a definition marked for deletion
// and no replacement: an agent that disappears at the next reboot, from the
// command this one documents as safe to re-run. launchd stops the job inside
// its own Uninstall and systemd disables a unit whose process keeps running, so
// the two managers CI can reason about both hid it.
//
// And then the resume has to be a Start. Adding the stop is what made this
// definition a freshly written one that has never run, and that is the state
// kardianos's Windows Restart cannot leave: it is ControlService(STOP) followed
// by StartService and it returns at the first failure, so the stop fails with
// ERROR_SERVICE_NOT_ACTIVE and StartService is never reached. launchd's
// unload-then-load has the same shape. The command reported "could not be
// started", exited zero, and left the agent down — the exact failure round 4
// fixed for the mechanism switch, walked back in through the fix for the one
// above. It is decided on whether anything is running under the definition now,
// not on what the host carried when the command began, which is also right for
// systemd: it keeps the old process alive across a unit replacement and answers
// active, so Linux still restarts.
func TestServiceInstall_ReplacesItsOwnDefinitionAndKeepsItRunning(t *testing.T) {
	args := installArgs(t)
	mechanism := fleetagent.MechanismService
	calls, _, restore := fleetagent.PinInstallForTest(fleetagent.InstallHostForTest{
		Installed: []fleetagent.Mechanism{mechanism},
		Running:   map[fleetagent.Mechanism]bool{mechanism: true},
	})
	defer restore()

	out := &bytes.Buffer{}
	code := fleetagent.Main(args, out)
	text := out.String()
	require.Equal(t, 0, code, "%s", text)

	assert.Equal(t, []string{"new:stop", "new:uninstall", "new:install", "new:start"}, calls(),
		"kardianos refuses to install over an existing definition, so a re-run has to replace it — "+
			"the SCM will not let the replacement be written while the old one is still running, and "+
			"what that leaves cannot be restarted, only started")
	assert.Contains(t, text, "existing service definition removed for replacement")
	assert.Contains(t, text, "reinstalled")
	assert.Contains(t, text, "service restarted with the new definition")
	assert.NotContains(t, text, "could not be started",
		"the agent was running before this command and has to be running after it")
}

// And the shape that says the choice is not "always Start": a daemon the
// replacement did not manage to stop is restarted onto the new definition.
//
// install says so and carries on when a stop fails, because a stop that failed
// is not a reason to leave the host on the old definition. What that produces
// is a new definition with the old daemon still running under it, and there
// Start is the wrong call: `systemctl start` on a unit systemd already
// considers active does nothing at all, and the operator is left running the
// definition this command was replacing, silently. Restart is what replaces it.
func TestServiceInstall_RestartsAReplacementItCouldNotStop(t *testing.T) {
	args := installArgs(t)
	mechanism := fleetagent.MechanismService
	calls, _, restore := fleetagent.PinInstallForTest(fleetagent.InstallHostForTest{
		Installed: []fleetagent.Mechanism{mechanism},
		Running:   map[fleetagent.Mechanism]bool{mechanism: true},
		StopFails: true,
	})
	defer restore()

	out := &bytes.Buffer{}
	require.Equal(t, 0, fleetagent.Main(args, out), "%s", out.String())
	assert.Equal(t, []string{"new:stop", "new:uninstall", "new:install", "new:restart"}, calls(),
		"a daemon still running under the new definition is restarted onto it, not started beside itself")
	assert.Contains(t, out.String(), "could not stop the running")
}

// And a registration that is not running is not stopped: there is nothing to
// stop, and a failed stop would print a note about a state nobody is in.
func TestServiceInstall_ReplacesAStoppedDefinitionWithoutStoppingIt(t *testing.T) {
	args := installArgs(t)
	mechanism := fleetagent.MechanismService
	calls, _, restore := fleetagent.PinInstallForTest(fleetagent.InstallHostForTest{
		Installed: []fleetagent.Mechanism{mechanism},
	})
	defer restore()

	out := &bytes.Buffer{}
	require.Equal(t, 0, fleetagent.Main(args, out), "%s", out.String())
	assert.Equal(t, []string{"new:uninstall", "new:install"}, calls())
}

// A host with nothing registered gets exactly one write and no lifecycle calls
// at all: install registers, and `service start` is a separate command an
// operator runs next. docs/service.md prints them in that order.
func TestServiceInstall_AFreshHostIsRegisteredAndNotStarted(t *testing.T) {
	args := installArgs(t)
	calls, _, restore := fleetagent.PinInstallForTest(fleetagent.InstallHostForTest{})
	defer restore()

	out := &bytes.Buffer{}
	code := fleetagent.Main(args, out)
	text := out.String()
	require.Equal(t, 0, code, "%s", text)

	assert.Equal(t, []string{"new:install"}, calls())
	assert.Contains(t, text, "service "+fleetagent.ServiceName+" installed")
	assert.NotContains(t, text, "reinstalled")
}

// When the write fails after the other registration has already been removed,
// the host has no agent registered on it at all — and the error has to say so.
//
// "install service: ..." on its own reads as "nothing happened", which is the
// one thing that is not true: the daemon was stopped, its registration was
// removed, and the replacement did not land. The same-mechanism replacement
// carried this warning already; the mechanism switch did not, and the switch is
// the flow this whole change exists to produce.
func TestServiceInstall_SaysTheHostIsUnregisteredWhenTheWriteFails(t *testing.T) {
	args := installArgs(t)
	calls, _, restore := fleetagent.PinInstallForTest(fleetagent.InstallHostForTest{
		Installed:   []fleetagent.Mechanism{fleetagent.MechanismTask},
		Running:     map[fleetagent.Mechanism]bool{fleetagent.MechanismTask: true},
		FailInstall: true,
	})
	defer restore()

	out := &bytes.Buffer{}
	err := runAgentCommand(t, out, args...)

	require.Error(t, err, "%s", out.String())
	assert.Equal(t, []string{"task:stop", "task:uninstall", "new:install"}, calls())
	assert.Contains(t, err.Error(), "is now not installed",
		"the previous registration is gone and the new one did not land; an operator reading this as `nothing happened` leaves the host with no agent")
	assert.Contains(t, err.Error(), "Re-run `service install`")
}

// A removal that fails after the daemon has been stopped says the agent is down.
//
// Round 4 established this for the failed *write*: "install service: ..." on its
// own reads as "nothing happened", which is the one thing that is not true. The
// stop round 5 added moves the same event one step earlier — install now stops
// the daemon before it removes anything, because on Windows DeleteService only
// marks a *running* service for deletion — so a removal that refuses leaves an
// agent that is down because of this command, and said so nowhere.
func TestServiceInstall_SaysTheAgentIsDownWhenTheRemovalFails(t *testing.T) {
	args := installArgs(t)
	mechanism := fleetagent.MechanismService
	calls, _, restore := fleetagent.PinInstallForTest(fleetagent.InstallHostForTest{
		Installed:     []fleetagent.Mechanism{mechanism},
		Running:       map[fleetagent.Mechanism]bool{mechanism: true},
		FailUninstall: true,
	})
	defer restore()

	out := &bytes.Buffer{}
	err := runAgentCommand(t, out, args...)

	require.Error(t, err, "%s", out.String())
	assert.Equal(t, []string{"new:stop", "new:uninstall"}, calls(),
		"nothing may be registered over a definition the manager would not remove")
	assert.Contains(t, err.Error(), "is not running now",
		"the daemon was stopped by this command and an operator reading this as `nothing happened` leaves the agent down")
	assert.Contains(t, err.Error(), "service start")
}

// And the same from the removal of the *other* mechanism, which is the flow
// `status` prints as the remedy for a confined agent.
func TestServiceInstall_SaysTheAgentIsDownWhenTheOtherRemovalFails(t *testing.T) {
	args := installArgs(t)
	calls, _, restore := fleetagent.PinInstallForTest(fleetagent.InstallHostForTest{
		Installed:     []fleetagent.Mechanism{fleetagent.MechanismTask},
		Running:       map[fleetagent.Mechanism]bool{fleetagent.MechanismTask: true},
		FailUninstall: true,
	})
	defer restore()

	out := &bytes.Buffer{}
	err := runAgentCommand(t, out, args...)

	require.Error(t, err, "%s", out.String())
	assert.Equal(t, []string{"task:stop", "task:uninstall"}, calls())
	assert.Contains(t, err.Error(), "is not running now")
}

// A removal that fails without anything having been stopped says nothing extra:
// the host is where it was, and a note about a stopped agent would be false.
func TestServiceInstall_SaysNothingAboutAStoppedAgentThatWasNotRunning(t *testing.T) {
	args := installArgs(t)
	mechanism := fleetagent.MechanismService
	_, _, restore := fleetagent.PinInstallForTest(fleetagent.InstallHostForTest{
		Installed:     []fleetagent.Mechanism{mechanism},
		FailUninstall: true,
	})
	defer restore()

	out := &bytes.Buffer{}
	err := runAgentCommand(t, out, args...)
	require.Error(t, err, "%s", out.String())
	assert.NotContains(t, err.Error(), "is not running now")
}

// A definition that cannot even be assembled is discovered before anything is
// removed.
//
// newRegistration writes nothing to the host, so building it first costs
// nothing and is the difference between a failure that changes a machine and
// one that does not. Built after the removal — which is where it was — a
// service manager this library cannot address left the host with its old
// registration gone, its daemon stopped, and an error that mentions neither.
func TestServiceInstall_ADefinitionItCannotBuildRemovesNothing(t *testing.T) {
	args := installArgs(t)
	calls, _, restore := fleetagent.PinInstallForTest(fleetagent.InstallHostForTest{
		Installed: []fleetagent.Mechanism{fleetagent.MechanismTask},
		Running:   map[fleetagent.Mechanism]bool{fleetagent.MechanismTask: true},
		FailBuild: true,
	})
	defer restore()

	out := &bytes.Buffer{}
	err := runAgentCommand(t, out, args...)

	require.Error(t, err, "%s", out.String())
	assert.Empty(t, calls(),
		"the registration being replaced is still there: nothing may be removed for a definition that was never assembled")
}

// install says a pre-rebrand service is still registered *before* it changes
// anything, so an operator who did not read the migration steps can stop there
// having changed nothing.
//
// A host with both registered runs two daemons against one state directory,
// each re-adopting the same supervised processes. The message itself is
// asserted in service_test.go; that install prints it, and prints it first, was
// asserted by nothing.
func TestServiceInstall_WarnsAboutAPreRebrandServiceBeforeItActs(t *testing.T) {
	args := installArgs(t)
	calls, _, restore := fleetagent.PinInstallForTest(fleetagent.InstallHostForTest{Legacy: true})
	defer restore()

	out := &bytes.Buffer{}
	code := fleetagent.Main(args, out)
	text := out.String()
	require.Equal(t, 0, code, "%s", text)
	require.Equal(t, []string{"new:install"}, calls())

	warning := strings.Index(text, fleetagent.LegacyServiceNameForTest)
	registered := strings.Index(text, "service "+fleetagent.ServiceName+" installed")
	require.GreaterOrEqual(t, warning, 0, "install has to say the host still carries a pre-rebrand service: %s", text)
	require.Greater(t, registered, warning,
		"and say it before it registers anything, or the operator reads it after the machine has already changed")
}

// The directories install creates are not world-anything.
//
// They hold the daemon's runtime report, its supervised process records and its
// logs, on a host where `install` is the elevated command that made them. 0750
// and an owner is the whole access control; a mode that let every account on
// the machine in changed no test anywhere.
func TestServiceInstall_CreatesItsDirectoriesClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Go synthesises a mode on Windows from the read-only attribute; the equivalent guarantee there is the icacls grant acl_test.go asserts")
	}
	configPath, stateDir, logDir := installConfig(t, "")
	args := append([]string{"service", "install", "--config", configPath}, installAccount(t)...)

	_, _, restore := fleetagent.PinInstallForTest(fleetagent.InstallHostForTest{})
	defer restore()

	out := &bytes.Buffer{}
	require.Equal(t, 0, fleetagent.Main(args, out), "%s", out.String())

	for _, dir := range []string{stateDir, logDir} {
		info, err := os.Stat(dir)
		require.NoError(t, err, "install has to create %s before the daemon needs it", dir)
		assert.Zero(t, info.Mode().Perm()&0o007,
			"%s is readable by every account on this host; it holds the agent's state and logs", dir)
	}
}

// install refuses when it cannot hand the enrollment material to the account
// the daemon will run as, and names the file.
//
// `enroll` writes agent.yaml and the private key 0600, owned by whoever ran it,
// and `install` is the step that decides somebody else will read them. Without
// this the advertised one-line install registers cleanly and then fails every
// start on "permission denied" opening its own certificate — with nothing
// anywhere saying that is what happened.
//
// Driven by naming a certificate that is not there, which is the one failure
// the handover has on every Unix without a second account. Not on Windows: the
// account these scenarios use is a built-in identity, which install grants
// nothing at all, and the icacls argv it would use otherwise is asserted in
// acl_test.go. The call site being asserted here is shared, untagged code.
//
// Run against a host that already carries a registration, which is what makes
// "nothing was registered" mean anything. Against an empty host — which is how
// this scenario started out — the assertion is satisfied by there having been
// nothing to remove, and moving the handover below removeOtherMechanism left
// the whole suite green while turning "install refuses and changes nothing"
// into "install takes the host's only registration off it and then refuses".
// That ordering is the same property TestServiceInstall_ADefinitionItCannotBuild-
// RemovesNothing pins for the definition, for the step that actually fails in
// the field.
func TestServiceInstall_RefusesWhenTheEnrollmentMaterialCannotChangeHands(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("install grants a built-in service identity nothing; the icacls argv is asserted in acl_test.go")
	}
	if os.Geteuid() == 0 {
		t.Skip("the superuser already reads everything, so the handover is a no-op and has nothing to refuse")
	}
	missing := filepath.Join(t.TempDir(), "missing.pem")
	configPath, _, _ := installConfig(t, "tls:\n  certificate: "+filepath.ToSlash(missing)+"\n")
	args := append([]string{"service", "install", "--config", configPath}, installAccount(t)...)

	calls, _, restore := fleetagent.PinInstallForTest(fleetagent.InstallHostForTest{
		Installed: []fleetagent.Mechanism{fleetagent.MechanismTask},
		Running:   map[fleetagent.Mechanism]bool{fleetagent.MechanismTask: true},
	})
	defer restore()

	out := &bytes.Buffer{}
	err := runAgentCommand(t, out, args...)

	require.Error(t, err, "%s", out.String())
	assert.Contains(t, err.Error(), missing, "the file the daemon will not be able to read has to be named")
	assert.Contains(t, err.Error(), "will not start without it")
	assert.Empty(t, calls(),
		"nothing may be registered — or unregistered — once the material the daemon reads cannot reach it: "+
			"this host had a running agent on it, and a refusal that has already removed it is not a refusal")
}

// The password the operator supplies is the one handed to the service manager,
// and install stops to ask for it.
//
// Only the Windows SCM logs an account on, so only a Windows host reaches the
// prompt at all; the rule is asserted for every platform in mechanism_test.go
// and the dry run's promise that it will ask in confine_test.go. This is the
// other half — that the command consults the rule, reads the password, and
// hands that value and no other to the definition it writes.
func TestServiceInstall_HandsTheSuppliedPasswordToTheServiceManager(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("only the Windows SCM asks for an account's password")
	}
	current, err := user.Current()
	require.NoError(t, err)
	// The two host steps install takes before it asks: it looks the account up,
	// and it grants that account access to the directories and the enrollment
	// material with icacls. Both are the host's answers, not this change's, and
	// a runner that cannot give them has nothing to say about the password.
	if _, err := user.Lookup(current.Username); err != nil {
		t.Skipf("this host cannot look up its own account %q: %v", current.Username, err)
	}
	probe := t.TempDir()
	if err := exec.Command("icacls.exe", probe, "/grant", current.Username+":(OI)(CI)M", "/T").Run(); err != nil { //nolint:gosec // the same argv install is about to use, against a directory this test owns
		t.Skipf("icacls cannot grant %s access to a directory on this host: %v", current.Username, err)
	}
	configPath, _, _ := installConfig(t, "")

	_, password, restore := fleetagent.PinInstallForTest(fleetagent.InstallHostForTest{})
	defer restore()

	out := &bytes.Buffer{}
	root := fleetagent.NewRootCommand(out)
	root.SetArgs([]string{
		"service", "install", "--config", configPath,
		"--mechanism", "service", "--user", current.Username, "--password-stdin",
	})
	root.SetIn(strings.NewReader("correct horse battery staple\n"))
	require.NoError(t, root.Execute(), "%s", out.String())

	assert.Equal(t, "correct horse battery staple", password(),
		"the SCM is the only thing that ever sees it, and it has to see the one that was typed")
	assert.NotContains(t, out.String(), "correct horse battery staple",
		"and it must not be echoed anywhere")
}

// What a dry run says about an account the host does not have.
//
// Which account the daemon runs as is one of the three things a dry run exists
// to answer, and whether the host has that account is decided in
// ensureServiceUser — one of the two steps a dry run deliberately does not
// reach. So `--dry-run --user build` printed a clean plan naming an account
// that does not exist and the install it was previewing refused.
func TestDryRunAccountNotes(t *testing.T) {
	assert.Empty(t, fleetagent.DryRunAccountNotesForTest("axel", "darwin", false, true),
		"an account the host has is nothing to say")
	assert.Empty(t, fleetagent.DryRunAccountNotesForTest(`NT AUTHORITY\NetworkService`, "windows", false, false),
		"a built-in service identity has no account database entry and needs none")

	created := strings.Join(fleetagent.DryRunAccountNotesForTest("fleet", "linux", true, false), "\n")
	assert.Contains(t, created, "would create the system account fleet",
		"Linux creates it, so a missing account is not a warning there")
	assert.NotContains(t, created, "WARNING")

	for _, tc := range []struct{ goos string }{{"darwin"}, {"windows"}} {
		note := strings.Join(fleetagent.DryRunAccountNotesForTest("build", tc.goos, true, false), "\n")
		assert.Contains(t, note, "WARNING", "goos %s", tc.goos)
		assert.Contains(t, note, "build does not exist", "goos %s", tc.goos)
		assert.Contains(t, note, "will refuse", "goos %s: install refuses this, and a dry run that does not say so is a plan that cannot be carried out", tc.goos)
	}

	refused := strings.Join(fleetagent.DryRunAccountNotesForTest("fleet", "linux", false, false), "\n")
	assert.Contains(t, refused, "--create-user=false",
		"the account is not created, so the dry run must not promise it will be")
}

// And the command prints it, which is the half a rule beside a command never
// proves.
func TestServiceInstall_DryRunSaysWhenTheAccountDoesNotExist(t *testing.T) {
	configPath, _, _ := installConfig(t, "")

	out := &bytes.Buffer{}
	code := fleetagent.Main([]string{
		"service", "install", "--dry-run", "--config", configPath,
		"--user", "fleet-agent-no-such-account",
	}, out)
	text := out.String()

	require.Equal(t, 0, code, "a dry run still changes nothing: %s", text)
	// The plan, first. On Windows this account is not the only thing wrong with
	// the command — the test binary is inside somebody's profile, which is the
	// refusal `install` exists to make — and until the fix that refusal came
	// back instead of everything below it.
	assert.Contains(t, text, "mechanism:")
	assert.Contains(t, text, "runs as:")
	assert.Contains(t, text, "fleet-agent-no-such-account")
	if runtime.GOOS == "linux" {
		assert.Contains(t, text, "would create the system account")
		return
	}
	assert.Contains(t, text, "fleet-agent-no-such-account does not exist on this host")
}

// The rule the dry run turns on: what `install` says about a binary the service
// account cannot read, and whether saying it ends the command.
//
// Windows refuses and Unix warns — that half is executableAccessIsFatal's and
// is asserted in acl_test.go. The half that was missing is that a dry run is
// not an install: it registers nothing, so there is nothing for it to refuse.
func TestExecutableAccessOutcome(t *testing.T) {
	headline, refuse := fleetagent.ExecutableAccessOutcomeForTest("windows", false)
	assert.True(t, refuse, "a real install on Windows refuses: the account provably cannot read the path")
	assert.Contains(t, headline, "refusing to install")

	headline, refuse = fleetagent.ExecutableAccessOutcomeForTest("windows", true)
	assert.False(t, refuse,
		"a dry run registers nothing, so a refusal here withholds the plan instead of preventing anything")
	assert.Contains(t, headline, "would refuse")
	assert.Contains(t, headline, "register nothing")

	for _, goos := range []string{"linux", "darwin"} {
		for _, dry := range []bool{false, true} {
			headline, refuse = fleetagent.ExecutableAccessOutcomeForTest(goos, dry)
			assert.False(t, refuse, "%s dry=%v: a supplementary group can grant what the mode bits appear to deny", goos, dry)
			assert.Equal(t, "WARNING:", headline, "%s dry=%v", goos, dry)
		}
	}
}

// And the command reports it, on the platform where it refuses.
//
// `install --dry-run` is sold as the way to see which mechanism a host will
// get, under which account, and whether the binary is somewhere that account
// can read — before running the command that acts on it. The executable check
// sat above the dry-run branch and is fatal on Windows, so the one platform
// that refuses answered only the third of those, by failing: the operator got
// the refusal and no mechanism, no account, no state directory. The Unix half
// of the identical condition warned, printed the plan and exited zero, and had
// been driven from the command since round 1; only the fatal half was reachable
// by nobody, and it disagreed.
func TestServiceInstall_DryRunReportsABinaryTheAccountCannotRead(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Unix warns rather than refusing; that half is driven from the command in confine_test.go")
	}
	exe, err := os.Executable()
	require.NoError(t, err)
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	// A profile root one level above the directory this binary is in, so the
	// binary is inside "somebody's profile" as far as the rule is concerned.
	t.Setenv("USERPROFILE", filepath.Join(filepath.Dir(filepath.Dir(exe)), "someone-else"))

	configPath, stateDir, _ := installConfig(t, "")
	_, _, restore := fleetagent.PinInstallForTest(fleetagent.InstallHostForTest{})
	defer restore()

	out := &bytes.Buffer{}
	code := fleetagent.Main([]string{
		"service", "install", "--dry-run", "--config", configPath,
		"--user", `NT AUTHORITY\NetworkService`,
	}, out)
	text := out.String()

	require.Equal(t, 0, code, "a dry run registers nothing, so it has nothing to refuse: %s", text)
	assert.Contains(t, text, "would refuse", "and it still has to say install will not do this")
	assert.Contains(t, text, "error 5, access denied", "the string an operator will search for")
	assert.Contains(t, text, "mechanism:",
		"the plan is what a dry run is for, and it is what the refusal was returned instead of")
	assert.Contains(t, text, `NT AUTHORITY\NetworkService`)
	assert.Equal(t, filepath.Clean(stateDir), plannedPath(t, text, "state"),
		"including the directories install would create")
}

// plannedPath is the path a `key:` line of the dry run's plan names, read back
// as a path rather than as a string.
//
// Same reason as keptStateDir, and the same trap: state_dir is echoed from the
// config exactly as it was written, agent.Load only joins a *relative* path,
// and these helpers write it with filepath.ToSlash — so on Windows the plan
// says `C:/.../state` two lines under a `config:` that says `C:\...\agent.yaml`.
// Same directory, different spelling, and a string comparison between them
// fails on the one runner that can tell.
func plannedPath(t *testing.T, text, key string) string {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), key+":"); ok {
			return filepath.Clean(strings.TrimSpace(rest))
		}
	}
	t.Fatalf("no %s line in the plan:\n%s", key, text)
	return ""
}

// The config directory install leaves alone, and the command that makes it
// traversable — on every platform, not only the one that grants by ownership.
//
// `enroll --dir` and `--config` both put the enrollment material somewhere
// fleet did not create. install hands the files inside it over individually and
// deliberately does not touch the directory, so the daemon still needs traverse
// on it: without that it starts and fails on its own config, and nothing names
// the directory as the reason. The note was gated on a per-platform constant
// that switched it off on Windows, where the remedy is an icacls grant rather
// than a chown — so the platform whose whole access story is ACLs was the one
// told nothing.
func TestForeignConfigDirNote(t *testing.T) {
	for _, tc := range []struct{ goos, fix string }{
		{"linux", "chown fleet /srv/enroll"},
		{"darwin", "chown fleet /srv/enroll"},
		{"windows", `icacls "/srv/enroll" /grant "fleet:(RX)"`},
	} {
		note := strings.Join(fleetagent.ForeignConfigDirNoteForTest("/srv/enroll", "fleet", tc.goos), "\n")
		assert.Contains(t, note, "/srv/enroll", "goos %s", tc.goos)
		assert.Contains(t, note, "traverse it", "goos %s", tc.goos)
		assert.Contains(t, note, tc.fix,
			"goos %s: a note without the command that fixes it leaves the operator where they were", tc.goos)
	}
}

// The Windows half of it, driven with the shapes Windows actually produces.
//
// Both arguments of that `icacls` line have backslashes in them on a real host
// — `%ProgramData%\...` and `COMPUTERNAME\build`, which is the spelling this
// document tells an operator to pass — and the note was composed with %q, which
// is Go string syntax and doubles every one of them. A doubled *path* survives,
// because Win32 collapses repeated separators; a doubled *account* does not,
// because an account name is not a path: icacls answers "No mapping between
// account names and security IDs was done", and the operator whose daemon
// cannot read its own config is handed a remedy that does not work.
//
// The rule was only ever driven with a Unix path and a bare account name, which
// is the one pair of inputs on which %q and a plain quote agree.
func TestForeignConfigDirNote_QuotesTheWindowsShapesUnchanged(t *testing.T) {
	note := strings.Join(fleetagent.ForeignConfigDirNoteForTest(
		`D:\fleet\enroll`, `WORKSTATION\build`, "windows"), "\n")

	assert.Contains(t, note, `icacls "D:\fleet\enroll" /grant "WORKSTATION\build:(RX)"`,
		"the command an operator pastes has to name the directory and the account they gave, byte for byte")
	assert.NotContains(t, note, `\\`,
		"a doubled backslash is Go string syntax leaking into a Windows command line")
}

// And `install` prints it, for the config it was actually given.
func TestServiceInstall_SaysTheConfigDirectoryItLeftAlone(t *testing.T) {
	args := installArgs(t)
	_, _, restore := fleetagent.PinInstallForTest(fleetagent.InstallHostForTest{})
	defer restore()

	out := &bytes.Buffer{}
	require.Equal(t, 0, fleetagent.Main(args, out), "%s", out.String())

	configDir := filepath.Dir(os.Getenv("FLEET_AGENT_CONFIG"))
	text := out.String()
	assert.Contains(t, text, configDir+" is not a directory fleet created")
	assert.Contains(t, text, "traverse it")
	if runtime.GOOS == "windows" {
		assert.Contains(t, text, "icacls")
		return
	}
	assert.Contains(t, text, "chown ")
}

// The refusal, driven from the command, on the platform where it refuses.
//
// `install` registers os.Executable() and never copies it, so a manual download
// on the Desktop registered under a built-in identity produced a service that
// installed cleanly and then failed every start with error 5, access denied,
// before a line of agent code ran. mechanism_test.go asserts the rule for both
// platforms and confine_test.go drives the *warning* half from the command on
// Unix; the half that stops an install had never been reached from any command.
//
// %USERPROFILE% names the directory holding every account's profile and is read
// rather than assumed precisely because it is relocatable, which is what lets
// this ask the question about the directory the test binary is really in.
func TestServiceInstall_RefusesABinaryTheServiceAccountCannotRead(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Unix warns rather than refusing; that half is driven from the command in confine_test.go")
	}
	exe, err := os.Executable()
	require.NoError(t, err)
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	// A profile root one level above the directory this binary is in, so the
	// binary is inside "somebody's profile" as far as the rule is concerned.
	t.Setenv("USERPROFILE", filepath.Join(filepath.Dir(filepath.Dir(exe)), "someone-else"))

	configPath, _, _ := installConfig(t, "")
	calls, _, restore := fleetagent.PinInstallForTest(fleetagent.InstallHostForTest{})
	defer restore()

	out := &bytes.Buffer{}
	err = runAgentCommand(t, out, "service", "install", "--config", configPath,
		"--user", `NT AUTHORITY\NetworkService`)

	require.Error(t, err, "%s", out.String())
	assert.Contains(t, err.Error(), "refusing to install a service that cannot start")
	assert.Contains(t, err.Error(), "error 5, access denied", "the string an operator will search for")
	assert.Empty(t, calls(),
		"nothing may be registered: the service manager accepts this definition and then fails every start")
}
