package fleetagent_test

import (
	"bytes"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/cli/fleetagent"
)

// The two things #74 says an implementation has to prove are asserted here.
//
//  1. A spawned process really has the operator's environment: a binary
//     installed only under the home directory is found by name off the PATH a
//     spawned command gets, and runs. Not "PATH is non-empty" — a session-0
//     service has a PATH.
//  2. `service status` reports *unusable* rather than *running* when the agent
//     is up and confined, driven from the command an operator types.

// perUserBinDir is a directory from the probe's own list, so the test cannot
// pass against a list that no longer contains anything real.
func perUserBinDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(".cargo", "bin")
	}
	return filepath.Join(".local", "bin")
}

// plantedToolchainName is the program the probe is told to look for. It is not
// a real toolchain on purpose: a test that resolved `cargo` would pass on a
// runner that happens to have one installed somewhere else entirely.
const plantedToolchainName = "fleetprobe"

// plantUserToolchain writes a genuinely runnable program into dir, and returns
// its path plus the arguments that make it create marker and exit zero.
//
// It has to be a real executable, and the marker has to be the assertion. The
// claim #74 asks for is that a binary installed only under a home directory is
// found *and runs*; a test that only compared the path the probe reported
// passed with the execution step deleted, which is this repository's most
// common defect shape and was sitting in this file until the mutation run found
// it.
func plantUserToolchain(t *testing.T, dir, marker string) (path string, versionArgs []string) {
	t.Helper()
	name := plantedToolchainName
	require.NoError(t, os.MkdirAll(dir, 0o755))

	if runtime.GOOS == "windows" {
		// CreateProcess will not run a .bat or a .cmd, so the planted program
		// has to be a real PE. cmd.exe is the smallest one guaranteed present
		// on every Windows host, and `copy nul <path>` is the shortest thing it
		// does that leaves evidence.
		src := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
		path = filepath.Join(dir, name+".exe")
		copyFileForTest(t, src, path)
		return path, []string{"/c", "copy", "nul", marker}
	}
	path = filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\nexec touch \"$1\"\n"), 0o755))
	return path, []string{marker}
}

// plantToolchainNamed is plantUserToolchain with the filename chosen, for the
// rules that turn on the extension rather than on the name.
func plantToolchainNamed(t *testing.T, dir, filename, marker string) (path string, versionArgs []string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o755))
	path = filepath.Join(dir, filename)
	if runtime.GOOS == "windows" {
		// CreateProcess reads the file, not the extension, so a copy of
		// cmd.exe under any name is a program. Which is the point: what
		// PATHEXT decides is whether the *name* resolves.
		copyFileForTest(t, filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), path)
		return path, []string{"/c", "copy", "nul", marker}
	}
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\nexec touch \"$1\"\n"), 0o755))
	return path, []string{marker}
}

// plantBrokenToolchain writes a file that resolves like a program and cannot be
// executed: the exact difference between a name being found and a command
// running.
func plantBrokenToolchain(t *testing.T, dir string) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o755))
	name := plantedToolchainName
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte("this is not a program\n"), 0o755))
	return path
}

func copyFileForTest(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src) //nolint:gosec // a fixed system path
	require.NoError(t, err)
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755) //nolint:gosec // a path under t.TempDir
	require.NoError(t, err)
	_, err = io.Copy(out, in)
	require.NoError(t, err)
	require.NoError(t, out.Close())
}

// Proof 1. A program that exists only under the home directory is resolved by
// name off the PATH a spawned command gets, and executed.
func TestProfileProbe_APerUserToolchainIsFoundAndRuns(t *testing.T) {
	home := t.TempDir()
	binDir := filepath.Join(home, perUserBinDir())
	marker := filepath.Join(t.TempDir(), "it-ran")
	planted, versionArgs := plantUserToolchain(t, binDir, marker)

	tools := []fleetagent.UserToolchainForTest{{Name: plantedToolchainName, Version: versionArgs}}
	visibility, ran, unreachable := fleetagent.ProfileProbeForTest(home, binDir, runtime.GOOS, tools)

	assert.Equal(t, fleetagent.ProfileVisibleForTest, visibility)
	assert.Equal(t, planted, ran,
		"the probe has to report the copy under the home directory, resolved by name")
	assert.Empty(t, unreachable)

	// And the half a path comparison cannot see. The marker exists only if the
	// program the probe resolved was actually executed.
	assert.FileExists(t, marker,
		"the per-user program has to be run, not merely resolved: that is the whole difference between a PATH lookup and a working agent")
}

// A file that resolves like a program and cannot be executed is the shape a
// PATH lookup cannot tell from a working toolchain: an ACL that denies execute,
// a shim left behind by an uninstall, a partial download.
func TestProfileProbe_DoesNotClaimAProgramThatWillNotRun(t *testing.T) {
	home := t.TempDir()
	binDir := filepath.Join(home, perUserBinDir())
	plantBrokenToolchain(t, binDir)

	tools := []fleetagent.UserToolchainForTest{{Name: plantedToolchainName, Version: nil}}
	visibility, ran, _ := fleetagent.ProfileProbeForTest(home, binDir, runtime.GOOS, tools)

	assert.Equal(t, fleetagent.ProfileVisibleForTest, visibility,
		"the per-user directory is on PATH, which is what visible means")
	assert.Empty(t, ran, "nothing ran, so nothing may be reported as having run")
}

// The failure this whole change is about, in the one shape a Linux or macOS
// runner can reproduce: the per-user toolchain is installed, PATH is populated,
// and PATH does not reach it.
func TestProfileProbe_ReportsAToolchainThePathCannotReach(t *testing.T) {
	home := t.TempDir()
	binDir := filepath.Join(home, perUserBinDir())
	_, versionArgs := plantUserToolchain(t, binDir, filepath.Join(t.TempDir(), "it-ran"))

	// A machine PATH: perfectly well populated, and per-user directories are
	// exactly what is not on it.
	machineDir := t.TempDir()
	tools := []fleetagent.UserToolchainForTest{{Name: plantedToolchainName, Version: versionArgs}}
	visibility, ran, unreachable := fleetagent.ProfileProbeForTest(home, machineDir, runtime.GOOS, tools)

	assert.Equal(t, fleetagent.ProfileHiddenForTest, visibility)
	assert.Empty(t, ran)
	assert.Contains(t, unreachable, binDir, "the report has to name what an operator can act on")
}

// A host with nothing installed per-user proves nothing either way, and saying
// so beats inventing an answer: a "hidden" here would report every freshly
// imaged machine as broken.
func TestProfileProbe_SaysUnknownWhenThereIsNothingToLookFor(t *testing.T) {
	home := t.TempDir()
	visibility, ran, unreachable := fleetagent.ProfileProbeForTest(home, home, runtime.GOOS, nil)
	assert.Equal(t, fleetagent.ProfileUnknownForTest, visibility)
	assert.Empty(t, ran)
	assert.Empty(t, unreachable)
}

// The claim is about the copy under the home directory. A name that resolves to
// a machine-wide install of the same tool proves the opposite, and must not be
// reported as the per-user one having run.
func TestProfileProbe_DoesNotCountAMachineWideCopy(t *testing.T) {
	home := t.TempDir()
	binDir := filepath.Join(home, perUserBinDir())
	marker := filepath.Join(t.TempDir(), "it-ran")
	_, versionArgs := plantUserToolchain(t, binDir, marker)

	machineDir := t.TempDir()
	shadow, _ := plantUserToolchain(t, machineDir, marker)

	// The machine directory first, as a machine PATH puts it.
	pathEnv := strings.Join([]string{machineDir, binDir}, string(os.PathListSeparator))
	tools := []fleetagent.UserToolchainForTest{{Name: plantedToolchainName, Version: versionArgs}}
	visibility, ran, _ := fleetagent.ProfileProbeForTest(home, pathEnv, runtime.GOOS, tools)

	assert.Equal(t, fleetagent.ProfileVisibleForTest, visibility,
		"the per-user directory is on PATH, which is what visible means")
	assert.NotEqual(t, shadow, ran)
	assert.Empty(t, ran, "nothing under the home directory was reached by name, so nothing is claimed")
	assert.NoFileExists(t, marker, "and the machine-wide copy must not have been run either")
}

// The daemon's own self-check, run against this process. It is what `serve`
// records at every start, and it has to produce an answer rather than an error
// on whatever runner it lands on.
func TestCollectRuntimeReport_DescribesThisProcess(t *testing.T) {
	account, home, visibility, _, sessionZero := fleetagent.CollectRuntimeReportForTest()
	assert.NotEmpty(t, account, "the report has to name the account the daemon is running as")
	assert.NotEmpty(t, home, "and the home directory it was started with")
	assert.Contains(t, []string{
		fleetagent.ProfileVisibleForTest,
		fleetagent.ProfileHiddenForTest,
		fleetagent.ProfileUnknownForTest,
	}, visibility)
	if runtime.GOOS != "windows" {
		assert.False(t, sessionZero, "only Windows has a session 0")
	}
}

// Which environment variable the daemon takes its home directory from.
//
// Windows sets USERPROFILE and never HOME, and Home is the input to everything
// this change concludes: the probe looks under it, and the verdict for a named
// account started without its profile is decided on it and nothing else. Read
// off the real environment, the fallback is a line only a Windows runner can
// tell is there — so it is driven with the environment supplied, and checked
// from all three.
func TestReportHome_WindowsNamesItUserProfile(t *testing.T) {
	assert.Equal(t, `C:\Users\axel`,
		fleetagent.ReportHomeForTest([]string{`USERPROFILE=C:\Users\axel`, `PATH=C:\Windows`}),
		"the base environment on Windows carries USERPROFILE and no HOME; without this the probe has nothing to look under on the one platform #74 is about")

	assert.Equal(t, "/home/axel",
		fleetagent.ReportHomeForTest([]string{"HOME=/home/axel", "PATH=/usr/bin"}))

	// HOME wins where both are set, so a Unix daemon is never reported on
	// against a variable Unix does not use.
	assert.Equal(t, "/home/axel",
		fleetagent.ReportHomeForTest([]string{"HOME=/home/axel", `USERPROFILE=C:\Users\axel`}))

	assert.Empty(t, fleetagent.ReportHomeForTest([]string{"PATH=/usr/bin"}),
		"a host with no discoverable home directory is reported as having none, not as having a synthesised one")
}

// The judgement `service status` draws from a report, asserted from every
// runner because the facts behind it can only be collected on one.
func TestConfinementFor(t *testing.T) {
	// The reported case: a service under a built-in identity.
	//
	// Asserted on what only this branch says, not on what any verdict says.
	// The realistic home for this account is a service profile, which also
	// matches the third case below — and every assertion here used to be one
	// that case satisfies too, so deleting the branch this whole issue is
	// about left the suite green. Four verdicts share a summary, share the
	// phrase "session 0", each interpolate the account, and three of them name
	// `--mechanism task`; the account being a built-in identity is the only
	// thing this one concludes from, and the two-line remedy is the only thing
	// only it prints.
	summary, detail, remedy := fleetagent.ConfinementForTest(&fleetagent.RuntimeReportForTest{
		Account:     `NT AUTHORITY\NetworkService`,
		Home:        `C:\Windows\ServiceProfiles\NetworkService`,
		SessionZero: true,
		Visibility:  fleetagent.ProfileUnknownForTest,
	})
	assert.Equal(t, "running, but unusable", summary)
	assert.Contains(t, strings.Join(detail, "\n"), "session 0")
	assert.Contains(t, strings.Join(detail, "\n"), `NT AUTHORITY\NetworkService`)
	assert.Contains(t, strings.Join(detail, "\n"), "built-in service identity has no operator profile",
		"the account is what this verdict is drawn from; the home directory is the next case's evidence, and it must not be what answers here")
	assert.NotContains(t, strings.Join(detail, "\n"), "profile was never loaded",
		"that is the named-account verdict, and reaching it for a built-in identity would name the wrong fault")
	assert.Contains(t, strings.Join(remedy, "\n"), "--mechanism task")
	assert.Contains(t, strings.Join(remedy, "\n"), "--user DOMAIN",
		"a built-in identity has a second way out — a service under a named account — and it is the only verdict that offers one")

	// And the account alone is enough: a built-in identity whose home is an
	// ordinary-looking directory is still an agent with no operator profile.
	// Without this, the case above could be reached by the home directory it
	// happens to have rather than by the rule it is meant to test.
	summary, detail, _ = fleetagent.ConfinementForTest(&fleetagent.RuntimeReportForTest{
		Account:     `NT AUTHORITY\LocalService`,
		Home:        `C:\Users\localservice`,
		SessionZero: true,
		Visibility:  fleetagent.ProfileUnknownForTest,
	})
	assert.Equal(t, "running, but unusable", summary)
	assert.Contains(t, strings.Join(detail, "\n"), "built-in service identity has no operator profile")

	// A service under a named account whose profile the SCM did not load: the
	// account is ordinary, the session is still zero, and the toolchains are
	// still invisible.
	summary, detail, _ = fleetagent.ConfinementForTest(&fleetagent.RuntimeReportForTest{
		Account:     `WORKSTATION\axel`,
		Home:        `C:\Users\axel`,
		SessionZero: true,
		Visibility:  fleetagent.ProfileHiddenForTest,
		Unreachable: []string{`C:\Users\axel\.cargo\bin`},
	})
	assert.Equal(t, "running, but unusable", summary)
	assert.Contains(t, strings.Join(detail, "\n"), `C:\Users\axel\.cargo\bin`)

	// A service under a named account that was started without that account's
	// profile at all. The probe cannot see this one: it looks for per-user
	// installs under the home directory the daemon was given, and the daemon
	// was given a built-in service profile — so it finds nothing to look for
	// and answers "unknown", which everywhere else means "nothing to conclude".
	// Before #79 that read as a healthy agent and exited zero.
	for _, home := range []string{
		`C:\Windows\system32\config\systemprofile`,
		`C:\Windows\ServiceProfiles\LocalService`,
		`C:\Users\Default`,
	} {
		summary, detail, remedy := fleetagent.ConfinementForTest(&fleetagent.RuntimeReportForTest{
			Account:     `WORKSTATION\build`,
			Home:        home,
			SessionZero: true,
			Visibility:  fleetagent.ProfileUnknownForTest,
		})
		assert.Equal(t, "running, but unusable", summary, "home %s", home)
		assert.Contains(t, strings.Join(detail, "\n"), home)
		assert.Contains(t, strings.Join(detail, "\n"), "profile was never loaded")
		assert.Contains(t, strings.Join(remedy, "\n"), "--mechanism task")
	}

	// And the account whose profile *is* its own is not caught by that rule,
	// however little is installed under it. A headless build box with every
	// toolchain in Program Files is a working agent.
	summary, _, _ = fleetagent.ConfinementForTest(&fleetagent.RuntimeReportForTest{
		Account:     `WORKSTATION\build`,
		Home:        `C:\Users\build`,
		SessionZero: true,
		Visibility:  fleetagent.ProfileUnknownForTest,
	})
	assert.Empty(t, summary, "a service with its own profile and nothing installed per-user is not broken")

	// Hidden toolchains without session 0 — a Unix daemon running as the wrong
	// account — is the same fault and gets the same verdict.
	summary, _, _ = fleetagent.ConfinementForTest(&fleetagent.RuntimeReportForTest{
		Account:     "fleet",
		Home:        "/home/axel",
		Visibility:  fleetagent.ProfileHiddenForTest,
		Unreachable: []string{"/home/axel/.cargo/bin"},
	})
	assert.Equal(t, "running, but unusable", summary)

	// And the agents that are fine stay fine. A verdict that fires on a healthy
	// host is worse than no verdict: it is the one an operator learns to ignore.
	for name, report := range map[string]*fleetagent.RuntimeReportForTest{
		"visible": {Account: `WORKSTATION\axel`, Home: `C:\Users\axel`, Visibility: fleetagent.ProfileVisibleForTest, Ran: `C:\Users\axel\.cargo\bin\cargo.exe`},
		"unknown": {Account: "fleet", Home: "/var/lib/fleet", Visibility: fleetagent.ProfileUnknownForTest},
		"none":    nil,
	} {
		summary, _, _ := fleetagent.ConfinementForTest(report)
		assert.Empty(t, summary, "%s must not be reported as unusable", name)
	}
}

// pinAgentConfig writes a config naming a fresh state directory and points the
// agent's own discovery at it, which is how `service status` finds the runtime
// report.
func pinAgentConfig(t *testing.T) (stateDir string) {
	t.Helper()
	dir := t.TempDir()
	stateDir = filepath.Join(dir, "state")
	require.NoError(t, os.MkdirAll(stateDir, 0o750))

	configPath := filepath.Join(dir, "agent.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(
		"name: test-host\nlisten: 127.0.0.1:0\nstate_dir: "+filepath.ToSlash(stateDir)+"\n"), 0o600))
	t.Setenv("FLEET_AGENT_CONFIG", configPath)
	return stateDir
}

// plantLiveReport writes a runtime report describing a daemon that is really
// running: this process, with this process's start identity.
func plantLiveReport(t *testing.T, stateDir string, report fleetagent.RuntimeReportForTest) {
	t.Helper()
	pid, startID := fleetagent.LiveProcessIdentityForTest()
	require.NotEmpty(t, startID, "the platform must be able to identify this process")
	report.PID, report.StartID = pid, startID
	require.NoError(t, fleetagent.WriteRuntimeReportForTest(stateDir, report))
}

// Proof 2, driven from the command an operator types.
func TestServiceStatus_ReportsAConfinedAgentAsUnusable(t *testing.T) {
	stateDir := pinAgentConfig(t)
	plantLiveReport(t, stateDir, fleetagent.RuntimeReportForTest{
		Account:     `NT AUTHORITY\NetworkService`,
		Home:        `C:\Windows\ServiceProfiles\NetworkService`,
		SessionZero: true,
		Visibility:  fleetagent.ProfileUnknownForTest,
	})
	defer fleetagent.PinInstalledForTest([]fleetagent.Mechanism{fleetagent.MechanismService}, true)()

	out := &bytes.Buffer{}
	code := fleetagent.Main([]string{"service", "status"}, out)
	text := out.String()

	require.Equal(t, 1, code,
		"an agent that is up and cannot run anything is a fault, not an answer: %s", text)
	assert.Contains(t, text, "running, but unusable")
	assert.NotContains(t, text, "fleet-agent: running\n",
		"the headline must not still read as a healthy daemon")
	assert.Contains(t, text, "UNUSABLE")
	assert.Contains(t, text, `NT AUTHORITY\NetworkService`)
	assert.Contains(t, text, "session 0")
	assert.Contains(t, text, "--mechanism task", "and it has to say what to do instead")
}

// The other half of the same claim: an agent that is fine is reported as fine,
// and exits zero. Without this, "always say unusable" would pass the test above.
func TestServiceStatus_ReportsAWorkingAgentAsRunning(t *testing.T) {
	stateDir := pinAgentConfig(t)
	plantLiveReport(t, stateDir, fleetagent.RuntimeReportForTest{
		Account:    `WORKSTATION\axel`,
		Home:       `C:\Users\axel`,
		Visibility: fleetagent.ProfileVisibleForTest,
		Ran:        `C:\Users\axel\.cargo\bin\cargo.exe`,
	})
	defer fleetagent.PinInstalledForTest([]fleetagent.Mechanism{fleetagent.MechanismTask}, true)()

	out := &bytes.Buffer{}
	code := fleetagent.Main([]string{"service", "status"}, out)
	text := out.String()

	require.Equal(t, 0, code, "%s", text)
	assert.Contains(t, text, "fleet-agent: running")
	assert.NotContains(t, text, "unusable")
	assert.Contains(t, text, "Scheduled Task", "status has to say which mechanism it found")
	assert.Contains(t, text, `C:\Users\axel\.cargo\bin\cargo.exe`,
		"the evidence for the verdict is the program it resolved and ran")
}

// A report outlives the daemon that wrote it. Reporting from a stale one means
// answering for a process that no longer exists — including telling an operator
// their agent is unusable when the confined daemon was stopped hours ago.
func TestServiceStatus_IgnoresAReportFromAProcessThatIsGone(t *testing.T) {
	stateDir := pinAgentConfig(t)
	require.NoError(t, fleetagent.WriteRuntimeReportForTest(stateDir, fleetagent.RuntimeReportForTest{
		PID:         os.Getpid(),
		StartID:     "not-the-identity-of-this-process",
		Account:     `NT AUTHORITY\NetworkService`,
		SessionZero: true,
		Visibility:  fleetagent.ProfileUnknownForTest,
	}))
	defer fleetagent.PinInstalledForTest([]fleetagent.Mechanism{fleetagent.MechanismService}, true)()

	out := &bytes.Buffer{}
	code := fleetagent.Main([]string{"service", "status"}, out)
	text := out.String()

	require.Equal(t, 0, code, "%s", text)
	assert.NotContains(t, text, "unusable",
		"a record whose process is gone says nothing about the one running now")
}

// A host carrying both registrations starts two daemons against one state
// directory. status has to say so; nothing else on the host will.
func TestServiceStatus_WarnsAboutTwoRegistrations(t *testing.T) {
	pinAgentConfig(t)
	defer fleetagent.PinInstalledForTest(
		[]fleetagent.Mechanism{fleetagent.MechanismService, fleetagent.MechanismTask}, false)()

	out := &bytes.Buffer{}
	require.Equal(t, 0, fleetagent.Main([]string{"service", "status"}, out))
	text := out.String()
	assert.Contains(t, text, "registered twice")
	assert.Contains(t, text, "state directory")
}

// `service install --dry-run` is the only way to see which mechanism a host
// will get before running an elevated command that changes it. Driven from the
// command line, because the decision it reports is one this repository has
// three times fixed in a function the CLI never reached.
func TestServiceInstall_DryRunReportsThePlan(t *testing.T) {
	pinAgentConfig(t)

	out := &bytes.Buffer{}
	code := fleetagent.Main([]string{"service", "install", "--dry-run"}, out)
	text := out.String()
	require.Equal(t, 0, code, "a dry run changes nothing and needs no elevation: %s", text)

	assert.Contains(t, text, "dry run")
	assert.Contains(t, text, "mechanism:")
	assert.Contains(t, text, "runs as:")

	switch runtime.GOOS {
	case "windows":
		assert.Contains(t, text, "Scheduled Task",
			"the Windows default is the operator's own session, not session 0")
		assert.Contains(t, text, "when they log off", "and the trade has to be said at the moment it is made")
	default:
		assert.Contains(t, text, "service manager registration")
	}
}

// A host that already carries the other registration is told that install will
// remove it, before install is the thing that removed it.
func TestServiceInstall_DryRunReportsTheRegistrationItWouldReplace(t *testing.T) {
	pinAgentConfig(t)

	// Whichever mechanism this host would not resolve to: off Windows that is
	// always the task, and on Windows the default resolves to the task, so the
	// one being replaced is the service.
	other := fleetagent.MechanismTask
	if runtime.GOOS == "windows" {
		other = fleetagent.MechanismService
	}
	defer fleetagent.PinInstalledForTest([]fleetagent.Mechanism{other}, false)()

	out := &bytes.Buffer{}
	code := fleetagent.Main([]string{"service", "install", "--dry-run"}, out)
	text := out.String()
	require.Equal(t, 0, code, "%s", text)
	assert.Contains(t, text, "would first remove the existing")
	assert.Contains(t, text, "second daemon against the same")
}

// The mechanism an operator asks for is the one they are told about, and the
// combination that cannot exist is refused before anything is registered.
func TestServiceInstall_DryRunRefusesATaskUnderABuiltInIdentity(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("resolveMechanism is asserted for every GOOS in mechanism_test.go; this drives the real one")
	}
	pinAgentConfig(t)

	out := &bytes.Buffer{}
	code := fleetagent.Main([]string{
		"service", "install", "--dry-run",
		"--mechanism", "task", "--user", `NT AUTHORITY\NetworkService`,
	}, out)
	require.Equal(t, 1, code, "%s", out.String())
}

// And `install --dry-run` prints it, on the one runner that can reach the
// branch.
//
// The rule is asserted for every platform in mechanism_test.go; this is the
// other half — that the command consults it — and only a Windows host resolves
// a mechanism that needs a password at all. The account is this runner's own,
// because any other one is refused first by the executable-access rule: the
// test binary lives inside this account's profile.
func TestServiceInstall_DryRunSaysItWillAskForAPassword(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("only the Windows SCM logs an account on, so only a Windows host resolves a mechanism that needs a password")
	}
	current, err := user.Current()
	require.NoError(t, err)
	pinAgentConfig(t)

	out := &bytes.Buffer{}
	code := fleetagent.Main([]string{
		"service", "install", "--dry-run", "--mechanism", "service", "--user", current.Username,
	}, out)
	text := out.String()

	require.Equal(t, 0, code, "%s", text)
	assert.Contains(t, text, "would prompt for",
		"an unattended installer that does not know install stops to ask hangs on the prompt")
	assert.Contains(t, text, "Log on as a service",
		"and the right the SCM stores the password for but does not grant, without which every start fails with error 1069")
}

// The Unix half of the same refusal, and the half that proves it is wired into
// the command rather than merely implemented beside it.
//
// `install` runs elevated, so root reads /root/fleet-agent and a 0700 build
// directory perfectly well; the unit then names a path the service account
// cannot traverse and systemd reports 203/EXEC, which names neither the path
// nor the account. The `go test` binary lives in exactly such a directory,
// which is what makes this assertable at all.
func TestServiceInstall_DryRunWarnsAboutABinaryTheAccountCannotReach(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows rule is path-based, asserted in mechanism_test.go and refused rather than warned")
	}
	if _, err := user.Lookup("nobody"); err != nil {
		t.Skip("no `nobody` account on this host to install against")
	}
	exe, err := os.Executable()
	require.NoError(t, err)
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	if reachableByEveryAccount(exe) {
		t.Skipf("%s is reachable by every account on this host, so there is nothing for install to warn about", exe)
	}
	pinAgentConfig(t)

	out := &bytes.Buffer{}
	code := fleetagent.Main([]string{"service", "install", "--dry-run", "--user", "nobody"}, out)
	text := out.String()

	require.Equal(t, 0, code, "a dry run still resolves everything: %s", text)
	assert.Contains(t, text, "WARNING")
	assert.Contains(t, text, "203/EXEC", "the string an operator will search for")
	assert.Contains(t, text, "/usr/local/bin/fleet-agent", "and the command that fixes it")
}

// reachableByEveryAccount reports whether every directory above path, and path
// itself, carries the world execute bit.
func reachableByEveryAccount(path string) bool {
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil || info.Mode().Perm()&0o001 == 0 {
			return false
		}
		if dir == filepath.Dir(dir) {
			break
		}
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode().Perm()&0o001 != 0
}

// The probe takes the platform as a parameter, and until #79 every test drove
// it with runtime.GOOS — which meant the Windows half of it was checked on one
// runner out of three, and the part of that half that matters most was checked
// on none.
//
// Windows PATH entries fold: %USERPROFILE% is spelled with whatever case the
// account was created with, an installer writes its own spelling into PATH, and
// the two routinely disagree. A comparison that did not fold would report a
// perfectly healthy workstation as HIDDEN — a false "unusable", which is the
// verdict an operator learns to ignore.
func TestProfileProbe_WindowsPathEntriesFoldAndSplitOnSemicolons(t *testing.T) {
	home := t.TempDir()
	binDir := filepath.Join(home, ".cargo", "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))

	// A Windows PATH: semicolon-separated, and spelling the per-user directory
	// in a different case from the one on disk.
	machineDir := t.TempDir()
	pathEnv := strings.Join([]string{machineDir, strings.ToUpper(binDir)}, ";")

	visibility, ran, unreachable := fleetagent.ProfileProbeForTest(
		home, pathEnv, "windows", []fleetagent.UserToolchainForTest{})

	assert.Equal(t, fleetagent.ProfileVisibleForTest, visibility,
		"a PATH entry that differs only in case still reaches the directory on Windows")
	assert.Empty(t, ran, "no tool was offered, so nothing may be claimed to have run")
	assert.NotContains(t, unreachable, binDir)
}

// The same parameter, the other Windows rule: a bare name resolves through
// PATHEXT, so the probe has to look for fleetprobe.exe and not fleetprobe.
func TestProfileProbe_WindowsResolvesThroughPathext(t *testing.T) {
	home := t.TempDir()
	binDir := filepath.Join(home, ".cargo", "bin")
	marker := filepath.Join(t.TempDir(), "it-ran")
	planted, versionArgs := plantWindowsNamedToolchain(t, binDir, marker)

	tools := []fleetagent.UserToolchainForTest{{Name: plantedToolchainName, Version: versionArgs}}
	visibility, ran, _ := fleetagent.ProfileProbeForTest(home, binDir+";", "windows", tools)

	assert.Equal(t, fleetagent.ProfileVisibleForTest, visibility)
	assert.Equal(t, planted, ran, "a bare name has to resolve to the .exe beside it")
	assert.FileExists(t, marker, "and it has to be run, not merely resolved")
}

// plantWindowsNamedToolchain plants a runnable program under the name a Windows
// PATHEXT lookup would find, whichever host this runs on.
func plantWindowsNamedToolchain(t *testing.T, dir, marker string) (path string, versionArgs []string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return plantUserToolchain(t, dir, marker)
	}
	require.NoError(t, os.MkdirAll(dir, 0o755))
	path = filepath.Join(dir, plantedToolchainName+".exe")
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\nexec touch \"$1\"\n"), 0o755))
	return path, []string{marker}
}

// The probe runs on the daemon's start path, before the listener is bound, and
// it executes programs it found on somebody else's disk. One of them blocking —
// a shim waiting on a lock, a node on a stalled network mount — must not become
// a daemon that never starts and a service manager that says only "failed".
//
// Asserted by running one that never exits, not by checking that the constant
// bounding it is a sensible number.
func TestProfileProbe_IsBoundedByItsBudget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the planted program is a shell script; the bound it exercises is platform-independent")
	}
	home := t.TempDir()
	binDir := filepath.Join(home, ".cargo", "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(binDir, plantedToolchainName),
		[]byte("#!/bin/sh\nsleep 120\n"), 0o755))

	type answer struct{ visibility, ran string }
	done := make(chan answer, 1)
	go func() {
		visibility, ran := fleetagent.ProfileProbeBudgetForTest(
			home, binDir, runtime.GOOS, 250*time.Millisecond,
			[]fleetagent.UserToolchainForTest{{Name: plantedToolchainName}})
		done <- answer{visibility, ran}
	}()

	select {
	case got := <-done:
		assert.Equal(t, fleetagent.ProfileVisibleForTest, got.visibility,
			"the directory is on PATH whatever the program in it did")
		assert.Empty(t, got.ran, "a program that had to be killed did not run successfully")
	case <-time.After(30 * time.Second):
		t.Fatal("the probe never returned: a toolchain that hangs hangs the daemon before it binds its listener")
	}
}

// `service stop` under the task mechanism takes every supervised background
// process with it, because Task Scheduler ends a task by terminating what the
// task started. That is the opposite of KillMode=process and
// AbandonProcessGroup, it is what the other two platforms go out of their way
// to avoid, and Windows offers no setting for it — so the only place an
// operator can learn it is here, before it happens.
//
// Driven from the command. The warning was composed by a branch nothing
// reached, which is the shape this repository ships most often.
func TestServiceStop_WarnsThatEndingATaskKillsWhatItStarted(t *testing.T) {
	pinAgentConfig(t)

	for _, verb := range []string{"stop", "restart"} {
		restore := fleetagent.PinInstalledForTest([]fleetagent.Mechanism{fleetagent.MechanismTask}, true)
		out := &bytes.Buffer{}
		// The stop itself cannot succeed here — nothing a test may do can
		// register a task — but the warning is printed before it is attempted,
		// which is the whole point of it.
		_ = fleetagent.Main([]string{"service", verb}, out)
		restore()

		text := out.String()
		assert.Contains(t, text, "terminates the processes it started", "verb %s", verb)
		assert.Contains(t, text, "supervises", "verb %s", verb)
	}

	// And it is said about the mechanism it is true of. A note printed for a
	// service manager stop would be wrong, and a note printed always would pass
	// the assertions above without meaning anything.
	restore := fleetagent.PinInstalledForTest([]fleetagent.Mechanism{fleetagent.MechanismService}, true)
	defer restore()
	out := &bytes.Buffer{}
	_ = fleetagent.Main([]string{"service", "stop"}, out)
	assert.NotContains(t, out.String(), "terminates the processes it started",
		"a service manager stop leaves supervised processes alone")
}

// `--mechanism task` off Windows is a combination that cannot exist, and the
// refusal has to come from the command rather than only from the rule beneath
// it. On Windows the same command is legitimate and the impossible combination
// is the built-in identity instead; both are the same check, one call apart.
func TestServiceInstall_DryRunRefusesAMechanismThisHostCannotHave(t *testing.T) {
	pinAgentConfig(t)

	args := []string{"service", "install", "--dry-run", "--mechanism", "task"}
	if runtime.GOOS == "windows" {
		// A logon trigger fires when an account logs on interactively, and a
		// built-in service identity never does.
		args = append(args, "--user", `NT AUTHORITY\NetworkService`)
	}

	out := &bytes.Buffer{}
	code := fleetagent.Main(args, out)
	require.Equal(t, 1, code,
		"install must refuse a mechanism this host cannot give, before it changes anything: %s", out.String())
	assert.NotContains(t, out.String(), "would be registered",
		"and it must refuse before printing a plan it cannot carry out")
}

// And `install` prints them, rather than composing them for nobody.
//
// The account is a built-in service identity, which is a rule about the account
// and not about the host — so this reaches the same function on every runner.
// On Windows the task branch of it is asserted by
// TestServiceInstall_DryRunReportsThePlan, which is the mechanism a Windows
// host resolves to; here the same command is refused earlier, because the test
// binary lives inside the runner's own profile and a built-in identity cannot
// read it.
func TestServiceInstall_DryRunSaysWhatTheMechanismCosts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("on Windows this command is refused first by the executable-access rule; the notes are asserted there through the default mechanism")
	}
	pinAgentConfig(t)

	out := &bytes.Buffer{}
	code := fleetagent.Main([]string{
		"service", "install", "--dry-run", "--user", `NT AUTHORITY\NetworkService`,
	}, out)
	text := out.String()
	require.Equal(t, 0, code, "%s", text)

	assert.Contains(t, text, "session 0",
		"install has to say what the account it is about to register costs, at the moment it registers it")
	assert.Contains(t, text, "--mechanism task", "and name what would work instead")

	// The other thing install says about an account before it registers it, and
	// the one that is not about Windows at all: --user root is allowed, and is
	// not allowed to be quiet. It is not a property of the daemon — it is a
	// property of every command any model ever runs through it.
	out = &bytes.Buffer{}
	code = fleetagent.Main([]string{"service", "install", "--dry-run", "--user", "root"}, out)
	text = out.String()
	require.Equal(t, 0, code, "%s", text)
	assert.Contains(t, text, "WARNING: installing to run as root")
	assert.Contains(t, text, "will run as root")
}

// A filesystem root is not somebody's home directory, and treating it as one
// turns every question the probe asks into "yes".
//
// HOME=/ makes $HOME/bin mean /bin — a machine directory that exists on every
// Unix and is on every PATH — so the probe finds a "per-user" install, finds it
// reachable, reports the agent's environment as visible, and executes whichever
// of node, go or cargo happens to be in there, once per start, as evidence. The
// underDir check that exists to catch exactly that is vacuous against a root.
// A container started for a uid with no passwd entry gets HOME=/, which is the
// shape a fleet agent lands in on a build box.
func TestProfileProbe_AFilesystemRootIsNotAHomeDirectory(t *testing.T) {
	// The host's own root, with the host's own PATH: on any Unix that is a root
	// holding /bin, which is the combination that used to answer "visible".
	root := string(filepath.Separator)
	if volume := filepath.VolumeName(t.TempDir()); volume != "" {
		root = volume + root
	}

	visibility, ran, unreachable := fleetagent.ProfileProbeForTest(
		root, os.Getenv("PATH"), runtime.GOOS, nil)

	assert.Equal(t, fleetagent.ProfileUnknownForTest, visibility,
		"a root is not a home directory, so there is nothing installed per-user under it to conclude anything from")
	assert.Empty(t, ran, "and nothing under it may be run as proof of anything")
	assert.Empty(t, unreachable)

	// The rule itself, spelled in both platforms' notation so the Windows half
	// is checked from a Linux runner too.
	for _, home := range []string{"/", "//", `\`, `C:\`, "c:/", `D:\`, "  "} {
		visibility, _, _ := fleetagent.ProfileProbeForTest(home, os.Getenv("PATH"), runtime.GOOS, nil)
		assert.Equal(t, fleetagent.ProfileUnknownForTest, visibility, "home %q is a root", home)
	}

	// And an ordinary home directory is still probed. Without this, "always
	// answer unknown" would pass everything above.
	home := t.TempDir()
	binDir := filepath.Join(home, perUserBinDir())
	require.NoError(t, os.MkdirAll(binDir, 0o755))
	visibility, _, _ = fleetagent.ProfileProbeForTest(home, binDir, runtime.GOOS, nil)
	assert.Equal(t, fleetagent.ProfileVisibleForTest, visibility,
		"a real home directory with a per-user install on PATH is still visible")
}

// The root rule is asked of the canonical path, not of the spelling it arrived
// in.
//
// Round 2 caught HOME=/ and wrote the check against the literal string. Every
// other thing the probe does with Home goes through Clean — filepath.Join
// resolves "..", filepath.Rel cleans both its arguments — so "/.", "/..", and
// any path at all that cleans to a root walked straight past the new check and
// produced the same false "visible", and the same once-per-start execution of
// whatever happens to be in /bin, that the check was added to stop.
func TestProfileProbe_ARootSpelledAnyOtherWayIsStillARoot(t *testing.T) {
	for _, home := range []string{"/.", "/..", "/./", "/usr/..", "/tmp/../", `C:\.`, `C:\..`, `C:\Users\..`} {
		visibility, ran, _ := fleetagent.ProfileProbeForTest(home, os.Getenv("PATH"), runtime.GOOS, nil)
		assert.Equal(t, fleetagent.ProfileUnknownForTest, visibility,
			"%q names a filesystem root once anything cleans it, and a root is not a home directory", home)
		assert.Empty(t, ran, "and nothing under it may be executed as evidence of anything, home %q", home)
	}

	// A home directory that merely contains a "." or ".." component and does
	// not clean to a root is still an ordinary home, or the fix above would
	// answer "unknown" for every host.
	home := t.TempDir()
	binDir := filepath.Join(home, perUserBinDir())
	require.NoError(t, os.MkdirAll(binDir, 0o755))
	visibility, _, _ := fleetagent.ProfileProbeForTest(filepath.Join(home, "x", ".."), binDir, runtime.GOOS, nil)
	assert.Equal(t, fleetagent.ProfileVisibleForTest, visibility,
		"cleaning to somewhere under the filesystem is not the same as cleaning to the root of it")
}

// The directories the probe looks for on Windows, which is the platform it
// exists for and the one two runners out of three never read the list on.
//
// The two lists share `.cargo\bin` and `go\bin`, which is what every test that
// plants a toolchain uses — so handing the Windows caller the Unix list changed
// no assertion anywhere, and the entries that are the reason this works on a
// real workstation were checked by nothing.
func TestUserBinDirs_TheWindowsListIsTheWindowsOne(t *testing.T) {
	windows := strings.Join(fleetagent.UserBinDirsForTest("windows"), "\n")

	for _, want := range []string{
		`AppData\Roaming\npm`,
		`scoop\shims`,
		`.pyenv\pyenv-win\shims`,
		// Always on an interactive user's PATH and never on a service's, which
		// makes it the entry every Windows account has and the one most likely
		// to be the difference between "hidden" and "unknown".
		`AppData\Local\Microsoft\WindowsApps`,
	} {
		assert.Contains(t, windows, want, "a Windows toolchain installs here and the probe has to look")
	}
	assert.NotContains(t, windows, "/", "Windows entries are backslash-separated; a Unix entry here would name a directory that never exists")

	unix := strings.Join(fleetagent.UserBinDirsForTest("linux"), "\n")
	assert.Contains(t, unix, ".local/bin")
	assert.NotContains(t, unix, `\`, "and a Windows entry on Unix is the same mistake the other way round")

	// Nothing machine-wide, on either. A directory that is not per-user being
	// off PATH would read as a confined agent, which is a false "unusable" on
	// every host that does not have it.
	for _, list := range []string{windows, unix} {
		for _, line := range strings.Split(list, "\n") {
			assert.False(t, strings.HasPrefix(line, "/") || strings.Contains(line, ":"),
				"%q is not relative to a home directory", line)
		}
	}
}

// A Windows PATH entry may be quoted, and %PATH% hands the quotes through
// verbatim.
//
// This is the same shape as the case-folding gap round 1 found, in the other
// normalisation `pathKey` does and on the same nobody-checks-it footing: a
// quoted entry that does not compare equal reports a healthy workstation as
// HIDDEN, and `service status` then exits non-zero calling a working agent
// unusable — the verdict an operator learns to ignore.
func TestProfileProbe_WindowsPathEntriesMayBeQuoted(t *testing.T) {
	home := t.TempDir()
	binDir := filepath.Join(home, ".cargo", "bin")
	require.NoError(t, os.MkdirAll(binDir, 0o755))

	pathEnv := strings.Join([]string{`"C:\Program Files\Git\cmd"`, `"` + binDir + `"`}, ";")
	visibility, _, unreachable := fleetagent.ProfileProbeForTest(home, pathEnv, "windows", nil)

	assert.Equal(t, fleetagent.ProfileVisibleForTest, visibility,
		"a quoted PATH entry reaches the directory it names; %%PATH%% carries the quotes and the comparison has to drop them")
	assert.Empty(t, unreachable)
}

// A bare name resolves through the account's own PATHEXT, not through the
// probe's built-in list.
//
// The built-in list is the Windows default and the fallback for a daemon
// started without the variable; the branch that reads the real one had never
// been exercised, because every test plants a `.exe`, which both lists admit.
func TestProfileProbe_WindowsHonoursTheAccountsPathext(t *testing.T) {
	home := t.TempDir()
	binDir := filepath.Join(home, ".cargo", "bin")
	// .fleet is in no default list anywhere, so only PATHEXT can admit it —
	// and it is a real program, so "resolved" and "ran" stay two claims.
	planted, versionArgs := plantToolchainNamed(t, binDir, plantedToolchainName+".fleet",
		filepath.Join(t.TempDir(), "it-ran"))

	tools := []fleetagent.UserToolchainForTest{{Name: plantedToolchainName, Version: versionArgs}}

	_, ran, _ := fleetagent.ProfileProbeForTest(home, binDir, "windows", tools)
	assert.Empty(t, ran, "without PATHEXT admitting it, a bare name must not resolve to this file")

	t.Setenv("PATHEXT", ".COM;.EXE;.FLEET")
	_, ran, _ = fleetagent.ProfileProbeForTest(home, binDir, "windows", tools)
	assert.Equal(t, planted, ran,
		"the account's PATHEXT is what decides whether a bare name resolves, and the probe has to ask the same question a spawned command would")
}

// A file that resolves like a program and cannot be executed does not shadow
// the one that can.
//
// PATH is searched in order and the first match wins, so a name that resolves
// to a non-executable file earlier on PATH — a shim left behind by an
// uninstall, an ACL that denies execute — makes the probe give up on that tool
// entirely and report a working per-user toolchain as never having run. It is
// the rule os/exec's own lookup applies, and it was applied here and checked
// nowhere.
func TestProfileProbe_ANonExecutableFileDoesNotShadowTheRealOne(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows decides executability by extension, not by a mode bit; PATHEXT covers the same ground and is asserted above")
	}
	home := t.TempDir()
	binDir := filepath.Join(home, perUserBinDir())
	marker := filepath.Join(t.TempDir(), "it-ran")
	planted, versionArgs := plantUserToolchain(t, binDir, marker)

	// A directory earlier on PATH holding a same-named file with no execute
	// bit at all.
	shadowDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(shadowDir, plantedToolchainName), []byte("#!/bin/sh\nexit 0\n"), 0o644))

	pathEnv := strings.Join([]string{shadowDir, binDir}, string(os.PathListSeparator))
	tools := []fleetagent.UserToolchainForTest{{Name: plantedToolchainName, Version: versionArgs}}
	visibility, ran, _ := fleetagent.ProfileProbeForTest(home, pathEnv, runtime.GOOS, tools)

	assert.Equal(t, fleetagent.ProfileVisibleForTest, visibility)
	assert.Equal(t, planted, ran, "a file that cannot be executed is not what a bare name resolves to")
	assert.FileExists(t, marker)
}

// A host carrying both registrations is the one `stop` and `uninstall` exist to
// put right, and it is the one where returning at the first failure does the
// most damage: the operator asked for the agent to stop, one of the two is
// still running, and the error names the other mechanism as the reason.
func TestServiceControl_ActsOnEveryRegistrationEvenWhenOneFails(t *testing.T) {
	pinAgentConfig(t)

	both := []fleetagent.Mechanism{fleetagent.MechanismService, fleetagent.MechanismTask}
	calls, restore := fleetagent.PinRecordingRegistrationsForTest(both,
		map[fleetagent.Mechanism]bool{fleetagent.MechanismService: true})
	defer restore()

	out := &bytes.Buffer{}
	code := fleetagent.Main([]string{"service", "stop"}, out)

	require.Equal(t, 1, code, "a stop that could not stop everything is a failure: %s", out.String())
	assert.Equal(t, []string{"service:stop", "task:stop"}, calls(),
		"the task has to be stopped even though the service refused; leaving it running is the outcome an operator is least able to detect")
	assert.Contains(t, out.String(), "stop requested ("+fleetagent.MechanismTask.Describe()+")",
		"and the one that did stop has to be reported, or the operator cannot tell which half happened")
}

// The same for every verb, and the successful case: one registration reached
// per mechanism, in the order the host lookup returned them.
func TestServiceControl_ActsOnEveryRegistration(t *testing.T) {
	pinAgentConfig(t)

	for _, verb := range []string{"start", "stop", "restart"} {
		both := []fleetagent.Mechanism{fleetagent.MechanismService, fleetagent.MechanismTask}
		calls, restore := fleetagent.PinRecordingRegistrationsForTest(both, nil)

		out := &bytes.Buffer{}
		code := fleetagent.Main([]string{"service", verb}, out)
		restore()

		require.Equal(t, 0, code, "verb %s: %s", verb, out.String())
		assert.Equal(t, []string{"service:" + verb, "task:" + verb}, calls(), "verb %s", verb)
	}
}

// runAgentCommand drives the same command tree `fleet-agent` runs, and hands
// back the error rather than only the exit code.
//
// Main writes the error to os.Stderr and returns 1, which is right for a
// binary and useless for asserting *what* it said. The tree is the one
// NewRootCommand builds either way, so nothing here is a shortcut past the
// command: it is the same RunE, reached the same way, with somewhere to read
// the failure from.
func runAgentCommand(t *testing.T, out *bytes.Buffer, args ...string) error {
	t.Helper()
	root := fleetagent.NewRootCommand(out)
	root.SetArgs(args)
	root.SetErr(io.Discard)
	return root.Execute()
}

// Two registrations, both refusing. Round 2 made these commands walk past the
// first failure; what they say at the end had only ever been asserted with one
// failure in it, and every part of the reporting was therefore free.
//
// Reporting the first failure and dropping the second, or reporting neither
// with the mechanism it came from, both left the whole suite green — and both
// leave an operator with an error about one mechanism and a daemon still
// running under the other, which is the exact outcome walking every
// registration exists to prevent.
func TestServiceControl_ReportsEveryFailureAndNamesEachMechanism(t *testing.T) {
	pinAgentConfig(t)

	both := []fleetagent.Mechanism{fleetagent.MechanismService, fleetagent.MechanismTask}
	calls, restore := fleetagent.PinRecordingRegistrationsForTest(both, map[fleetagent.Mechanism]bool{
		fleetagent.MechanismService: true,
		fleetagent.MechanismTask:    true,
	})
	defer restore()

	out := &bytes.Buffer{}
	err := runAgentCommand(t, out, "service", "stop")

	require.Error(t, err, "neither registration stopped, so the command failed: %s", out.String())
	assert.Equal(t, []string{"service:stop", "task:stop"}, calls(),
		"the second is still attempted; that is what round 2 fixed")
	assert.Contains(t, err.Error(), fleetagent.MechanismService.Describe(),
		"each failure has to name the registration it came from, or two of them are indistinguishable")
	assert.Contains(t, err.Error(), fleetagent.MechanismTask.Describe(),
		"the second failure must not be dropped: an operator told about one still has a daemon running under the other")
}

// The same for uninstall, where a definition left behind starts a second daemon
// at the next boot and nothing says so.
func TestServiceUninstall_ReportsEveryFailureAndNamesEachMechanism(t *testing.T) {
	defer fleetagent.PinElevatedForTest()()

	both := []fleetagent.Mechanism{fleetagent.MechanismService, fleetagent.MechanismTask}
	calls, restore := fleetagent.PinRecordingRegistrationsForTest(both, map[fleetagent.Mechanism]bool{
		fleetagent.MechanismService: true,
		fleetagent.MechanismTask:    true,
	})
	defer restore()

	out := &bytes.Buffer{}
	err := runAgentCommand(t, out, "service", "uninstall")

	require.Error(t, err, "%s", out.String())
	assert.Equal(t, []string{"service:stop", "service:uninstall", "task:stop", "task:uninstall"}, calls())
	assert.Contains(t, err.Error(), fleetagent.MechanismService.Describe())
	assert.Contains(t, err.Error(), fleetagent.MechanismTask.Describe())
	assert.NotContains(t, out.String(), "left in place:",
		"nothing was removed, so the summary of what removal kept would be a lie")
}

// `service status` reads every answer it gives about a confined agent out of
// one file. When it cannot read that file it used to print "running" and exit
// zero, having never got to ask the question — and on Linux that is the common
// case, because `install` gives the state directory to the service account at
// 0750 and `status` is not an elevated command.
func TestServiceStatus_SaysWhenItCouldNotReadTheDaemonsReport(t *testing.T) {
	stateDir := pinAgentConfig(t)
	require.NoError(t, os.WriteFile(filepath.Join(stateDir, "runtime.json"),
		[]byte("{ this is not the report\n"), 0o600))
	defer fleetagent.PinInstalledForTest([]fleetagent.Mechanism{fleetagent.MechanismService}, true)()

	out := &bytes.Buffer{}
	code := fleetagent.Main([]string{"service", "status"}, out)
	text := out.String()

	require.Equal(t, 0, code, "the agent may be perfectly fine; this command just cannot tell: %s", text)
	assert.Contains(t, text, "could not read the record the daemon writes")
	assert.Contains(t, text, "runtime.json", "and it has to name the file, or there is nothing to go and look at")
	assert.Contains(t, text, "cannot tell a confined")
}

// And a host that simply has no report is not told anything: an agent that has
// never started is an ordinary state, not a fault of this command.
func TestServiceStatus_SaysNothingWhenThereIsNoReportAtAll(t *testing.T) {
	pinAgentConfig(t)
	defer fleetagent.PinInstalledForTest([]fleetagent.Mechanism{fleetagent.MechanismService}, true)()

	out := &bytes.Buffer{}
	require.Equal(t, 0, fleetagent.Main([]string{"service", "status"}, out))
	assert.NotContains(t, out.String(), "could not read the record")
}

// The confined shape `status` has to name, in the one report field an operator
// can act on: which directories are installed and off the agent's PATH.
func TestServiceStatus_NamesTheToolchainsItCannotReach(t *testing.T) {
	stateDir := pinAgentConfig(t)
	plantLiveReport(t, stateDir, fleetagent.RuntimeReportForTest{
		Account:     `WORKSTATION\axel`,
		Home:        `C:\Users\axel`,
		SessionZero: true,
		Visibility:  fleetagent.ProfileHiddenForTest,
		Unreachable: []string{`C:\Users\axel\.cargo\bin`},
	})
	defer fleetagent.PinInstalledForTest([]fleetagent.Mechanism{fleetagent.MechanismService}, true)()

	out := &bytes.Buffer{}
	code := fleetagent.Main([]string{"service", "status"}, out)
	text := out.String()

	require.Equal(t, 1, code, "%s", text)
	assert.Contains(t, text, "per-user toolchains: HIDDEN (1 directory installed and not on its PATH)")
	assert.Contains(t, text, `C:\Users\axel\.cargo\bin`)
	// The task mechanism has no SCM entry to ask for a pid, so the daemon's own
	// record is the only source of one. "unavailable" here means status found
	// the report, drew a verdict from it, and still could not say which process
	// it was about.
	assert.NotContains(t, text, "pid:        unavailable")
}

// `uninstall` on a host carrying both registrations removes both — including
// when the first one refuses.
//
// That host is not hypothetical: it is what switching mechanisms produces, and
// it is the state `install` and `status` both warn about. Removing one of the
// two and returning is the outcome an operator is least able to detect, because
// the command has already said it removed something and the error names the
// other mechanism.
func TestServiceUninstall_RemovesEveryRegistrationEvenWhenOneFails(t *testing.T) {
	defer fleetagent.PinElevatedForTest()()

	both := []fleetagent.Mechanism{fleetagent.MechanismService, fleetagent.MechanismTask}
	calls, restore := fleetagent.PinRecordingRegistrationsForTest(both,
		map[fleetagent.Mechanism]bool{fleetagent.MechanismService: true})
	defer restore()

	out := &bytes.Buffer{}
	code := fleetagent.Main([]string{"service", "uninstall"}, out)

	require.Equal(t, 1, code, "a removal that could not remove everything is a failure: %s", out.String())
	assert.Equal(t, []string{"service:stop", "service:uninstall", "task:stop", "task:uninstall"}, calls(),
		"the task has to be removed even though the service refused; a definition left behind starts a second daemon at the next boot")
	assert.Contains(t, out.String(), "service fleet-agent removed ("+fleetagent.MechanismTask.Describe()+")")
}

// And the whole of it when nothing refuses: both removed, and the material an
// operator must not lose named as kept.
func TestServiceUninstall_KeepsTheEnrollmentAndProcessState(t *testing.T) {
	defer fleetagent.PinElevatedForTest()()

	both := []fleetagent.Mechanism{fleetagent.MechanismService, fleetagent.MechanismTask}
	calls, restore := fleetagent.PinRecordingRegistrationsForTest(both, nil)
	defer restore()

	out := &bytes.Buffer{}
	code := fleetagent.Main([]string{"service", "uninstall"}, out)
	text := out.String()

	require.Equal(t, 0, code, "%s", text)
	assert.Equal(t, []string{"service:stop", "service:uninstall", "task:stop", "task:uninstall"}, calls())
	assert.Contains(t, text, "left in place:")
	assert.Contains(t, text, "supervised process state")
	assert.Contains(t, text, "rejoin without enrolling again",
		"uninstall keeps the enrollment on purpose, and an operator has to be told so or they will enroll again")
}
