package fleetagent_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/cli/fleetagent"
)

// The rule that decides where a Windows agent lands, asserted from every
// runner rather than only from a Windows one.
//
// It is the whole of #74. A Windows service runs in session 0 and sees no
// per-user toolchain; a logon-triggered Scheduled Task runs in the operator's
// session and sees all of them. Which one an operator gets is decided here, by
// a pure function, so that the decision is checked on ubuntu and macos too —
// where nothing else about it can be.
func TestResolveMechanism_Windows(t *testing.T) {
	// The default, and the change: no --user, no --mechanism, and the agent
	// lands in the session the operator is sitting in.
	got, err := fleetagent.ResolveMechanismForTest(fleetagent.MechanismAuto, "windows", `WORKSTATION\axel`)
	require.NoError(t, err)
	assert.Equal(t, fleetagent.MechanismTask, got,
		"an ordinary account must get its own session, not session 0")

	// A built-in service identity is a deliberate ask for a confined agent, and
	// the only mechanism that can host one is a service.
	for _, account := range []string{`NT AUTHORITY\NetworkService`, "LocalSystem", `nt authority\localservice`} {
		got, err := fleetagent.ResolveMechanismForTest(fleetagent.MechanismAuto, "windows", account)
		require.NoError(t, err)
		assert.Equal(t, fleetagent.MechanismService, got, "%s can only be a service", account)
	}

	// Asked for explicitly, a service is a service whoever runs it.
	got, err = fleetagent.ResolveMechanismForTest(fleetagent.MechanismService, "windows", `WORKSTATION\axel`)
	require.NoError(t, err)
	assert.Equal(t, fleetagent.MechanismService, got)
}

// The combination that cannot exist, refused with the reason rather than
// registered and left to fail at the next boot.
func TestResolveMechanism_TaskCannotRunABuiltInIdentity(t *testing.T) {
	_, err := fleetagent.ResolveMechanismForTest(fleetagent.MechanismTask, "windows", `NT AUTHORITY\NetworkService`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logon")
	assert.Contains(t, err.Error(), "--mechanism service",
		"the refusal has to name the mechanism that would work")
}

func TestResolveMechanism_TaskIsWindowsOnly(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		_, err := fleetagent.ResolveMechanismForTest(fleetagent.MechanismTask, goos, "fleet")
		require.Error(t, err, "%s has no Task Scheduler", goos)
		assert.Contains(t, err.Error(), goos)

		for _, requested := range []fleetagent.Mechanism{fleetagent.MechanismAuto, fleetagent.MechanismService} {
			got, err := fleetagent.ResolveMechanismForTest(requested, goos, "fleet")
			require.NoError(t, err)
			assert.Equal(t, fleetagent.MechanismService, got)
		}
	}
}

func TestParseMechanism(t *testing.T) {
	for input, want := range map[string]fleetagent.Mechanism{
		"":        fleetagent.MechanismAuto,
		"auto":    fleetagent.MechanismAuto,
		"Service": fleetagent.MechanismService,
		" TASK ":  fleetagent.MechanismTask,
	} {
		got, err := fleetagent.ParseMechanism(input)
		require.NoError(t, err, "input %q", input)
		assert.Equal(t, want, got)
	}
	_, err := fleetagent.ParseMechanism("scheduled")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auto, service, task")
}

// Only the Windows SCM asks for a password, and only for a named account. A
// prompt anywhere else is a prompt an unattended installer hangs on.
func TestServiceNeedsPassword(t *testing.T) {
	assert.True(t, fleetagent.ServiceNeedsPasswordForTest(fleetagent.MechanismService, "windows", `WORKSTATION\axel`))
	assert.False(t, fleetagent.ServiceNeedsPasswordForTest(fleetagent.MechanismService, "windows", `NT AUTHORITY\NetworkService`),
		"a built-in service identity has no password")
	assert.False(t, fleetagent.ServiceNeedsPasswordForTest(fleetagent.MechanismTask, "windows", `WORKSTATION\axel`),
		"an interactive logon type borrows the session that already exists")
	assert.False(t, fleetagent.ServiceNeedsPasswordForTest(fleetagent.MechanismService, "linux", "fleet"))
	assert.False(t, fleetagent.ServiceNeedsPasswordForTest(fleetagent.MechanismService, "darwin", "axel"))
}

// The built-in identities, which are the accounts with no operator profile.
func TestRunsInSessionZero(t *testing.T) {
	for _, account := range []string{
		`NT AUTHORITY\NetworkService`,
		`nt authority\networkservice`,
		`NT AUTHORITY\LocalService`,
		`NT AUTHORITY\SYSTEM`,
		"LocalSystem",
		" networkservice ",
	} {
		assert.True(t, fleetagent.RunsInSessionZeroForTest(account), "%q is a built-in service identity", account)
	}
	for _, account := range []string{"", "axel", `WORKSTATION\axel`, "fleet", `CORP\systemsadmin`} {
		assert.False(t, fleetagent.RunsInSessionZeroForTest(account),
			"%q is an ordinary account and must not be treated as session-0-only", account)
	}
}

// `service install` runs elevated by definition, so "the invoking user" would
// otherwise quietly mean the machine's most privileged account.
func TestInvokingServiceUser_RefusesASuperuser(t *testing.T) {
	name, err := fleetagent.InvokingServiceUserForTest(`WORKSTATION\axel`)
	require.NoError(t, err)
	assert.Equal(t, `WORKSTATION\axel`, name)

	for _, superuser := range []string{"root", "LocalSystem", `NT AUTHORITY\SYSTEM`} {
		_, err := fleetagent.InvokingServiceUserForTest(superuser)
		require.Error(t, err, "%s must not become the default", superuser)
		assert.Contains(t, strings.ToLower(err.Error()), "refusing")
		assert.Contains(t, err.Error(), "--user")
	}

	_, err = fleetagent.InvokingServiceUserForTest("  ")
	require.Error(t, err)
}

// `install` registers os.Executable() and never copies it. A manual download
// lands on the Desktop, and a service registered there under an account that
// cannot read it installs cleanly and then fails every start with error 5.
func TestWindowsExecutableAccessProblem(t *testing.T) {
	const usersRoot = `C:\Users`

	problem := fleetagent.WindowsExecutableAccessProblemForTest(
		`C:\Users\axel\Desktop\fleet-agent.exe`, `NT AUTHORITY\NetworkService`, usersRoot)
	require.NotEmpty(t, problem, "a built-in service identity cannot read anybody's profile")
	assert.Contains(t, problem, "axel")

	problem = fleetagent.WindowsExecutableAccessProblemForTest(
		`C:\Users\axel\Desktop\fleet-agent.exe`, `WORKSTATION\bob`, usersRoot)
	require.NotEmpty(t, problem, "bob cannot read axel's profile either")

	// The case the new default creates, and it must be allowed: the operator
	// installs from their own Desktop and the agent runs as them.
	assert.Empty(t, fleetagent.WindowsExecutableAccessProblemForTest(
		`C:\Users\axel\Desktop\fleet-agent.exe`, `WORKSTATION\axel`, usersRoot))
	assert.Empty(t, fleetagent.WindowsExecutableAccessProblemForTest(
		`C:\Users\axel\Desktop\fleet-agent.exe`, "axel", usersRoot))

	// A second profile for the same account is named axel.CORP, and refusing
	// that install would refuse one that works.
	assert.Empty(t, fleetagent.WindowsExecutableAccessProblemForTest(
		`C:\Users\axel.CORP\bin\fleet-agent.exe`, `CORP\axel`, usersRoot))

	// So is an 8.3 short name, which is how an inherited %TEMP% spells the
	// same directory.
	assert.Empty(t, fleetagent.WindowsExecutableAccessProblemForTest(
		`C:\Users\RUNNER~1\AppData\Local\Temp\fleet-agent.exe`, `RUNNERVM\runneradmin`, usersRoot))

	// Outside anybody's profile there is nothing to say.
	for _, exe := range []string{
		`C:\Program Files\fleet\fleet-agent.exe`,
		`C:\Users\fleet-agent.exe`,
		`D:\tools\fleet-agent.exe`,
	} {
		assert.Empty(t, fleetagent.WindowsExecutableAccessProblemForTest(exe, `NT AUTHORITY\NetworkService`, usersRoot),
			"%s is not inside a profile", exe)
	}
}

// The refusal has to carry the fix, or an operator is left with a command that
// says no and nothing else.
func TestExecutableAccessAdvice(t *testing.T) {
	advice := fleetagent.ExecutableAccessAdviceForTest(
		"it is inside axel's profile", `C:\Users\axel\Desktop\fleet-agent.exe`, `NT AUTHORITY\NetworkService`, "windows")
	assert.Contains(t, advice, "error 5, access denied", "the string an operator will search for")
	assert.Contains(t, advice, `Copy-Item`)
	assert.Contains(t, advice, `C:\Program Files\fleet`)

	// "linux", not runtime.GOOS. The parameter exists so that both platforms'
	// wording is asserted from every runner; reading the host's GOOS here made
	// this half run on two runners out of three and fail on the third.
	for _, goos := range []string{"linux", "darwin"} {
		advice = fleetagent.ExecutableAccessAdviceForTest(
			"/root/fleet-agent is mode 0700", "/root/fleet-agent", "fleet", goos)
		assert.Contains(t, advice, "203/EXEC", "goos %s", goos)
		assert.Contains(t, advice, "/usr/local/bin/fleet-agent", "goos %s", goos)
	}
}

// The account `install` hands the SCM, which is not the account it prints.
//
// CreateService resolves a bare name against the *domain*, not the machine, so
// `--user build` on a domain-joined host registers a service for CORP\build —
// an account that does not exist — and the install fails naming it. The rule
// was Windows-only code until #79, which meant the one runner that could check
// it was the one nobody has a domain on.
func TestSCMAccount_LocalAccountsAreSpelledForTheSCM(t *testing.T) {
	scmAccount := func(goos, account string) string {
		p := fleetagent.UnitParams{Executable: "fleet-agent.exe", ConfigPath: "agent.yaml", User: account}
		return fleetagent.SCMAccountForTest(p, goos, "")
	}

	assert.Equal(t, `.\build`, scmAccount("windows", "build"),
		"a bare name is a domain account to CreateService")

	// Already qualified, in any of the three ways Windows qualifies a name.
	for _, account := range []string{`CORP\build`, `.\build`, "build@corp.example"} {
		assert.Equal(t, account, scmAccount("windows", account), "%s is already qualified", account)
	}

	// The built-in identities are spelled the way the SCM names them and must
	// not be turned into local accounts that do not exist.
	assert.Equal(t, `NT AUTHORITY\NetworkService`, scmAccount("windows", `NT AUTHORITY\NetworkService`))
	assert.Equal(t, "LocalSystem", scmAccount("windows", "LocalSystem"))

	// Everywhere else the account is what the operator typed: `.\fleet` is not
	// a user systemd or launchd has ever heard of.
	for _, goos := range []string{"linux", "darwin"} {
		assert.Equal(t, "fleet", scmAccount(goos, "fleet"), "goos %s", goos)
	}
}

// The password reaches the service manager and nothing else builds a copy of
// it: it is set on the configuration only when there is one to set.
func TestSCMConfig_CarriesThePasswordOnlyWhenThereIsOne(t *testing.T) {
	p := fleetagent.UnitParams{Executable: "fleet-agent.exe", ConfigPath: "agent.yaml", User: "build"}

	secret, ok := fleetagent.SCMPasswordForTest(p, "windows", "hunter2")
	require.True(t, ok, "the SCM will not create a service under a named account without one")
	assert.Equal(t, "hunter2", secret)

	_, ok = fleetagent.SCMPasswordForTest(p, "windows", "")
	assert.False(t, ok, "a built-in identity has no password, and an empty one is not a password")
}

// What `install` says at the moment it registers something, asserted from every
// runner because the rule deciding it is a rule and not a platform.
func TestMechanismNotes(t *testing.T) {
	joined := func(m fleetagent.Mechanism, goos, account string) string {
		return strings.Join(fleetagent.MechanismNotesForTest(m, goos, account), "\n")
	}

	// The task's two costs, both discovered as a surprise otherwise.
	task := joined(fleetagent.MechanismTask, "windows", `WORKSTATION\axel`)
	assert.Contains(t, task, `WORKSTATION\axel`)
	assert.Contains(t, task, "log off", "an agent that stops at logout has to say so")
	assert.Contains(t, task, "terminates what the",
		"and that `service stop` takes the supervised background processes with it")

	// A built-in identity is a working registration and a useless agent.
	confined := joined(fleetagent.MechanismService, "windows", `NT AUTHORITY\NetworkService`)
	assert.Contains(t, confined, "session 0")
	assert.Contains(t, confined, "--mechanism task", "and it has to name what would work")

	// A named account needs a right the SCM stores no password for. Without it
	// the service installs cleanly and every start fails with error 1069 — the
	// same shape as the error 5 install already refuses, from the other side.
	named := joined(fleetagent.MechanismService, "windows", `WORKSTATION\build`)
	assert.Contains(t, named, "Log on as a service")
	assert.Contains(t, named, "1069", "the number an operator will search for")
	assert.Contains(t, named, "secedit", "and a command that grants it")

	// And nothing is said where nothing is true: systemd and launchd log an
	// account on with neither a password nor a privilege.
	for _, goos := range []string{"linux", "darwin"} {
		assert.Empty(t, fleetagent.MechanismNotesForTest(fleetagent.MechanismService, goos, "fleet"),
			"goos %s has nothing to warn about here", goos)
	}
}
