package fleetagent_test

import (
	"runtime"
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

	advice = fleetagent.ExecutableAccessAdviceForTest(
		"/root/fleet-agent is mode 0700", "/root/fleet-agent", "fleet", runtime.GOOS)
	assert.Contains(t, advice, "203/EXEC")
	assert.Contains(t, advice, "/usr/local/bin/fleet-agent")
}
