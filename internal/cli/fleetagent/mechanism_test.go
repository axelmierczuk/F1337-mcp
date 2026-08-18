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

// The same identities, spelled the way the platform spells them back.
//
// Every case above is the *logon* name: what CreateService takes and what an
// operator types. LookupAccountSid — which is where runtimeReport.Account comes
// from, deliberately, and what `whoami` and services.msc print — returns the
// display name for the same well-known SIDs, and two of the three have a space
// in them. Recognised on neither side, that spelling made `service status` name
// the wrong fault for the account #74 is about, and made `--user` with it
// resolve to a logon-triggered task for an account that never logs on.
func TestRunsInSessionZero_TheSpellingThePlatformReports(t *testing.T) {
	for _, account := range []string{
		`NT AUTHORITY\NETWORK SERVICE`,
		`NT AUTHORITY\LOCAL SERVICE`,
		`nt authority\network service`,
		"Network Service",
		"Local Service",
		// What currentAccount records when the name lookup cannot be made:
		// the well-known SIDs themselves.
		"S-1-5-18",
		"S-1-5-19",
		"S-1-5-20",
	} {
		assert.True(t, fleetagent.RunsInSessionZeroForTest(account),
			"%q is how Windows itself names a built-in service identity", account)
	}
	for _, account := range []string{`CORP\network services`, `CORP\system`, `WORKSTATION\axel smith`} {
		assert.False(t, fleetagent.RunsInSessionZeroForTest(account),
			"%q is an ordinary account and must not be treated as session-0-only", account)
	}
}

// The same identities, spelled the way this program itself produces and asks
// for them.
//
// `.\name` is how CreateService is told "this machine, not the domain":
// serviceAccountName exists to add it, and the account prompt offers
// `DOMAIN\name, .\name, or name@domain` as the three shapes to type. So the
// prefixed form is one an operator reaches by following this program's own
// instructions — and unfolded, every rule built on the session-zero key read it
// as an ordinary named account. #99 named account spelling as one of its two
// hypotheses, after `NT AUTHORITY\NETWORK SERVICE` had already been a
// showstopper for the same reason.
func TestRunsInSessionZero_TheSpellingThisProgramProduces(t *testing.T) {
	for _, account := range []string{
		`.\LocalSystem`,
		`.\SYSTEM`,
		`.\NetworkService`,
		`.\LOCAL SERVICE`,
		`.\localservice`,
	} {
		assert.True(t, fleetagent.RunsInSessionZeroForTest(account),
			"%q is a built-in service identity spelled the way this program spells accounts for the SCM", account)
	}
	// And it cannot promote an ordinary account: the prefix is a location, not
	// a privilege. `.\admin` is what the host in #99 was registered under.
	for _, account := range []string{`.\admin`, `.\build`, `.\systemsadmin`, `.\`} {
		assert.False(t, fleetagent.RunsInSessionZeroForTest(account),
			"%q is a machine-local *named* account and must stay one", account)
	}

	// Every rule drawn from that answer, driven with the prefixed form. Each of
	// these was silently wrong: a logon-triggered task for the machine account,
	// no warning that every command would run as SYSTEM, a prompt for the
	// password of an account that has none, and — in ensureServiceUser — an
	// account-database lookup a built-in identity has no entry to satisfy.
	mechanism, err := fleetagent.ResolveMechanismForTest(fleetagent.MechanismAuto, "windows", `.\LocalSystem`)
	require.NoError(t, err)
	assert.Equal(t, fleetagent.MechanismService, mechanism,
		"the machine account can only be hosted by a service, however it is spelled")

	_, err = fleetagent.ResolveMechanismForTest(fleetagent.MechanismTask, "windows", `.\NetworkService`)
	require.Error(t, err, "a logon trigger for an account that never logs on is the one combination this rule refuses")

	assert.True(t, fleetagent.IsSuperuserForTest(`.\LocalSystem`),
		"install has to say that every command the agent runs will run as the machine")
	assert.False(t, fleetagent.ServiceNeedsPasswordForTest(fleetagent.MechanismService, "windows", `.\NetworkService`),
		"a built-in service identity has no password, so install must not stop to ask for one")
	assert.Contains(t, strings.Join(fleetagent.MechanismNotesForTest(fleetagent.MechanismService, "windows", `.\LocalService`, false), "\n"),
		"no operator profile",
		"and the confined-agent warning is the one this account gets, not the credential note")
}

// The two rules that ask about the same accounts have to agree about them.
//
// runsInSessionZero folds spaces and knows the well-known SIDs; isSuperuser
// matched four literal strings and neither. So `--user S-1-5-18` — what a
// report carries when the name lookup fails, and a perfectly good argument to
// CreateService — was a session-0 identity to one rule and an ordinary account
// to the other, which is a machine-account install with no warning that every
// command the agent runs would run as the machine. `NT AUTHORITY\LocalSystem`,
// which is how Microsoft's own documentation writes the account CreateService
// takes as the bare word `LocalSystem`, was unknown to both: it resolved to a
// logon-triggered task for an account that never logs on.
func TestSuperuserAndSessionZeroAgree(t *testing.T) {
	for _, account := range []string{
		"LocalSystem",
		`NT AUTHORITY\SYSTEM`,
		`nt authority\system`,
		`NT AUTHORITY\LocalSystem`,
		"S-1-5-18",
		" system ",
	} {
		assert.True(t, fleetagent.IsSuperuserForTest(account),
			"%q is the machine account, and install has to say every command will run as it", account)
		assert.True(t, fleetagent.RunsInSessionZeroForTest(account),
			"%q can only be hosted by a service, so the mechanism rule has to know it too", account)
	}
	for _, account := range []string{`NT AUTHORITY\NETWORK SERVICE`, "LocalService", "S-1-5-20"} {
		assert.False(t, fleetagent.IsSuperuserForTest(account),
			"%q is confined, not all-powerful, and warning about it would be false", account)
		assert.True(t, fleetagent.RunsInSessionZeroForTest(account))
	}
	for _, account := range []string{"axel", `CORP\build`, `WORKSTATION\systemsadmin`} {
		assert.False(t, fleetagent.IsSuperuserForTest(account), "%q is an ordinary account", account)
	}
}

// And the two rules that decide what an operator ends up with, driven with that
// spelling: a built-in identity can only be a service, and asking for a task
// under one is refused.
func TestResolveMechanism_TheSpellingThePlatformReports(t *testing.T) {
	const reported = `NT AUTHORITY\NETWORK SERVICE`

	mechanism, err := fleetagent.ResolveMechanismForTest(fleetagent.MechanismAuto, "windows", reported)
	require.NoError(t, err)
	assert.Equal(t, fleetagent.MechanismService, mechanism,
		"a logon trigger fires when an account logs on interactively, and this one never does")

	_, err = fleetagent.ResolveMechanismForTest(fleetagent.MechanismTask, "windows", reported)
	require.Error(t, err, "asking for a task under a built-in identity is refused, however the identity is spelled")

	assert.False(t, fleetagent.ServiceNeedsPasswordForTest(fleetagent.MechanismService, "windows", reported),
		"a built-in service identity has no password, so install must not stop to ask for one")
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

	// And so is an account spelled as a UPN, which is how a domain-joined or
	// Entra-joined host names one and how an operator will type it. The
	// profile directory is still just the sAMAccountName, so refusing here
	// would refuse an operator installing their own binary to run as
	// themselves — the case the new default is built around.
	assert.Empty(t, fleetagent.WindowsExecutableAccessProblemForTest(
		`C:\Users\axel\Desktop\fleet-agent.exe`, "axel@corp.example", usersRoot))

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
	assert.NotContains(t, advice, `\\`,
		"the remedy is pasted into a Windows shell, and %q would double every backslash in the path it names")
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
// What a dry run says about the one step the resolved plan cannot show.
//
// A dry run exists so an operator can find out what `install` will do before it
// does it, and "it is going to stop and ask you for a password" is the part
// they most need in advance — an unattended installer that does not know it
// hangs on a prompt. Only the Windows SCM asks, so the branch fires on one
// runner in three, and composed inline in the command it was checked on none:
// the same shape as the `service stop` warning round 1 found.
func TestDryRunNotes_SayWhenInstallWillAskForAPassword(t *testing.T) {
	joined := func(m fleetagent.Mechanism, goos, account string, choice fleetagent.AccountChoiceForTest) string {
		return strings.Join(fleetagent.DryRunNotesForTest(m, goos, account, choice), "\n")
	}

	named := joined(fleetagent.MechanismService, "windows", `WORKSTATION\build`, fleetagent.AccountFromFlagForTest)
	assert.Contains(t, named, `would prompt for WORKSTATION\build's password`)
	assert.Contains(t, named, "check it against the logon the SCM",
		"install no longer only stores the credential, and a preview that says it only stores it is out of date")

	// The account prompt is the other half, and the one that changes what the
	// plan above it means: `runs as:` is only the account that gets registered
	// if the operator presses return.
	asked := joined(fleetagent.MechanismService, "windows", `WORKSTATION\axel`, fleetagent.AccountFromPromptForTest)
	assert.Contains(t, asked, "would ask which account")
	assert.Contains(t, asked, "the default it would offer",
		"otherwise the plan reads as a decision that has been made")
	assert.Contains(t, asked, "--user", "and it has to name the way to answer it up front")

	// And the combination install will not guess at, reported in the plan
	// rather than by failing: a dry run fails only when it cannot produce one.
	unaskable := joined(fleetagent.MechanismService, "windows", `WORKSTATION\axel`, fleetagent.AccountUnaskableForTest)
	assert.Contains(t, unaskable, "would refuse")
	assert.Contains(t, unaskable, "--password-stdin")

	for _, tc := range []struct {
		mechanism fleetagent.Mechanism
		goos      string
		account   string
		why       string
	}{
		{fleetagent.MechanismTask, "windows", `WORKSTATION\build`, "a task with an interactive logon type borrows a session rather than starting one"},
		{fleetagent.MechanismService, "windows", `NT AUTHORITY\NetworkService`, "a built-in service identity has no password"},
		{fleetagent.MechanismService, "linux", "fleet", "systemd does not log an account on"},
		{fleetagent.MechanismService, "darwin", "axel", "neither does launchd"},
	} {
		assert.Empty(t, fleetagent.DryRunNotesForTest(tc.mechanism, tc.goos, tc.account, fleetagent.AccountFromFlagForTest), tc.why)
	}
}

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
		return strings.Join(fleetagent.MechanismNotesForTest(m, goos, account, false), "\n")
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

	// And it is still session 0, which is the whole of #99: the mechanism that
	// arrived on that host was a service under the invoking operator, and the
	// only thing `install` said about it was a privilege note. An operator who
	// asked for their own account and got session-0 isolation has to be told
	// which command answers whether the agent can reach their toolchain, and
	// which mechanism does not have the question.
	assert.Contains(t, named, "session 0",
		"a Windows service runs in session 0 whoever it runs as, and that is the #74 outcome when the profile is not loaded")
	assert.Contains(t, named, "service status",
		"install cannot know whether the profile was loaded; the command that checks has to be named")
	assert.Contains(t, named, "--mechanism task", "and so does the mechanism that has no session 0 at all")

	// And nothing is said where nothing is true: systemd and launchd log an
	// account on with neither a password nor a privilege.
	for _, goos := range []string{"linux", "darwin"} {
		assert.Empty(t, fleetagent.MechanismNotesForTest(fleetagent.MechanismService, goos, "fleet", false),
			"goos %s has nothing to warn about here", goos)
	}
}

// Once `install` has performed the SCM's own logon, the note about the right it
// just used is not merely redundant — it contradicts what the command proved.
//
// #79 printed it unconditionally because nothing could check. #84 checks, so
// the note is what is left over for the case where the check could not run, and
// which of those a host is in is a rule rather than a platform.
func TestMechanismNotes_ARightThatWasCheckedIsNotAlsoWarnedAbout(t *testing.T) {
	const account = `WORKSTATION\build`
	unverified := strings.Join(fleetagent.MechanismNotesForTest(fleetagent.MechanismService, "windows", account, false), "\n")
	require.Contains(t, unverified, "Log on as a service",
		"a host where nothing could check still has to be told")

	verified := strings.Join(fleetagent.MechanismNotesForTest(fleetagent.MechanismService, "windows", account, true), "\n")
	for _, gone := range []string{"Log on as a service", "1069", "secedit"} {
		assert.NotContains(t, verified, gone,
			"install logged this account on as a service moments ago; telling the operator it may not be able to is wrong, not cautious")
	}

	// What the check settled is the privilege, and nothing else. A service that
	// logs on perfectly is still a service in session 0, so the note #99 is
	// about does not depend on a credential either.
	assert.Contains(t, verified, "session 0",
		"a successful logon says nothing about which session the daemon lands in")

	// And the parameter must not reach the notes that have nothing to do with a
	// credential: a task still stops at logout, and a built-in identity still
	// cannot see a toolchain, whatever a logon check said.
	task := fleetagent.MechanismNotesForTest(fleetagent.MechanismTask, "windows", account, true)
	assert.NotEmpty(t, task, "the task's two costs are not conditional on a credential check")
	confined := fleetagent.MechanismNotesForTest(fleetagent.MechanismService, "windows", `NT AUTHORITY\NetworkService`, true)
	assert.NotEmpty(t, confined)
}
