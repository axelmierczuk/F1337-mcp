package fleetagent_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/cli/fleetagent"
)

// #84's one open question, and the decision this repository is making: the
// logon-triggered Scheduled Task stays the Windows default, and the prompt
// belongs to the mechanism that cannot work without a credential.
//
// #74 is a workstation bug. #79's answer to it — a task in the operator's own
// session — needs no password at all, and is what somebody who has never heard
// of session 0 gets by not choosing. A prompt on every Windows install would
// ask that operator for a credential the mechanism they are getting does not
// use, and would block the one install that has to work with nobody in front of
// it. So the prompt fires exactly where the SCM demands a password: a Windows
// service under a named account.
//
// The rule is asserted from every runner because it decides what an operator is
// asked, and a rule only the Windows runner can reach is a rule only that
// runner checks.
func TestResolveAccountChoice(t *testing.T) {
	choice := fleetagent.ResolveAccountChoiceForTest

	// The decision: a Windows service with no --user stops and asks.
	assert.Equal(t, fleetagent.AccountFromPromptForTest,
		choice(fleetagent.MechanismService, "windows", "", false),
		"the account a Windows service runs as is every command's account, and it is no longer defaulted to whoever opened the elevated shell")

	// And the workstation default does not, which is the whole point of
	// reserving it: the task needs no password, so there is nothing to ask.
	assert.Equal(t, fleetagent.AccountFromDefaultForTest,
		choice(fleetagent.MechanismAuto, "windows", "", false),
		"a prompt on every Windows install would undo #79: the task default is the one thing that works on a workstation with no stored credential")
	assert.Equal(t, fleetagent.AccountFromDefaultForTest,
		choice(fleetagent.MechanismTask, "windows", "", false))

	// --user is how a script says it, on every mechanism and every platform.
	for _, m := range []fleetagent.Mechanism{fleetagent.MechanismAuto, fleetagent.MechanismService, fleetagent.MechanismTask} {
		assert.Equal(t, fleetagent.AccountFromFlagForTest, choice(m, "windows", `WORKSTATION\build`, false),
			"mechanism %s", m)
	}
	assert.Equal(t, fleetagent.AccountFromFlagForTest,
		choice(fleetagent.MechanismService, "windows", "   ", false),
		"a flag the operator did pass is not silently replaced by the platform default, even when what they passed is a typo: `ensureServiceUser` refuses it by name")

	// Nothing off Windows asks: no other service manager logs an account on, so
	// there is no credential and nothing to choose.
	for _, goos := range []string{"linux", "darwin"} {
		assert.Equal(t, fleetagent.AccountFromDefaultForTest,
			choice(fleetagent.MechanismService, goos, "", false), "goos %s", goos)
	}

	// And the combination that has to refuse rather than guess. stdin is the
	// password; reading a line off it for the account would consume the
	// password and then ask for it again.
	assert.Equal(t, fleetagent.AccountUnaskableForTest,
		choice(fleetagent.MechanismService, "windows", "", true))
	assert.Equal(t, fleetagent.AccountFromFlagForTest,
		choice(fleetagent.MechanismService, "windows", `WORKSTATION\build`, true),
		"--user and --password-stdin together is the scripted install, and it must keep working")
}

// The account prompt, driven against a supplied stream.
//
// An empty line takes the suggestion, which is what pressing return means. End
// of stream is not an empty line and must not be read as one: a script that
// redirected stdin from nowhere would otherwise get the silent fallback to the
// invoking account that this change exists to remove.
func TestPromptServiceAccount(t *testing.T) {
	out := &bytes.Buffer{}
	account, err := fleetagent.PromptServiceAccountForTest(
		strings.NewReader("CORP\\build\n"), out, `WORKSTATION\axel`)
	require.NoError(t, err)
	assert.Equal(t, `CORP\build`, account)
	assert.Contains(t, out.String(), `WORKSTATION\axel`, "the prompt has to show what return would accept")
	assert.Contains(t, out.String(), "session 0",
		"and what the answer costs: a service has no operator profile")
	assert.Contains(t, out.String(), "Log on as a service",
		"and the right a named account needs, which is the other half of the credential")

	// Return accepts the suggestion.
	account, err = fleetagent.PromptServiceAccountForTest(
		strings.NewReader("\n"), io.Discard, `WORKSTATION\axel`)
	require.NoError(t, err)
	assert.Equal(t, `WORKSTATION\axel`, account)

	// Surrounding whitespace is not part of an account name.
	account, err = fleetagent.PromptServiceAccountForTest(
		strings.NewReader("  CORP\\build \r\n"), io.Discard, "")
	require.NoError(t, err)
	assert.Equal(t, `CORP\build`, account)

	// Nothing on the stream at all. This is the case that must not fall back.
	_, err = fleetagent.PromptServiceAccountForTest(strings.NewReader(""), io.Discard, `WORKSTATION\axel`)
	require.Error(t, err, "an operator who pressed return is not a script that had nothing to say")
	assert.Contains(t, err.Error(), "--user", "and the refusal has to name the way to answer it")
	assert.Contains(t, err.Error(), "--password-stdin",
		"including the unattended form in full: this product is installed by scripts")

	// And a host with no defensible default insists on an answer.
	_, err = fleetagent.PromptServiceAccountForTest(strings.NewReader("\n"), io.Discard, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--user")
}

// readInputLine consumes exactly one line and not a byte more.
//
// Invisible from either caller and load-bearing for both. install now asks two
// questions off one stream, and a buffered reader fills its buffer from the
// underlying stream: the account prompt would swallow the password typed after
// it, and the password prompt would then block on a stream with nothing left.
// The retry has the same shape — three reads, one stream.
func TestReadInputLine_ConsumesExactlyOneLine(t *testing.T) {
	stream := strings.NewReader("CORP\\build\nhunter2\nhunter3\n")

	first, err := fleetagent.ReadInputLineForTest(stream)
	require.NoError(t, err)
	assert.Equal(t, `CORP\build`, first)

	second, err := fleetagent.ReadInputLineForTest(stream)
	require.NoError(t, err)
	assert.Equal(t, "hunter2", second, "the line after the first one is still on the stream")

	third, err := fleetagent.ReadInputLineForTest(stream)
	require.NoError(t, err)
	assert.Equal(t, "hunter3", third)

	// CRLF, which is what a Windows console sends.
	line, err := fleetagent.ReadInputLineForTest(strings.NewReader("hunter2\r\n"))
	require.NoError(t, err)
	assert.Equal(t, "hunter2", line)

	// A last line with no terminator is still a line.
	line, err = fleetagent.ReadInputLineForTest(strings.NewReader("hunter2"))
	require.NoError(t, err)
	assert.Equal(t, "hunter2", line)

	// And end of stream is not an empty line.
	_, err = fleetagent.ReadInputLineForTest(strings.NewReader(""))
	require.ErrorIs(t, err, io.EOF)

	line, err = fleetagent.ReadInputLineForTest(strings.NewReader("\n"))
	require.NoError(t, err, "an empty line is an answer: it means take the default")
	assert.Empty(t, line)
}

// What install makes of the answer LogonUser gave.
//
// The classification is the whole of "validate before registering": two codes
// refuse, and everything else does not. It is a rule over Win32 status numbers,
// which no runner here can produce and every runner can check — the same reason
// the account-name rules in this package take goos as a parameter.
func TestClassifyServiceLogon(t *testing.T) {
	classify := fleetagent.ClassifyServiceLogonForTest

	assert.Equal(t, fleetagent.LogonOKForTest, classify(nil))

	// ERROR_LOGON_TYPE_NOT_GRANTED: the password is right and
	// SeServiceLogonRight is not granted. This is error 1069 at every start,
	// which #79 could only warn about after the fact.
	assert.Equal(t, fleetagent.LogonRightMissingForTest, classify(syscall.Errno(1385)))

	// The credential itself will not log on, in each of the ways Windows says
	// so. All of them produce a service that fails every start, so all of them
	// refuse.
	for _, code := range []uintptr{1317, 1326, 1327, 1328, 1329, 1330, 1331, 1332, 1793, 1907, 1909} {
		assert.Equal(t, fleetagent.LogonBadCredentialForTest, classify(syscall.Errno(code)), "code %d", code)
	}

	// Wrapped, which is how it arrives from anything that adds context.
	assert.Equal(t, fleetagent.LogonBadCredentialForTest,
		classify(fmt.Errorf("check %s: %w", `CORP\build`, syscall.Errno(1326))),
		"errors.As, not equality: the code is what decides, wherever it is wrapped")

	// A platform with no SCM: not an answer about the credential.
	assert.Equal(t, fleetagent.LogonUnverifiableForTest, classify(fleetagent.ErrLogonUnverifiableForTest))
	assert.Equal(t, fleetagent.LogonUnverifiableForTest,
		classify(fmt.Errorf("wrapped: %w", fleetagent.ErrLogonUnverifiableForTest)))

	// And the default is deliberately not a refusal. A status code this code
	// has never seen is not evidence that the install would fail, and refusing
	// on one blocks an install that works for a reason nobody anticipated.
	assert.Equal(t, fleetagent.LogonUnknownForTest, classify(syscall.Errno(5)),
		"ERROR_ACCESS_DENIED is about the caller, not about the account being checked")
	assert.Equal(t, fleetagent.LogonUnknownForTest, classify(errors.New("no error code at all")))
}

// The account the logon is checked against has to be the account the SCM will
// be handed, split the way LogonUser wants it.
//
// Checking a different account from the one being registered is worse than not
// checking: it would pass for `build` on the domain while CreateService
// registers `.\build` on the machine.
func TestSplitServiceAccount(t *testing.T) {
	account, domain := fleetagent.SplitServiceAccountForTest(`CORP\build`)
	assert.Equal(t, "build", account)
	assert.Equal(t, "CORP", domain)

	// What serviceAccountName produces for a bare local name. "." is how Win32
	// names the local account database.
	account, domain = fleetagent.SplitServiceAccountForTest(`.\build`)
	assert.Equal(t, "build", account)
	assert.Equal(t, ".", domain)

	// A UPN goes whole, with no domain, which is what LogonUser documents.
	account, domain = fleetagent.SplitServiceAccountForTest("build@corp.example")
	assert.Equal(t, "build@corp.example", account)
	assert.Empty(t, domain)

	// A built-in identity, which the SCM spells with the authority in front.
	account, domain = fleetagent.SplitServiceAccountForTest(`NT AUTHORITY\NetworkService`)
	assert.Equal(t, "NetworkService", account)
	assert.Equal(t, "NT AUTHORITY", domain)
}

// The SeServiceLogonRight text is one text with two renderings.
//
// #79 wrote it for the note it prints after registering. #84 turns the same
// condition into a refusal before registering, and a second copy of the
// instructions would be a second thing to keep true — which is how this area
// ended up with two spellings of NetworkService.
func TestServiceLogonRight_OneTextTwoRenderings(t *testing.T) {
	const account = `CORP\build`
	note := strings.Join(fleetagent.ServiceLogonRightNoteForTest(account), "\n")
	refusal := fleetagent.ServiceLogonRightRefusalForTest(account)

	for _, fragment := range []string{
		"Log on as a service", "SeServiceLogonRight", "1069",
		"secedit /export /cfg", "secedit /configure", "Local Security Policy", account,
	} {
		assert.Contains(t, note, fragment, "the note has to carry %q", fragment)
		assert.Contains(t, refusal, fragment, "and so does the refusal built from the same text")
	}
	assert.Contains(t, refusal, "Nothing has been created, granted, or registered",
		"a refusal has to say the host is unchanged, or an operator goes looking for what to undo")
}

// --password-stdin gets one attempt, and a prompt gets three.
//
// The non-interactive path must not turn into a prompt: a pipe holds one
// password, and asking again reads whatever came after it, which is nothing.
// An installer that blocks forever is worse than one that fails.
func TestPasswordAttempts(t *testing.T) {
	assert.Equal(t, 1, fleetagent.PasswordAttemptsForTest(true),
		"a pipe has one password on it; a second read would hang an unattended install")
	assert.Equal(t, fleetagent.InteractivePasswordAttemptsForTest, fleetagent.PasswordAttemptsForTest(false))
	assert.Greater(t, fleetagent.InteractivePasswordAttemptsForTest, 1,
		"the point of checking before registering is that a typo is retyped rather than re-running an elevated command")
}

// reads answers a sequence of passwords, and says how many were taken.
func reads(passwords ...string) (func() (string, error), func() int) {
	taken := 0
	return func() (string, error) {
			if taken >= len(passwords) {
				return "", errors.New("nothing left on the stream")
			}
			taken++
			return passwords[taken-1], nil
		}, func() int {
			return taken
		}
}

// The credential is checked before install touches the host, and the verdict
// decides what happens next.
//
// The whole sequence is unreachable from every runner here — readPassword needs
// a Windows console, and the check needs a real LSA, a real account and that
// account's real password — so every decision in it would otherwise be free to
// delete.
func TestCredentialLoop_AcceptsAVerifiedCredential(t *testing.T) {
	out := &bytes.Buffer{}
	read, taken := reads("hunter2")

	password, verified, err := fleetagent.CredentialLoopForTest(out, `CORP\build`, 3, false, read,
		func(string) error { return nil })

	require.NoError(t, err)
	assert.Equal(t, "hunter2", password)
	assert.True(t, verified, "the SCM's own logon succeeded, so install has no reason to warn about the right it just used")
	assert.Equal(t, 1, taken(), "a password that works is read once")
	assert.NotContains(t, out.String(), "hunter2")
}

// A mistyped password is retyped at the prompt, which is the point of checking
// before anything is registered.
//
// Without the retry the check turns one wrong character into a re-run of an
// elevated command — and the operator cannot see what they typed.
func TestCredentialLoop_RetriesAMistypedPassword(t *testing.T) {
	out := &bytes.Buffer{}
	read, taken := reads("hunter1", "hunter2")
	answers := []error{syscall.Errno(1326), nil}
	call := 0

	password, verified, err := fleetagent.CredentialLoopForTest(out, `CORP\build`, 3, false, read,
		func(string) error {
			call++
			return answers[call-1]
		})

	require.NoError(t, err)
	assert.Equal(t, "hunter2", password, "the accepted one, not the first one")
	assert.True(t, verified)
	assert.Equal(t, 2, taken())
	assert.Contains(t, out.String(), "was not accepted", "and the operator is told why they are being asked again")
	assert.Contains(t, out.String(), "2 attempts left")
	for _, secret := range []string{"hunter1", "hunter2"} {
		assert.NotContains(t, out.String(), secret, "neither the rejected one nor the accepted one may be echoed")
	}
}

// The attempt budget ends the command, and ends it having registered nothing.
func TestCredentialLoop_GivesUpAfterTheBudget(t *testing.T) {
	out := &bytes.Buffer{}
	read, taken := reads("wrong1", "wrong2", "wrong3", "wrong4")

	password, verified, err := fleetagent.CredentialLoopForTest(out, `CORP\build`, 3, false, read,
		func(string) error { return syscall.Errno(1326) })

	require.Error(t, err)
	assert.Equal(t, 3, taken(), "three attempts, not an unbounded loop and not one")
	assert.Empty(t, password, "a refused credential is not carried out of here")
	assert.False(t, verified)
	assert.Contains(t, err.Error(), "1069",
		"the number an operator searches for when the service they registered will not start")
	assert.Contains(t, err.Error(), "Nothing has been created, granted, or registered")
	assert.Contains(t, err.Error(), "retype")
	for _, secret := range []string{"wrong1", "wrong2", "wrong3"} {
		assert.NotContains(t, err.Error()+out.String(), secret)
	}
}

// --password-stdin refuses on the first rejection and names the pipe.
func TestCredentialLoop_DoesNotRetryAPipe(t *testing.T) {
	out := &bytes.Buffer{}
	read, taken := reads("wrong1", "wrong2", "wrong3")

	_, _, err := fleetagent.CredentialLoopForTest(out, `CORP\build`, 1, true, read,
		func(string) error { return syscall.Errno(1326) })

	require.Error(t, err)
	assert.Equal(t, 1, taken(), "a second read on a pipe with one password on it blocks an unattended install")
	assert.Contains(t, err.Error(), "--password-stdin", "and the refusal names where the wrong one came from")
}

// A missing right refuses without a retry, and with #79's instructions.
//
// Retyping a password does not grant a privilege, and asking three times for
// one that was right the first time reads as the password being the problem.
func TestCredentialLoop_RefusesAMissingLogonRightWithoutRetrying(t *testing.T) {
	out := &bytes.Buffer{}
	read, taken := reads("hunter2", "hunter2", "hunter2")

	password, verified, err := fleetagent.CredentialLoopForTest(out, `CORP\build`, 3, false, read,
		func(string) error { return syscall.Errno(1385) })

	require.Error(t, err)
	assert.Equal(t, 1, taken(), "the password was right; asking for it again says the wrong thing")
	assert.Empty(t, password)
	assert.False(t, verified)
	assert.Contains(t, err.Error(), "SeServiceLogonRight")
	assert.Contains(t, err.Error(), "secedit", "and how to grant it")
	assert.Contains(t, err.Error(), "Nothing has been created, granted, or registered")
}

// A check that could not run is not a failed check.
//
// Off Windows there is nothing to ask, and on a host where LogonUser answers
// something this code has never seen, refusing would block an install that
// works. Both proceed — and the second says so, because the operator has to
// know the thing that would have caught a bad credential did not run.
func TestCredentialLoop_ProceedsWhenNothingCouldCheck(t *testing.T) {
	out := &bytes.Buffer{}
	read, _ := reads("hunter2")
	password, verified, err := fleetagent.CredentialLoopForTest(out, `CORP\build`, 3, false, read,
		func(string) error { return fleetagent.ErrLogonUnverifiableForTest })
	require.NoError(t, err)
	assert.Equal(t, "hunter2", password)
	assert.False(t, verified, "and install must still print the right it could not check")
	assert.Empty(t, out.String(), "a platform that never had an SCM has nothing to report about one")

	out = &bytes.Buffer{}
	read, _ = reads("hunter2")
	password, verified, err = fleetagent.CredentialLoopForTest(out, `CORP\build`, 3, false, read,
		func(string) error { return syscall.Errno(5) })
	require.NoError(t, err, "an unrecognised status code is not evidence the install would fail")
	assert.Equal(t, "hunter2", password)
	assert.False(t, verified)
	assert.Contains(t, out.String(), "could not check", "but it is not swallowed either")
	assert.Contains(t, out.String(), "proceeds without that check")
	assert.NotContains(t, out.String(), "hunter2")
}

// A read that fails ends the command, with nothing registered and no attempt to
// carry on without a password.
func TestCredentialLoop_APasswordItCannotReadEndsIt(t *testing.T) {
	password, verified, err := fleetagent.CredentialLoopForTest(io.Discard, `CORP\build`, 3, false,
		func() (string, error) { return "", errors.New("no password was given") },
		func(string) error { return errors.New("the check must not be reached") })

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no password was given")
	assert.Empty(t, password)
	assert.False(t, verified)
}

// The password reaches the SCM's Password option and appears nowhere else in
// the definition.
//
// This is the failure the brief calls silent and permanent: a credential
// written into an argument list, a unit file or a plist is on disk or in the
// process table for as long as the service exists, and nothing ever reports it.
// Asserting it against the definition the command actually builds — including
// the rendered systemd unit and launchd plist, which ride in the same Option
// map — is the difference between a property and a parameter name.
func TestSCMConfig_ThePasswordIsInExactlyOnePlace(t *testing.T) {
	const secret = "correct-horse-battery-staple-84"
	params := fleetagent.UnitParams{
		Executable:   `C:\Program Files\fleet\fleet-agent.exe`,
		ConfigPath:   `C:\ProgramData\fleet\agent.yaml`,
		User:         `CORP\build`,
		StateDir:     `C:\ProgramData\fleet\state`,
		LogDir:       `C:\ProgramData\fleet\logs`,
		AllowedRoots: []string{`C:\work`},
	}

	stored, ok := fleetagent.SCMPasswordForTest(params, "windows", secret)
	require.True(t, ok, "the SCM will not create a service under a named account without one")
	assert.Equal(t, secret, stored)

	for _, field := range fleetagent.SCMConfigFieldsForTest(params, "windows", secret) {
		assert.NotContains(t, field, secret,
			"a password in any other field of the definition is on disk for as long as the service exists")
	}

	// The Scheduled Task carries no credential at all: an interactive logon
	// type borrows a session rather than starting one.
	assert.NotContains(t, params.ScheduledTaskXML(), secret)
	assert.NotContains(t, params.SystemdUnit(), secret)
	assert.NotContains(t, params.LaunchdPlist(), secret)
}
