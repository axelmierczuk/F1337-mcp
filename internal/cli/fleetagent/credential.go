package fleetagent

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"syscall"

	"github.com/axelmierczuk/fleet-mcp/internal/cli"
)

// accountChoice is where `service install` gets the account the daemon will run
// as, decided before anything on this host is created, granted or registered.
//
// The account is the single most consequential thing an install decides. It is
// what every command any model runs through this agent executes as, what owns
// every file they write, and — on Windows — what decides whether the agent can
// see a toolchain at all. #84 is the argument that a decision that large should
// be asked for rather than resolved on the operator's behalf.
//
// It is not asked for everywhere, and that is the decision this type records.
// See resolveAccountChoice.
type accountChoice int

const (
	// accountFromFlag: --user named it, which is how a script says it.
	accountFromFlag accountChoice = iota
	// accountFromDefault: there is nothing worth stopping to ask. Either this
	// is not a mechanism that logs an account on with a stored credential, or
	// the platform's default is the answer.
	accountFromDefault
	// accountFromPrompt: install stops and asks.
	accountFromPrompt
	// accountUnaskable: install has to ask and has nothing to ask with,
	// because --password-stdin has made stdin the password.
	accountUnaskable
)

// resolveAccountChoice decides whether `service install` stops to ask which
// account it is about to register, and it is the whole of #84's one open
// question: does asking become the Windows default, or does it belong to the
// mechanism that cannot work without it.
//
// It belongs to the mechanism. #74 is a workstation bug and #79's answer to it
// is the logon-triggered Scheduled Task, which runs in the operator's own
// session, needs no password, and is what an operator who has never heard of
// session 0 gets by not choosing. A prompt on every Windows install would ask
// that operator for a credential the mechanism they are getting does not use,
// and the one install that has to keep working with no operator in front of it
// — the workstation one — is the one it would block.
//
// So the prompt fires exactly where the credential is unavoidable: a Windows
// service under a named account, which the SCM logs on with LogonUser and will
// not register without a password. That is `--mechanism service`, which is
// already the deliberate, headless, non-default ask. Where it fires, nothing is
// resolved silently any more: the account is chosen at the prompt, not defaulted
// to whoever happened to open the elevated shell.
//
// goos is a parameter for the reason resolveMechanism's is: the rule decides
// what an operator is asked, and a rule only one runner can reach is a rule only
// that runner checks.
func resolveAccountChoice(requested Mechanism, goos, userFlag string, passwordStdin bool) accountChoice {
	// Not trimmed. `--user "  "` is a typo, and the answer to a typo is the
	// refusal ensureServiceUser already gives it — naming the account that does
	// not resolve. Treating it as "unset" would substitute the platform default
	// for a flag the operator did pass, which is the silent resolution this
	// change exists to remove.
	if userFlag != "" {
		return accountFromFlag
	}
	if goos != "windows" || requested != MechanismService {
		return accountFromDefault
	}
	if passwordStdin {
		// stdin is the password. Reading a line off it for the account would
		// consume the password and then ask for it again, so this combination
		// is refused rather than guessed at.
		return accountUnaskable
	}
	return accountFromPrompt
}

// serviceAccountPrompt is what an operator is asked, and it has to carry the
// consequences of the answer rather than only the question.
//
// Composed here rather than inline in the command for the reason mechanismNotes
// is: it fires on one runner in three, and a message composed inside a branch
// no runner reaches is a message checked by nobody.
func serviceAccountPrompt(suggestion string) string {
	var b strings.Builder
	b.WriteString("\nA Windows service is logged on by the SCM with a stored credential and runs in\n")
	b.WriteString("session 0. Every command this agent runs, and every file it writes, is that\n")
	b.WriteString("account's.\n\n")
	b.WriteString("  DOMAIN\\name, .\\name, or name@domain\n")
	b.WriteString("      a named account. Needs its password, and the \"Log on as a service\" right.\n")
	b.WriteString("  " + networkServiceAccount + "\n")
	b.WriteString("      a built-in identity. No password, and no operator profile: it sees no\n")
	b.WriteString("      nvm, rustup, pyenv, cargo, scoop or npm globals.\n\n")
	if suggestion != "" {
		return b.String() + "Account [" + suggestion + "]: "
	}
	return b.String() + "Account: "
}

// promptServiceAccount asks which account the Windows service will run as.
//
// An empty line takes the suggestion, which is what an operator pressing return
// means. End-of-stream is not an empty line and must not be read as one: a
// script that redirected stdin from nowhere would otherwise get the silent
// fallback to the invoking account that this whole change exists to remove.
func promptServiceAccount(in io.Reader, out io.Writer, suggestion string) (string, error) {
	if _, err := fmt.Fprint(out, serviceAccountPrompt(suggestion)); err != nil {
		return "", err
	}
	line, err := readInputLine(in)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return "", errors.New(noAccountToAskRefusal("stdin ended before an account was given"))
		}
		return "", fmt.Errorf("read the account for the Windows service: %w", err)
	}
	if answer := strings.TrimSpace(line); answer != "" {
		return answer, nil
	}
	if suggestion == "" {
		return "", errors.New(noAccountToAskRefusal("no account was given, and this host offers no default"))
	}
	return suggestion, nil
}

// noAccountToAskRefusal is what install says when it must be told the account
// and cannot be.
//
// The scripted form is spelled out in full, because "this product is installed
// by scripts" is the reason the non-interactive path exists at all, and a
// refusal that only says what went wrong leaves the operator to work out what
// the command should have been.
func noAccountToAskRefusal(why string) string {
	return "refusing to register a Windows service without being told which account it runs as: " + why + ".\n\n" +
		"Every command this agent runs is that account's, so it is not defaulted here.\n" +
		"Pass --user, which is also how an unattended install supplies it:\n" +
		"  'the password' | fleet-agent service install --mechanism service --user 'DOMAIN\\name' --password-stdin"
}

// readInputLine reads exactly one line, and not a byte more.
//
// One byte at a time, deliberately. A buffered reader fills its buffer from the
// underlying stream, so a prompt read through one can swallow input the *next*
// prompt was going to read — which here means the account prompt eating the
// password typed after it, and the password prompt eating nothing while the
// operator waits.
//
// io.EOF is returned when the stream ends before any byte arrives. That is a
// different answer from an empty line, and the two must not be conflated: an
// empty line is an operator pressing return to accept a default, and
// end-of-stream is a script with no answer to give.
func readInputLine(in io.Reader) (string, error) {
	var b strings.Builder
	// An array rather than a slice: one byte, provably, at every read.
	var buf [1]byte
	for {
		n, err := in.Read(buf[:])
		if n > 0 {
			c := buf[0]
			if c == '\n' {
				return strings.TrimSuffix(b.String(), "\r"), nil
			}
			b.WriteByte(c)
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) && b.Len() > 0 {
				// A final line with no terminator is still a line.
				return strings.TrimSuffix(b.String(), "\r"), nil
			}
			return "", err
		}
	}
}

// logonVerdict is what the SCM's own logon says about the credential `install`
// is about to hand it, classified into the four answers that decide different
// things.
type logonVerdict int

const (
	// logonOK: the account can be logged on as a service with this password,
	// which is precisely what the SCM will do at every start.
	logonOK logonVerdict = iota
	// logonBadCredential: the account and password will not log on. A typo, a
	// disabled or expired account, a locked-out one.
	logonBadCredential
	// logonRightMissing: the credential is right and SeServiceLogonRight is
	// not granted. This is error 1069 at every start, found before the service
	// exists rather than after.
	logonRightMissing
	// logonUnverifiable: this platform has no way to ask. Everything but
	// Windows.
	logonUnverifiable
	// logonUnknown: the check failed for a reason this code does not
	// recognise, which is not a reason to refuse an install that would work.
	logonUnknown
)

// errLogonUnverifiable is what a platform with no SCM answers.
var errLogonUnverifiable = errors.New("only Windows can check a service logon")

// Win32 status codes LogonUser answers a service logon with.
//
// Declared here, as plain numbers, rather than taken from golang.org/x/sys/
// windows — that package builds on Windows only, and the classification below
// is a rule. A rule only the Windows runner can compile is a rule only the
// Windows runner checks, which is how the wrong spelling of NetworkService
// survived in this same area until #79's last round.
const (
	errorNoSuchUser          = 1317
	errorLogonFailure        = 1326
	errorAccountRestriction  = 1327
	errorInvalidLogonHours   = 1328
	errorInvalidWorkstation  = 1329
	errorPasswordExpired     = 1330
	errorAccountDisabled     = 1331
	errorNoneMapped          = 1332
	errorLogonTypeNotGranted = 1385
	errorAccountExpired      = 1793
	errorPasswordMustChange  = 1907
	errorAccountLockedOut    = 1909
)

// classifyServiceLogon turns what LogonUser returned into what install should
// do about it.
//
// The default is deliberately not a refusal. This check exists to stop an
// install that would produce a service failing every start; a status code this
// code has never seen is not evidence of that, and refusing on one would block
// an install that works for a reason nobody here anticipated. The two codes
// that *are* evidence are named, and everything else warns and proceeds.
func classifyServiceLogon(err error) logonVerdict {
	switch {
	case err == nil:
		return logonOK
	case errors.Is(err, errLogonUnverifiable):
		return logonUnverifiable
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return logonUnknown
	}
	switch uintptr(errno) {
	case errorLogonTypeNotGranted:
		return logonRightMissing
	case errorNoSuchUser, errorLogonFailure, errorAccountRestriction, errorInvalidLogonHours,
		errorInvalidWorkstation, errorPasswordExpired, errorAccountDisabled, errorNoneMapped,
		errorAccountExpired, errorPasswordMustChange, errorAccountLockedOut:
		return logonBadCredential
	default:
		return logonUnknown
	}
}

// splitServiceAccount splits the account the SCM will be handed into the two
// halves LogonUser wants.
//
// `DOMAIN\name` and `.\name` split on the backslash — "." being how Win32 names
// the local account database, and the spelling serviceAccountName already
// produces for a bare local name. A UPN (`name@domain`) is passed whole with no
// domain, which is what LogonUser documents.
//
// A bare name would be resolved against the domain rather than the machine,
// which is the trap serviceAccountName exists for, so nothing here is given one:
// the caller passes exactly what CreateService will get. Checking a different
// account from the one being registered is worse than not checking.
func splitServiceAccount(name string) (account, domain string) {
	if i := strings.LastIndex(name, `\`); i >= 0 {
		return name[i+1:], name[:i]
	}
	return name, ""
}

// serviceLogonRightAdvice names the right the SCM does not grant, and how to
// grant it.
//
// One text with two renderings, and #79 wrote it. It is the note `install`
// prints when it could not check, and the refusal it returns when the check
// says the right is missing; a second copy of it would be a second thing to
// keep true.
func serviceLogonRightAdvice(account string) []string {
	return []string{
		account + " does not have the \"Log on as a service\" right, which the SCM stores the",
		"password for but does not grant. Without it every start fails with error 1069, a",
		"logon failure. Grant it with:",
		"  secedit /export /cfg C:\\Windows\\Temp\\sec.cfg",
		"  # add " + account + " to SeServiceLogonRight in that file, then",
		"  secedit /configure /db secedit.sdb /cfg C:\\Windows\\Temp\\sec.cfg /areas USER_RIGHTS",
		"or add it under Local Security Policy > User Rights Assignment.",
	}
}

// serviceLogonRightNote is that advice as one of the notes `install` prints,
// for the case where nothing could check.
func serviceLogonRightNote(account string) []string {
	advice := serviceLogonRightAdvice(account)
	lines := []string{"  NOTE: " + advice[0]}
	for _, line := range advice[1:] {
		lines = append(lines, "        "+line)
	}
	return lines
}

// serviceLogonRightRefusal is that same advice as the refusal, returned before
// anything is registered.
//
// This is the failure #79 found and could only warn about: CreateService stores
// a password and grants nothing, so the service installs cleanly and every
// start fails with 1069. Asking the SCM's own logon first turns it from
// something an operator discovers afterwards into something install declines to
// build.
func serviceLogonRightRefusal(account string) string {
	return "refusing to register a service that cannot start: " +
		strings.Join(serviceLogonRightAdvice(account), "\n") +
		"\n\nNothing has been created, granted, or registered."
}

// badCredentialRefusal is what install says when the SCM's logon rejects the
// account and password it was about to store.
func badCredentialRefusal(account string, fromStdin bool, cause error) string {
	how := "Run `fleet-agent service install` again and retype it"
	if fromStdin {
		how = "Check the password on the pipe feeding --password-stdin"
	}
	return fmt.Sprintf("refusing to register a service that cannot start: %s could not be logged on with the password given: %v.\n\n"+
		"The SCM stores this credential and uses it at every start, so a service registered\n"+
		"with it would fail every start with error 1069. %s.\n\n"+
		"Nothing has been created, granted, or registered", account, cause, how)
}

// unverifiedLogonNote is what an operator is told when the pre-flight logon
// could not answer.
//
// Said rather than swallowed, and said rather than refused: the install goes
// ahead, so the operator has to know that the thing which would have caught a
// bad credential did not run.
func unverifiedLogonNote(account string, cause error) []string {
	return []string{
		fmt.Sprintf("note: could not check that %s can log on as a service before registering", account),
		fmt.Sprintf("      (%v), so this install proceeds without that check.", cause),
	}
}

// interactivePasswordAttempts is how many times an operator typing a password
// they cannot see gets to type it again.
//
// A retry is the whole point of checking before registering. Without it the
// check turns one mistyped character into a re-run of an elevated command, and
// #84's ask is that a typo fails *at the prompt*.
const interactivePasswordAttempts = 3

// passwordAttempts is how many times install will read a password before it
// gives up.
//
// A pipe holds one password. Asking again reads whatever came after it, which
// is nothing, so --password-stdin gets exactly one attempt: an installer that
// blocks on a second prompt is worse than one that fails. A rule rather than a
// branch inside the loop, because "the non-interactive path must not turn into
// a prompt" is the property, and a property nothing states is one nothing
// checks.
func passwordAttempts(fromStdin bool) int {
	if fromStdin {
		return 1
	}
	return interactivePasswordAttempts
}

// serviceCredential reads the account's password and checks it against the
// logon the SCM will perform, before anything on this host has changed.
//
// The check is the SCM's own: LogonUser with a service logon type is exactly
// what starting the service does, so it answers both questions that produce a
// service which fails every start — is this the right password, and does this
// account hold SeServiceLogonRight — and it answers them while the host is
// still untouched. Everything it can decide is decided here, above the first
// mkdir.
//
// It returns whether the logon was actually verified, because that decides
// whether `install` still has to warn about the right it could not check.
func serviceCredential(in io.Reader, out io.Writer, p *cli.Printer, account string, fromStdin bool) (password string, verified bool, err error) {
	// The spelling CreateService will be given, so the logon that is checked is
	// the logon that will happen. Checking a different account from the one
	// being registered would be worse than not checking.
	scmAccount := serviceAccountName(account, "windows")

	return credentialLoop(p, account, passwordAttempts(fromStdin), fromStdin,
		func() (string, error) { return servicePassword(in, out, account, fromStdin) },
		func(secret string) error { return verifyServiceLogon(scmAccount, secret) })
}

// credentialLoop is that sequence with both halves supplied: how a password is
// obtained, and what the platform says about it.
//
// Split from serviceCredential because the sequence is where the decisions are
// — which verdict refuses, which warns and proceeds, which gets another
// attempt, and what the operator is told in between — and neither half is
// reachable from any runner in this repository. readPassword needs a Windows
// console, and the check needs a real LSA and a real account's real password.
// Everything above them is a rule, and a rule reachable by nothing is a rule
// that could be deleted with the suite still green.
func credentialLoop(p *cli.Printer, account string, attempts int, fromStdin bool, read func() (string, error), verify func(string) error) (password string, verified bool, err error) {
	for attempt := 1; ; attempt++ {
		password, err = read()
		if err != nil {
			return "", false, err
		}
		logonErr := verify(password)
		switch classifyServiceLogon(logonErr) {
		case logonOK:
			return password, true, nil
		case logonRightMissing:
			// No retry: retyping a password does not grant a privilege, and
			// asking three times for one that was right the first time reads as
			// the password being the problem.
			return "", false, errors.New(serviceLogonRightRefusal(account))
		case logonUnverifiable:
			return password, false, nil
		case logonUnknown:
			for _, line := range unverifiedLogonNote(account, logonErr) {
				p.Println(line)
			}
			return password, false, nil
		case logonBadCredential:
			if attempt >= attempts {
				return "", false, errors.New(badCredentialRefusal(account, fromStdin, logonErr))
			}
			p.Printf("that password was not accepted for %s (%v); %d attempts left\n",
				account, logonErr, attempts-attempt)
		}
	}
}
