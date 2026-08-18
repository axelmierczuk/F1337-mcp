package fleetagent

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// networkServiceAccount is a standing, password-less, non-administrative
// built-in identity.
//
// It used to be the default, and #74 is what that cost: it runs in session 0,
// which has been isolated from every interactive session since Vista, and it
// has no operator profile — so an agent installed under it sees no nvm, no
// rustup, no pyenv, no cargo, no scoop, no npm globals, and none of the
// credentials in %APPDATA% that git and the package registries read. It stays
// available for an operator who wants a confined agent and has weighed that.
// It is no longer what somebody gets by not choosing.
const networkServiceAccount = `NT AUTHORITY\NetworkService`

// requireElevation refuses an operation that will fail partway through
// without an elevated token.
func requireElevation(action string) error {
	if isElevated() {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		exe = "fleet-agent.exe"
	}
	return fmt.Errorf("`service %s` needs an elevated prompt: it registers a Windows service or a Scheduled Task and creates directories under ProgramData.\n\nRe-run it from an elevated PowerShell:\n  Start-Process -Verb RunAs %s -ArgumentList 'service %s'",
		action, exe, action)
}

// isElevated reports whether this process holds an elevated token.
func isElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

func describeDefaultUser() string { return "the invoking user" }

// defaultServiceUser picks the account the daemon runs as when --user is not
// given: the operator running the install, which is the same answer macOS
// gives and for the same reason.
//
// docs/service.md has always argued it, one platform over: "the account that
// already has the toolchains, the caches, and a home directory the agent can
// build in is the one the operator is sitting in front of". That is not a
// statement about launchd. It was simply never applied here.
func defaultServiceUser() (string, error) {
	current, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("determine the invoking user; pass --user with the account the agent should run as: %w", err)
	}
	return invokingServiceUser(current.Username)
}

// ensureServiceUser accepts the built-in service identities as they are and
// verifies that any other account actually exists.
//
// Creating a Windows account non-interactively means choosing and storing a
// password, which is a worse outcome than telling the operator to create one.
func ensureServiceUser(name string, _ bool) error {
	if name == "" {
		return fmt.Errorf("no service account resolved; pass --user")
	}
	if runsInSessionZero(name) {
		return nil
	}
	if _, err := user.Lookup(name); err != nil {
		return fmt.Errorf("service account %q does not resolve: %w\n\nCreate it, or pass --user with an existing account. Built-in options are %s and NT AUTHORITY\\LocalService — both of which run in session 0 and cannot see a per-user toolchain",
			name, err, networkServiceAccount)
	}
	return nil
}

// chownToServiceUser gives the account the ability to write a directory the
// daemon owns: its state and its logs. The grant itself is serviceACL's, which
// is where the argv can be asserted from every runner rather than only from an
// elevated Windows one.
func chownToServiceUser(dir, name string) error {
	return serviceACL{}.grantOwnedDir(dir, name)
}

// grantServiceUserAccess makes the enrollment material readable by the account
// the daemon will run as. See serviceACL.grantEnrollment.
func grantServiceUserAccess(name, dir string, files []string) error {
	return serviceACL{}.grantEnrollment(name, dir, files)
}

// currentAccount is how the platform names the account this process is running
// as, which is not always what the service definition asked for.
func currentAccount() string {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		if name, err := user.Current(); err == nil {
			return name.Username
		}
		return ""
	}
	account, domain, _, err := u.User.Sid.LookupAccount("")
	if err != nil {
		return u.User.Sid.String()
	}
	if domain != "" {
		return domain + `\` + account
	}
	return account
}

// currentAccountSID is the security identifier of the account this process is
// running as, which is the only spelling of it that does not change.
//
// currentAccount is a *name*, and LookupAccountSid returns the display name the
// running installation uses, which is localised: the account #74 is about is
// spelled one way on an English host, another on a German one, and another
// again on a French one. There is no list of spellings to keep up to date and
// no amount of folding that reaches them. The fifth audit round found this same
// verdict unable to fire because the name had a space in it; one locale over it
// could not fire at all.
//
// So the report carries the SID beside the name and the judgement is drawn from
// whichever of the two it recognises. S-1-5-18, -19 and -20 are the same three
// strings on every installation of Windows in every language, which is the
// reason Microsoft's own guidance is to compare SIDs and never names.
func currentAccountSID() string {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return ""
	}
	return u.User.Sid.String()
}

// inSessionZero reports whether this process is in Windows session 0.
//
// Session 0 is the whole of #74. It holds the services and nothing an operator
// can see, it has had no interactive desktop since Vista, and a process in it
// reaches no per-user installation. Asked of the process rather than inferred
// from the account name, because the account is what somebody configured and
// the session is what actually happened.
func inSessionZero() bool {
	var session uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session); err != nil {
		return false
	}
	return session == 0
}

// executableAccessProblem reports why the account may not be able to start the
// agent from exe. Whether that refuses the install or warns is
// executableAccessIsFatal's; see windowsExecutableAccessProblem for what
// installing anyway costs.
func executableAccessProblem(exe, account string) string {
	usersRoot := ""
	if profile := os.Getenv("USERPROFILE"); profile != "" {
		usersRoot = filepath.Dir(profile)
	}
	if usersRoot == "" {
		drive := os.Getenv("SystemDrive")
		if drive == "" {
			drive = "C:"
		}
		usersRoot = drive + `\Users`
	}
	return windowsExecutableAccessProblem(exe, account, usersRoot)
}

// readPassword reads a password from the console without echoing it.
//
// The SCM will not create a service under a named account without one, and this
// is the only place the agent ever handles it: it goes to CreateService, which
// stores it as a machine-bound LSA secret, and then out of scope. Nothing
// writes it to a file, an environment variable, or a log line.
func readPassword(in io.Reader, out io.Writer, prompt string) (string, error) {
	file, isFile := in.(*os.File)
	if !isFile {
		return readLine(in)
	}
	handle := windows.Handle(file.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		// Not a console: a pipe, which is how an unattended installer supplies
		// it. Read it plainly rather than refusing.
		return readLine(in)
	}
	if _, err := fmt.Fprint(out, prompt); err != nil {
		return "", err
	}
	if err := windows.SetConsoleMode(handle, mode&^windows.ENABLE_ECHO_INPUT); err != nil {
		return "", fmt.Errorf("turn off console echo: %w", err)
	}
	defer func() { _ = windows.SetConsoleMode(handle, mode) }()

	line, err := readLine(in)
	_, _ = fmt.Fprintln(out)
	return line, err
}

// readLine reads one line, without the terminator.
func readLine(in io.Reader) (string, error) {
	line, err := bufio.NewReader(in).ReadString('\n')
	line = strings.TrimRight(line, "\r\n")
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if line == "" {
		return "", errors.New("no password was given")
	}
	return line, nil
}
