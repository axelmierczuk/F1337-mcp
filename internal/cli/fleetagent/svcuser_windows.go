package fleetagent

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
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

// serviceAccountName is the form the SCM wants.
//
// CreateService resolves a bare name against the domain, not the machine, so a
// local account has to be spelled `.\name` or the install fails on a
// domain-joined host with an error about a nonexistent account. The task
// scheduler wants the opposite — `.\name` is not a valid <UserId> — which is
// why this is applied to the service configuration only and not to the account
// the rest of `install` prints and reasons about.
func serviceAccountName(name string) string {
	if name == "" || runsInSessionZero(name) {
		return name
	}
	if strings.ContainsAny(name, `\/@`) {
		return name
	}
	return `.\` + name
}

// serviceAccessByOwnership records that access on Windows is governed by ACLs
// rather than by an owner, so nothing an installer does to ownership grants it.
const serviceAccessByOwnership = false

// chownToServiceUser gives the account the ability to write a directory the
// daemon owns: its state and its logs.
//
// This used to be a no-op, on the reasoning that %ProgramData% inherits an ACL
// admitting the built-in service identities. That was true of the account the
// installer used to pick and false of the one it picks now: the directories are
// created by an elevated install, so their contents are the administrators' and
// an ordinary operator token cannot write them. The agent's first supervised
// process, or its own runtime report, would fail on a directory install had
// just made for it.
func chownToServiceUser(dir, name string) error {
	if dir == "" || name == "" || runsInSessionZero(name) {
		return nil
	}
	// (OI)(CI) so new files and directories inherit it, M for modify, /T so the
	// grant reaches what an earlier install already put there.
	return runIcacls(dir, "/grant", name+":(OI)(CI)M", "/T")
}

// grantServiceUserAccess makes the enrollment material readable by the account
// the daemon will run as.
//
// The Unix half of this hands over ownership; here it is an ACE. Same purpose,
// same failure without it: `enroll` writes agent.yaml and the private key under
// an elevated token, `install` is what decides somebody else will read them,
// and nothing else reconciles the two. An operator whose agent starts and then
// fails every connection on "permission denied" opening its own certificate has
// no way to know that is what happened.
func grantServiceUserAccess(name, dir string, files []string) error {
	if name == "" || runsInSessionZero(name) {
		// The built-in identities are already admitted by what %ProgramData%
		// inherits, and granting them more is not this command's business.
		return nil
	}
	for _, path := range files {
		if err := runIcacls(path, "/grant", name+":(R)"); err != nil {
			return fmt.Errorf("%w\n\nThe daemon reads this file as %s and will not start without it", err, name)
		}
	}
	if dir == "" {
		return nil
	}
	return runIcacls(dir, "/grant", name+":(OI)(CI)(RX)")
}

// runIcacls applies one ACL change, folding icacls' exit code into an error
// that carries what it printed.
func runIcacls(path string, args ...string) error {
	exe := "icacls.exe"
	if root := os.Getenv("SystemRoot"); root != "" {
		exe = filepath.Join(root, "System32", "icacls.exe")
	}
	out, err := exec.Command(exe, append([]string{path}, args...)...).CombinedOutput() //nolint:gosec // fixed argv; path and account come from the resolved install parameters
	if err != nil {
		return fmt.Errorf("grant access to %s: %w: %s", path, err, strings.TrimSpace(string(out)))
	}
	return nil
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
// agent from exe, and that install should refuse rather than warn.
//
// It refuses because on Windows the answer is not a guess: a profile directory
// admits its owner, SYSTEM and the administrators, and nothing else. See
// windowsExecutableAccessProblem for what installing anyway costs.
func executableAccessProblem(exe, account string) (problem string, refuse bool) {
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
	return windowsExecutableAccessProblem(exe, account, usersRoot), true
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
