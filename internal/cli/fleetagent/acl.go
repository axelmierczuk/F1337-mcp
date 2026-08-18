package fleetagent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// serviceACL is the set of access-control entries `install` applies on Windows
// so that the account it just decided the daemon will run as can read what it
// was enrolled with and write the directories it owns.
//
// # Why this file is not _windows.go
//
// Nothing in it is a Windows API: it is argv and an exit code, the same as
// task.go. It used to live in svcuser_windows.go, which meant the strings
// deciding whether a service can read its own private key — `:(R)`,
// `:(OI)(CI)M`, `/T` — were composed where no runner could see them and were
// asserted by nothing anywhere. That is the shape #79's first audit round found
// three times over, and the grants are the half of this change that makes the
// new default work at all: `%ProgramData%\fleet` is created by an elevated
// install, so an ordinary operator token cannot write it and cannot read the
// certificate `enroll` left behind, and the daemon fails every start on its own
// files. Keeping the argv portable and the invocation injectable is what closes
// that gap; see run.
//
// The skip rules are here too, and for the same reason: "a built-in service
// identity is already admitted and is not granted anything more" is a decision
// about which accounts this command touches, not a Windows API call.
type serviceACL struct {
	// run invokes icacls.exe against path with these arguments. nil means
	// runIcacls, which is what every real install uses. A test supplies its
	// own, and that is the only way anything on any runner here sees the argv.
	run func(path string, args ...string) error
}

func (a serviceACL) icacls(path string, args ...string) error {
	if a.run != nil {
		return a.run(path, args...)
	}
	return runIcacls(path, args...)
}

// grantOwnedDir gives the account the ability to write a directory the daemon
// owns: its state and its logs.
//
// This used to be a no-op, on the reasoning that %ProgramData% inherits an ACL
// admitting the built-in service identities. That was true of the account the
// installer used to pick and false of the one it picks now: the directories are
// created by an elevated install, so their contents are the administrators' and
// an ordinary operator token cannot write them. The agent's first supervised
// process, or its own runtime report, would fail on a directory install had
// just made for it.
func (a serviceACL) grantOwnedDir(dir, account string) error {
	if dir == "" || !accountNeedsGrant(account) {
		return nil
	}
	// (OI)(CI) so new files and directories inherit it, M for modify, /T so the
	// grant reaches what an earlier install already put there.
	return a.icacls(dir, "/grant", account+":(OI)(CI)M", "/T")
}

// grantEnrollment makes the enrollment material readable by the account the
// daemon will run as.
//
// The Unix half of this hands over ownership; here it is an ACE. Same purpose,
// same failure without it: `enroll` writes agent.yaml and the private key under
// an elevated token, `install` is what decides somebody else will read them,
// and nothing else reconciles the two. An operator whose agent starts and then
// fails every connection on "permission denied" opening its own certificate has
// no way to know that is what happened.
//
// dir is granted read-and-traverse rather than modify: the daemon reads its
// enrollment directory, it does not write it. An empty dir means the caller
// judged the directory not fleet's to reassign.
func (a serviceACL) grantEnrollment(account, dir string, files []string) error {
	if !accountNeedsGrant(account) {
		return nil
	}
	for _, path := range files {
		if err := a.icacls(path, "/grant", account+":(R)"); err != nil {
			return fmt.Errorf("%w\n\nThe daemon reads this file as %s and will not start without it", err, account)
		}
	}
	if dir == "" {
		return nil
	}
	return a.icacls(dir, "/grant", account+":(OI)(CI)(RX)")
}

// accountNeedsGrant reports whether this account has to be given anything.
//
// The built-in identities are already admitted by what %ProgramData% inherits,
// and granting them more is not this command's business. No account at all is
// nothing to grant to, and handing icacls an empty principal would produce an
// ACE nobody asked for.
func accountNeedsGrant(account string) bool {
	return account != "" && !runsInSessionZero(account)
}

// runIcacls applies one ACL change, folding icacls' exit code into an error
// that carries what it printed.
func runIcacls(path string, args ...string) error {
	exe := "icacls.exe"
	if root := os.Getenv("SystemRoot"); root != "" {
		// Resolved rather than left to PATH, for the reason runSchtasks does
		// it: the installer runs with an environment this repository keeps
		// small, and a bare name would be one more thing to be missing.
		exe = filepath.Join(root, "System32", "icacls.exe")
	}
	out, err := exec.Command(exe, append([]string{path}, args...)...).CombinedOutput() //nolint:gosec // fixed argv; path and account come from the resolved install parameters
	if err != nil {
		return fmt.Errorf("grant access to %s: %w: %s", path, err, strings.TrimSpace(string(out)))
	}
	return nil
}
