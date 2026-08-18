//go:build !windows

package fleetagent

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
)

// systemUserName is the dedicated account the Linux installer creates. It owns
// nothing except the agent's state and log directories.
const systemUserName = "fleet"

// legacySystemUserName is what systemUserName was before the fleet rebrand. A
// host installed back then already has this account, and its state and log
// directories are owned by it.
const legacySystemUserName = "sandboxd"

// requireElevation refuses an operation that will fail partway through
// without it, naming what to do instead.
//
// Failing early matters more than the message: half of `service install` is
// creating directories and a user, and discovering the missing privilege only
// at the point the unit file is written leaves those behind.
func requireElevation(action string) error {
	if isElevated() {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		exe = "fleet-agent"
	}
	return fmt.Errorf("`service %s` needs root: it writes to a system service directory and changes file ownership.\n\nRe-run it as:\n  sudo %s service %s",
		action, exe, action)
}

// isElevated reports whether this process can write system service
// directories and change file ownership.
func isElevated() bool { return os.Geteuid() == 0 }

// describeDefaultUser is the flag help for --user.
func describeDefaultUser() string {
	if runtime.GOOS == "darwin" {
		return "the invoking user"
	}
	return systemUserName
}

// defaultServiceUser picks the account the daemon runs as when --user is not
// given. It is never root.
//
// The two platforms differ because the right answer differs. On Linux a system
// daemon conventionally gets a dedicated system account, and useradd makes
// creating one a single command. On macOS creating a system account means a
// sequence of dscl calls and a hand-picked UID, and the account that already
// has the toolchains, the caches, and a home directory the agent can build in
// is the one the operator is sitting in front of — so that is what is used.
func defaultServiceUser() (string, error) {
	if runtime.GOOS == "darwin" {
		// invokingServiceUser, not a second copy of its rule. The refusal it
		// carries is the one thing between `sudo fleet-agent service install`
		// and an agent that runs every command a model issues as root, and
		// macOS used to have its own inline version of it — reachable only
		// from a suite running as root, therefore asserted by nothing, and
		// free to drift from the Windows one its own comment says it shares.
		if name := os.Getenv("SUDO_USER"); name != "" {
			return invokingServiceUser(name)
		}
		current, err := user.Current()
		if err != nil {
			return "", fmt.Errorf("determine the invoking user; pass --user with the account the agent should run as: %w", err)
		}
		return invokingServiceUser(current.Username)
	}
	return linuxServiceUser(accountExists), nil
}

// accountExists reports whether name resolves to an account on this host.
func accountExists(name string) bool {
	_, err := user.Lookup(name)
	return err == nil
}

// linuxServiceUser applies the same rule the config directories follow: a host
// that already has the pre-rebrand account keeps it.
//
// Defaulting to the new name on an upgraded host would grow a second system
// account per host and chown the state and log directories away from the
// account that owns them and is currently running as them.
//
// When both accounts exist the new name wins, which is the post-migration
// state: an operator who created `fleet` deliberately gets it, and the leftover
// `sandboxd` account is theirs to remove.
//
// Split out from defaultServiceUser and given the lookup rather than calling
// os/user directly because the rule turns on which system accounts exist, and a
// test cannot create one.
func linuxServiceUser(exists func(string) bool) string {
	if !exists(systemUserName) && exists(legacySystemUserName) {
		return legacySystemUserName
	}
	return systemUserName
}

// ensureServiceUser makes sure name exists, creating a locked-down system
// account when it does not and creation is permitted.
func ensureServiceUser(name string, create bool) error {
	if name == "" {
		return fmt.Errorf("no service account resolved; pass --user")
	}
	if _, err := user.Lookup(name); err == nil {
		return nil
	}
	if !create {
		return fmt.Errorf("service account %q does not exist and --create-user=false; create it or pass --user with an existing account", name)
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("service account %q does not exist.\n\nfleet does not create accounts on %s. Create one, or pass --user with an existing account",
			name, runtime.GOOS)
	}

	// useradd on most distributions, adduser on Alpine and other
	// BusyBox-based ones. Neither is guaranteed present, so the failure names
	// both and the account it was trying to create.
	attempts := [][]string{
		{"useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", name},
		{"adduser", "-S", "-D", "-H", "-s", "/sbin/nologin", name},
	}
	var lastErr error
	for _, argv := range attempts {
		path, err := exec.LookPath(argv[0])
		if err != nil {
			continue
		}
		out, err := exec.Command(path, argv[1:]...).CombinedOutput() //nolint:gosec // fixed argv, name is validated by the lookup above
		if err == nil {
			// Re-check rather than trust the exit status: a useradd that
			// succeeded but wrote nothing usable is worse than one that failed.
			if _, err := user.Lookup(name); err == nil {
				return nil
			}
			lastErr = fmt.Errorf("%s reported success but %q still does not resolve", argv[0], name)
			continue
		}
		lastErr = fmt.Errorf("%s: %w: %s", argv[0], err, out)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("neither useradd nor adduser is available")
	}
	return fmt.Errorf("create service account %q: %w\n\nCreate it manually and re-run, or pass --user with an existing account", name, lastErr)
}

// serviceAccessByOwnership records that on Unix, giving the service account
// access to a file is a matter of ownership — which `install` can do. On
// Windows it is ACLs, which it does not touch.
const serviceAccessByOwnership = true

// grantServiceUserAccess makes the enrollment material readable by the account
// the daemon will run as.
//
// files are given to it outright: they are the agent's own certificate, key, CA
// bundle and config, written 0600 by whoever ran `enroll`. dir, when non-empty,
// is a directory `enroll` created — it has to change hands too, because a file
// inside a 0700 directory owned by somebody else is not readable however its
// own mode reads. An empty dir means the caller judged the directory not
// fleet's to reassign.
//
// Ownership rather than a group and a wider mode: the account is already the
// one every command this agent runs executes as, so it can read the key by
// definition — it is the key it serves with. Widening the mode instead would
// hand the same material to every other member of that group.
func grantServiceUserAccess(name, dir string, files []string) error {
	uid, gid, err := lookupServiceIDs(name)
	if err != nil {
		return err
	}
	if uid == 0 {
		// The superuser already reads everything, and chowning to root on a
		// read-only or foreign-owned mount can fail for no useful reason.
		return nil
	}

	for _, path := range files {
		if err := os.Chown(path, uid, gid); err != nil {
			return fmt.Errorf("give %s access to %s: %w\n\nThe daemon reads this file as %s and will not start without it", name, path, err, name)
		}
	}
	if dir == "" {
		return nil
	}
	if err := os.Chown(dir, uid, gid); err != nil {
		return fmt.Errorf("give %s access to %s: %w", name, dir, err)
	}
	return nil
}

// chownToServiceUser gives the account ownership of a directory the daemon
// must be able to write as itself.
func chownToServiceUser(dir, name string) error {
	uid, gid, err := lookupServiceIDs(name)
	if err != nil {
		return err
	}
	// Walk, because MkdirAll may have created intermediate directories that
	// the daemon needs to traverse and write beneath.
	return filepath.WalkDir(dir, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(path, uid, gid)
	})
}

// lookupServiceIDs resolves the service account to the numeric ids chown takes.
func lookupServiceIDs(name string) (uid, gid int, err error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, fmt.Errorf("look up %q: %w", name, err)
	}
	uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse uid %q for %q: %w", u.Uid, name, err)
	}
	gid, err = strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse gid %q for %q: %w", u.Gid, name, err)
	}
	return uid, gid, nil
}

// currentAccount is how the platform names the account this process is running
// as.
func currentAccount() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

// inSessionZero is a Windows question; Unix has no session 0 to be isolated in.
func inSessionZero() bool { return false }

// executableAccessProblem reports why the service account may not be able to
// start the agent from exe.
//
// The same failure as the Windows one, from the other direction: `enroll` and
// `install` run as root, root reads /root/fleet-agent and ~/bin/fleet-agent
// perfectly well, and the unit then names a path whose 0700 ancestor the
// service account cannot traverse. systemd reports 203/EXEC, which names
// neither the path nor the account.
//
// Whether that refuses the install or warns is executableAccessIsFatal's.
func executableAccessProblem(exe, account string) string {
	uid, gid, err := lookupServiceIDs(account)
	if err != nil || uid == 0 {
		// An account that does not resolve is ensureServiceUser's to report,
		// and it has a better message for it. The superuser reads everything.
		return ""
	}
	return unixPathAccessProblem(exe, uid, gid)
}

// unixPathAccessProblem returns the first component of exe that uid/gid appears
// unable to get through, or "".
func unixPathAccessProblem(exe string, uid, gid int) string {
	for _, path := range append(ancestorDirs(exe), exe) {
		info, err := os.Stat(path)
		if err != nil {
			// Cannot tell. Saying nothing is right: this check exists to catch
			// a mistake, not to become one.
			return ""
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return ""
		}
		if hasExecuteBit(info.Mode(), int(st.Uid), int(st.Gid), uid, gid) {
			continue
		}
		if path == exe {
			return fmt.Sprintf("%s is mode %#o and owned by uid %d, so uid %d cannot execute it", path, info.Mode().Perm(), st.Uid, uid)
		}
		return fmt.Sprintf("%s is mode %#o and owned by uid %d, so uid %d cannot traverse it to reach %s", path, info.Mode().Perm(), st.Uid, uid, exe)
	}
	return ""
}

// hasExecuteBit reports whether uid/gid gets the execute bit on a file owned by
// ownerUID/ownerGID with mode.
func hasExecuteBit(mode os.FileMode, ownerUID, ownerGID, uid, gid int) bool {
	perm := mode.Perm()
	switch {
	case uid == ownerUID:
		return perm&0o100 != 0
	case gid == ownerGID:
		return perm&0o010 != 0
	default:
		return perm&0o001 != 0
	}
}

// ancestorDirs lists every directory above path, outermost first.
func ancestorDirs(path string) []string {
	var dirs []string
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		dirs = append(dirs, dir)
		if dir == filepath.Dir(dir) {
			break
		}
	}
	// Outermost first, so the message names the shallowest thing that is wrong
	// rather than the deepest.
	for i, j := 0, len(dirs)-1; i < j; i, j = i+1, j-1 {
		dirs[i], dirs[j] = dirs[j], dirs[i]
	}
	return dirs
}

// readPassword is never reached on Unix: no Unix service manager asks for an
// account's password, and serviceNeedsPassword says so. It exists so that the
// shared install path compiles, and errors rather than prompting so a future
// caller finds out instead of quietly echoing a password to a terminal.
func readPassword(io.Reader, io.Writer, string) (string, error) {
	return "", fmt.Errorf("a service account password is only ever needed by the Windows SCM")
}
