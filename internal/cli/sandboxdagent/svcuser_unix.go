//go:build !windows

package sandboxdagent

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
)

// systemUserName is the dedicated account the Linux installer creates. It owns
// nothing except the agent's state and log directories.
const systemUserName = "sandboxd"

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
		exe = "sandboxd-agent"
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
		if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
			return name, nil
		}
		current, err := user.Current()
		if err != nil {
			return "", fmt.Errorf("determine the invoking user; pass --user with the account the agent should run as: %w", err)
		}
		if current.Username == "root" {
			return "", fmt.Errorf("refusing to default the service account to root: every command the agent runs would run as root.\n\nPass --user with a dedicated account, or --user root to accept that deliberately")
		}
		return current.Username, nil
	}
	return systemUserName, nil
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
		return fmt.Errorf("service account %q does not exist.\n\nsandboxd does not create accounts on %s. Create one, or pass --user with an existing account",
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

// chownToServiceUser gives the account ownership of a directory the daemon
// must be able to write as itself.
func chownToServiceUser(dir, name string) error {
	u, err := user.Lookup(name)
	if err != nil {
		return fmt.Errorf("look up %q: %w", name, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("parse uid %q for %q: %w", u.Uid, name, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("parse gid %q for %q: %w", u.Gid, name, err)
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
