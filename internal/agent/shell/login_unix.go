//go:build !windows

package shell

import "os"

// loginShellVar names the environment variable holding the account's preferred
// shell.
const loginShellVar = "SHELL"

// fallbackShell is what a session runs when nothing else names a shell.
//
// /bin/sh by absolute path, because it is the one interpreter every supported
// Unix has in the same place, and because a PATH search here would let whatever
// the daemon's environment happens to hold decide what "a shell" means.
const fallbackShell = "/bin/sh"

// loginShell picks the command a session with an empty argv runs.
//
// $SHELL from the daemon's own environment, then /bin/sh. The account's entry
// in the passwd database is deliberately not consulted, tempting though it is:
// a daemon commonly runs as a service account whose login shell is
// /usr/sbin/nologin or /bin/false, and starting *that* would give the operator
// a session that prints "This account is currently not available" and exits.
// The fallback has to be a shell that works, and an operator who wants a
// specific one names it — `fleetctl shell -- /bin/zsh`.
func loginShell() []string { return loginShellFor(os.Getenv) }
