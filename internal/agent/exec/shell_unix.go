//go:build !windows

package exec

import "strings"

// shellArgv wraps a command for the platform shell.
//
// The arguments are joined with spaces and handed to `sh -c` as one string,
// which is what makes `shell: true` different in kind from the default: the
// shell re-parses that string, so quoting, globbing, redirection and word
// splitting all apply to values the caller may not have quoted. That is why it
// is opt-in and why the default path never builds one of these.
//
// /bin/sh is named by absolute path rather than looked up, so a PATH the
// request supplied cannot decide which interpreter "shell mode" means.
func shellArgv(argv []string) []string {
	return []string{shellPath, "-c", strings.Join(argv, " ")}
}

// shellPath is the interpreter shell mode routes through. Every supported Unix
// has one here; a host without it gets a not-found error naming this path,
// which is a better failure than a PATH search that finds something else.
const shellPath = "/bin/sh"
