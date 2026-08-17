//go:build !windows

package policy

import "os"

// pathSeparators are the characters that make a name a path rather than
// something to look up in PATH.
const pathSeparators = "/"

// patternEscapes reports whether a backslash escapes the next character in a
// rule pattern. It mirrors filepath.Match, which honours the escape everywhere
// except Windows.
const patternEscapes = true

// extensions is empty on Unix: an executable is one by its mode bits, not by
// its name.
func extensions(string) []string { return nil }

// findExecutable reports whether path is a file this agent can execute.
//
// The mode bits are checked rather than trusted to execve, so a directory or a
// data file named like a command produces "not an executable file" here
// instead of a bare EACCES from the kernel three layers down. Any of the three
// execute bits counts: which one applies depends on the account the daemon
// runs as and its groups, which this check does not attempt to evaluate — the
// kernel does that at exec time, and this only rules out what could not
// possibly run.
func findExecutable(path string, _ []string) (string, bool) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	if info.Mode().Perm()&0o111 == 0 {
		return "", false
	}
	return path, true
}
