package exec

import (
	"os"
	"strings"
)

// shellArgv wraps a command for the platform shell.
//
// Windows has no `sh -c`, so shell mode is `cmd /c` with the arguments joined
// into one command line for cmd.exe to re-parse. The same warning applies as on
// Unix, with an extra one on top: cmd.exe's quoting rules are not the C runtime
// rules os/exec applies to an ordinary argv, so a string that survives one may
// not survive the other. Shell mode is opt-in for these reasons.
func shellArgv(argv []string) []string {
	return []string{shellPath(), "/c", strings.Join(argv, " ")}
}

// shellPath resolves cmd.exe.
//
// COMSPEC names it on every Windows install, and falls back to the system
// directory when the daemon was started without one. It is resolved to an
// absolute path rather than left as "cmd" so that a PATH the request supplied
// cannot decide what shell mode means.
func shellPath() string {
	if comspec := os.Getenv("COMSPEC"); comspec != "" {
		return comspec
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return root + `\system32\cmd.exe`
}
