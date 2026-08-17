package exec

import (
	"os"
	osexec "os/exec"
	"strings"
	"syscall"
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

// applyShellCommandLine hands cmd.exe the command line verbatim.
//
// os/exec otherwise builds the line by quoting each argument the way the C
// runtime parses them, and cmd.exe does not parse them that way. `cmd /c` gets
// a single argument holding the whole command, so it arrives quoted —
// `cmd /c "go build ./..."` — and cmd's documented recovery is to strip the
// first quote and the *last* quote on the line. That is harmless for a command
// with no quotes of its own and wrong the moment there is one:
// `echo "hi there"` comes back through it mangled, and the backslash-escaped
// quotes os/exec would emit are not something cmd understands at all.
//
// Setting CmdLine bypasses that construction, so the shell receives exactly the
// string the caller's arguments joined to, which is the whole contract of shell
// mode. Only the interpreter's own path is escaped, because it is a path and
// may contain spaces.
//
// argv is shellArgv's output: [comspec, "/c", command].
func applyShellCommandLine(cmd *osexec.Cmd, argv []string) {
	if len(argv) != 3 || cmd.SysProcAttr == nil {
		return
	}
	cmd.SysProcAttr.CmdLine = syscall.EscapeArg(argv[0]) + " /c " + argv[2]
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
