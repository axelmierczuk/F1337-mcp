//go:build !windows

package exec

// homeVar is the variable naming the account's home directory.
const homeVar = "HOME"

// caseInsensitiveEnv reports whether environment variable names fold. Unix
// environments are case-sensitive: PATH and Path are two variables.
const caseInsensitiveEnv = false

// defaultPath is used when the daemon itself was started without a PATH, which
// is what systemd does unless the unit sets one. It is the conventional system
// path and deliberately holds no per-user directory.
const defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// tempVars are the temporary-directory variables passed through when set.
var tempVars = []string{"TMPDIR"}
