package exec

// homeVar is the variable naming the account's home directory. Windows calls
// it USERPROFILE; the toolchains that look for HOME on Unix look for this one
// here.
const homeVar = "USERPROFILE"

// caseInsensitiveEnv reports whether environment variable names fold. The
// Windows environment block is case-insensitive, so a request setting "path"
// must replace the base "PATH" rather than sit beside it.
const caseInsensitiveEnv = true

// defaultPath is used when the daemon was started without one. The system
// directories are named through SystemRoot's usual location because a service
// with no PATH at all cannot resolve any bare command name.
const defaultPath = `C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem`

// tempVars are the temporary-directory variables passed through when set.
// Windows tools read either.
var tempVars = []string{"TEMP", "TMP"}
