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

// basePassthrough names the variables a Windows process cannot reliably start
// without, mirroring the toolchain probe's list in internal/agent/host.
//
// A bare PATH is enough on Unix and is not here: SystemRoot is where the loader
// finds the system DLLs, and a child launched without it fails to initialise —
// winsock in particular — before it ever reads its own arguments. COMSPEC is
// what `shell: true` resolves cmd.exe through, and PATHEXT is what makes a bare
// name resolve to a .exe or .bat at all.
//
// The list is deliberately short, and carries nothing that identifies a user or
// holds a credential — which is the reason the base environment exists rather
// than inheriting the daemon's.
var basePassthrough = []string{
	"SystemRoot",
	"SystemDrive",
	"windir",
	"COMSPEC",
	"PATHEXT",
	"NUMBER_OF_PROCESSORS",
	"PROCESSOR_ARCHITECTURE",
	"PROCESSOR_IDENTIFIER",
	"ProgramData",
	"ProgramFiles",
	"ProgramFiles(x86)",
	"CommonProgramFiles",
	"PUBLIC",
}
