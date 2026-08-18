package shell

import "os"

// loginShellVar names the environment variable holding the command interpreter.
// Windows has no login shell as such; COMSPEC is the nearest thing, and it is
// what `shell: true` resolves cmd.exe through on the exec path too.
const loginShellVar = "COMSPEC"

// fallbackShell is what a session runs when COMSPEC names nothing.
//
// cmd.exe rather than PowerShell, for the same reason /bin/sh rather than zsh
// on Unix: it is the interpreter that is present on every Windows install, in
// the same place, with no execution policy in front of it. PowerShell is
// usually the better shell and is one argument away — `fleetctl shell --
// powershell` — which is the right place for a preference to live.
const fallbackShell = `C:\Windows\system32\cmd.exe`

// loginShell picks the command a session with an empty argv runs.
func loginShell() []string { return loginShellFor(os.Getenv) }
