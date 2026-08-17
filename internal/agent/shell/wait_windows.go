package shell

import "os"

// terminatingSignal reports the signal that ended the session, if one did.
//
// Windows has none. A process there is terminated with an exit code — the one
// this agent's job objects use is 1 — and there is no separate fact to recover,
// so signaled is always false and a caller reads exit_code and idle_timeout
// instead. Synthesising a "SIGHUP" would tell the operator the agent knows
// something it does not.
func terminatingSignal(*os.ProcessState) (string, bool) { return "", false }
