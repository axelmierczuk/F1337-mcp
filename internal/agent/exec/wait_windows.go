package exec

import "os"

// terminatingSignal reports the signal that killed the process, if one did.
//
// Windows has no signals: a process is terminated with an exit code, and the
// one this agent's job objects use is 1. Reporting a signal name here would be
// inventing a Unix concept the platform does not have, so signaled is always
// false and callers read timed_out and exit_code instead.
func terminatingSignal(*os.ProcessState) (string, bool) { return "", false }
