package process

import "os"

// exitSignal always reports "not signalled" on Windows.
//
// Windows has no signals to be killed by. A terminated process reports the exit
// code TerminateProcess was called with — the agent uses 1 — and there is no
// separate fact to recover. Synthesising a "KILL" here would tell a caller the
// agent knows something it does not: an exit code of 1 from a job-object
// termination is indistinguishable from the process exiting 1 on its own.
func exitSignal(*os.ProcessState) (string, bool) { return "", false }
