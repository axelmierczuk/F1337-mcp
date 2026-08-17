//go:build unix

package process

import (
	"os"
	"strings"
	"syscall"
)

// exitSignal reports the signal that killed a process, in the runtime's own
// spelling: "killed", "terminated", "interrupt", and a bare number for a signal
// it has no name for. Not "KILL" or "TERM" — those are the request vocabulary,
// and inventing a translation back into it would make the field claim the
// process was stopped by this agent when it may have been stopped by anyone.
//
// A process that exited normally returns false, which is what separates
// "exited 1" from "killed by SIGKILL" in the status a caller reads. Both land
// in CRASHED; only one of them is worth looking for a bug in the process about.
func exitSignal(state *os.ProcessState) (string, bool) {
	status, ok := state.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() {
		return "", false
	}
	return strings.TrimPrefix(status.Signal().String(), "signal "), true
}
