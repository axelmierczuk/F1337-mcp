//go:build !windows

package shell

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// terminatingSignal reports the signal that ended the session, if one did.
//
// The spelling carries the SIG prefix — "SIGHUP", "SIGKILL" — matching
// ExecResult.signal and ShellExit.signal, which document that form. It is
// deliberately not ProcessService's vocabulary, which is the runtime's
// ("hangup", "killed"): that field describes a supervised process an operator
// asked about, and this one describes a session ending, so each says it the way
// its own caller reads it.
//
// SIGHUP is the one that turns up most here. It is what the kernel sends when
// the session's terminal is closed, which is how a reaped session ends.
func terminatingSignal(state *os.ProcessState) (string, bool) {
	if state == nil {
		return "", false
	}
	status, ok := state.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() {
		return "", false
	}
	sig := status.Signal()
	if name := unix.SignalName(sig); name != "" {
		return name, true
	}
	// A real-time signal, or one this build of x/sys has no name for. The
	// number is still the answer to "what ended it".
	return fmt.Sprintf("SIG%d", int(sig)), true
}
