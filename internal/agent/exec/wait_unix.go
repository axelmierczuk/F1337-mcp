//go:build !windows

package exec

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// terminatingSignal reports the signal that killed the process, if one did.
//
// The name carries the SIG prefix, matching ExecResult.signal's documented
// example ("SIGKILL"). It comes from x/sys rather than from
// syscall.Signal.String, which renders a description — "killed", "terminated" —
// and would put "SIGkilled" on the wire.
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
	// number is still the answer to "what killed it".
	return fmt.Sprintf("SIG%d", int(sig)), true
}
