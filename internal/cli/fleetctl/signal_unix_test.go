//go:build !windows

package fleetctl

import (
	"os"
	"syscall"
	"testing"
)

// requireSelfSignal skips a test on a platform where a process cannot deliver a
// signal to itself.
func requireSelfSignal(*testing.T) {}

// deliverSignalToSelf sends this process a SIGINT.
//
// It is safe here because the session under test has already called
// signal.Notify for it: the handler catches it, and the default action — which
// would end the test binary — never runs. A test that signalled before the
// session was up would take the whole run down, which is why the caller waits
// for the session to be on the wire first.
func deliverSignalToSelf() error {
	return syscall.Kill(os.Getpid(), syscall.SIGINT)
}
