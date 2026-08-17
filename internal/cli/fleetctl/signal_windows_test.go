package fleetctl

import (
	"errors"
	"testing"
)

// requireSelfSignal skips the signal-restoration test on Windows.
//
// A process there cannot deliver a signal to itself: the nearest equivalent,
// GenerateConsoleCtrlEvent, is aimed at a console process group and in a test
// binary that group includes the test runner. Faking one would assert on the
// fake, so the test says what it cannot cover instead — the restoration paths a
// Windows operator does reach (a normal exit, a dropped connection, a panic)
// are covered by the tests around it, and the same handler serves all four.
func requireSelfSignal(t *testing.T) {
	t.Helper()
	t.Skip("a Windows process cannot signal itself; see signal_windows_internal_test.go")
}

func deliverSignalToSelf() error {
	return errors.New("a Windows process cannot signal itself")
}
