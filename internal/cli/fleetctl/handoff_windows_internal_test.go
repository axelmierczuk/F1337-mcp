//go:build windows

package fleetctl

import (
	"os"
	"os/signal"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// The hand-off on the one platform that has no exec.
//
// Everywhere else `fleetctl tui` *becomes* the helper — same pid, same process
// group, same terminal — and the end-to-end suite drives that on a real
// pseudo-terminal. Windows cannot: there is a second process, and the two
// things that costs are paid by hand in handoff_windows.go. The integration
// suite runs on Linux and macOS only, so without this file the one platform
// with its own implementation of the hand-off is the one platform where it is
// compiled and never run.

// TestOnWindowsTheHelpersExitStatusIsThisCommands.
//
// The exit status is the whole of what a wrapper process can lose. `fleetctl
// tui` on Unix cannot get this wrong, because the status the operator's shell
// reads *is* the view's; here it is a number this command has to carry out of a
// child and report as its own, and a script wrapping `fleetctl tui` cannot tell
// a view that failed from one that was never reached if every failure is 1.
func TestOnWindowsTheHelpersExitStatusIsThisCommands(t *testing.T) {
	// execHelper ignores Ctrl-C for as long as the helper holds the console,
	// and that is process-wide. Undone here so the rest of this package is not
	// run with interrupts ignored.
	t.Cleanup(func() { signal.Reset(os.Interrupt) })

	interpreter := commandInterpreter(t)

	t.Run("a helper that fails", func(t *testing.T) {
		err := execHelper(interpreter, []string{"/c", "exit", "17"})

		var status *exitStatus
		require.ErrorAs(t, err, &status,
			"a helper that exited non-zero did not come back as an exit status, so this command would report 1 for everything the view can fail at")
		require.Equal(t, 17, status.code, "the status the operator's shell reads is not the helper's own")
		require.Contains(t, err.Error(), helperName, "the status does not say whose it is")
	})

	t.Run("a helper that quits normally", func(t *testing.T) {
		require.NoError(t, execHelper(interpreter, []string{"/c", "exit", "0"}),
			"an operator quitting the view was reported as a failure")
	})
}

// commandInterpreter is a program every Windows host has, standing in for the
// helper. What is under test is what this command does with the status its
// child exited with, not what the child was.
func commandInterpreter(t *testing.T) string {
	t.Helper()

	path := os.Getenv("COMSPEC")
	if path == "" {
		path = filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no command interpreter to stand in for the helper: %v", err)
	}
	return path
}
