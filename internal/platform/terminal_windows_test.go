package platform_test

import (
	"testing"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// openTerminal has nothing to offer on Windows, and the tests that need one say
// so rather than asserting against a substitute.
//
// A ConPTY is not a console: its Fd is a pseudo-console handle, and
// GetConsoleMode — which is what IsTerminal, MakeRaw and WindowSize all go
// through here — does not answer for it. The object these tests would need is
// the console a real operator's terminal gives the process, and a test binary
// run by `go test` does not have one it can safely reconfigure. The Windows
// half of this file's subject is exercised by the CI matrix compiling it and by
// `fleetctl shell` on a Windows workstation; see the report on #43.
func openTerminal(t *testing.T) (uintptr, platform.PTY) {
	t.Helper()
	t.Skip("a ConPTY is not a console, and a test binary has no console it may reconfigure; see terminal_windows_test.go")
	return 0, nil
}

// terminalSettings is unreachable on Windows: every caller goes through
// openTerminal, which skips.
func terminalSettings(t *testing.T, _ uintptr) uint32 {
	t.Helper()
	t.Fatal("terminalSettings is unreachable on Windows")
	return 0
}

// deliverWindowChange has nothing to deliver on Windows, where the watch polls
// rather than waiting for a signal. Every caller is behind openTerminal, which
// skips.
func deliverWindowChange(t *testing.T) { t.Helper() }
