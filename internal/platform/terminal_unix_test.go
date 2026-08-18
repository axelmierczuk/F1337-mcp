//go:build unix

package platform_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// openTerminal returns a descriptor that is a terminal, and the pty it belongs
// to so a test can change its size.
//
// The master end, not the slave: it is a terminal by every check this package
// makes, its termios is the pair's, and it needs no type assertion to reach.
func openTerminal(t *testing.T) (uintptr, platform.PTY) {
	t.Helper()

	if !platform.PTYSupported() {
		t.Skip("no pseudo-terminal available on this host")
	}
	tty, err := platform.OpenPTY()
	require.NoError(t, err)
	t.Cleanup(func() { _ = tty.Close() })

	return tty.Fd(), tty
}

// terminalSettings reads a terminal's settings, so a test can compare them
// before and after raw mode rather than trusting that a call returned nil.
func terminalSettings(t *testing.T, fd uintptr) unix.Termios {
	t.Helper()

	// Read through the ioctl directly rather than through the code under test:
	// a test that asked the implementation what the settings are would agree
	// with it about a wrong answer. testReadTermios is the same request number,
	// spelled again per platform beside this file.
	settings, err := unix.IoctlGetTermios(int(fd), testReadTermios) //nolint:gosec // a descriptor is small and non-negative
	require.NoError(t, err)
	return *settings
}

// deliverWindowChange sends this process the signal a terminal emulator's
// resize would produce.
//
// Safe to send unconditionally: SIGWINCH's default disposition is to be
// ignored, so a test that sends one while nothing is watching does nothing at
// all.
func deliverWindowChange(t *testing.T) {
	t.Helper()
	require.NoError(t, unix.Kill(os.Getpid(), unix.SIGWINCH))
}
