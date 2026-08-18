//go:build unix

package platform_test

import (
	"os"
	"testing"
	"time"

	"github.com/aymanbagabas/go-pty"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// TestReleasePTYChildEnd_GivesUpTheParentsCopyOfTheChildEnd covers the one call
// in the pty layer whose absence changes nothing that any other test looks at.
//
// A Unix pty is a pair and go-pty holds both ends. The child gets its own copies
// of the slave at fork, so the parent's copy is redundant afterwards — and while
// it is open the kernel still has a writer for the master, so a read there
// blocks rather than reporting that the command has finished. That read is a
// session's output pump: it is what tells ShellService the session's last output
// has arrived, and it is the goroutine that has to end before the session does.
//
// Two assertions, because one of them does not hold everywhere. That the parent
// has given the descriptor up is the mechanism and is true on every Unix. That
// a read then ends when the command does is the consequence, and it is only
// *distinguishable* on Linux: macOS revokes a controlling terminal when its
// session leader exits, which invalidates the parent's copy as a side effect and
// would let a build with this call missing look correct here.
func TestReleasePTYChildEnd_GivesUpTheParentsCopyOfTheChildEnd(t *testing.T) {
	if !platform.PTYSupported() {
		t.Skip("no pseudo-terminal available on this host")
	}

	tty, err := platform.OpenPTY()
	require.NoError(t, err)
	t.Cleanup(func() { _ = tty.Close() })

	unixPTY, ok := tty.(pty.UnixPty)
	require.True(t, ok, "a pty on this platform is a Unix pair")

	argv := echoArgv()
	cmd := tty.Command(argv[0], argv[1:]...)
	require.NoError(t, cmd.Start())

	// Reading from the start, and not after the wait below. A pty holds the
	// exit of a process that still has output queued on it — macOS blocks the
	// child inside exit until the master has been drained — so a test that
	// waited first would be waiting for itself.
	ended := make(chan error, 1)
	go func() {
		buf := make([]byte, 512)
		for {
			if _, err := tty.Read(buf); err != nil {
				ended <- err
				return
			}
		}
	}()

	// After Start, never before: this is the parent giving up its copy of the
	// child's end, and doing it first would hand the child a terminal that has
	// already hung up.
	require.NoError(t, platform.ReleasePTYChildEnd(tty))

	_, err = unixPTY.Slave().Write([]byte("x"))
	require.ErrorIs(t, err, os.ErrClosed,
		"the agent still holds the child's end of the session terminal, so the kernel still has a writer for the master")

	require.NoError(t, cmd.Wait())

	select {
	case <-ended:
	case <-time.After(30 * time.Second):
		t.Fatal("a read of the terminal did not end when the command did; a session's output pump would sit in " +
			"this read until the handler tore the terminal down, long after the shell had gone")
	}
}
