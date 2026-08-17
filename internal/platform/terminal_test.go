package platform_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// The local terminal, exercised against a real one.
//
// A pseudo-terminal is what makes these assertable without a person at a
// keyboard: it is a terminal by every test the platform applies, so raw mode,
// restoration and window size can all be driven and read back. What it cannot
// stand in for is a Windows console, which is a different object with different
// calls — see the skip in requireUnixTerminal.

func TestIsTerminal_IsFalseForAnOrdinaryFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "not-a-terminal")
	f, err := os.Create(path) //nolint:gosec // a path this test just built
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	assert.False(t, platform.IsTerminal(f.Fd()),
		"a regular file must not read as a terminal; this is the check that keeps `fleetctl shell` out of a script")
}

func TestTerminalState_ZeroValueRestoresNothing(t *testing.T) {
	t.Parallel()

	// The property that lets a client defer a restore before it knows whether
	// raw mode was ever entered.
	var zero platform.TerminalState
	assert.NoError(t, zero.Restore())

	var nilState *platform.TerminalState
	assert.NoError(t, nilState.Restore())
}

func TestTerminal_RawModeRoundTripsAndRestores(t *testing.T) {
	fd, tty := openTerminal(t)

	require.True(t, platform.IsTerminal(fd))

	before := terminalSettings(t, fd)
	state, err := platform.MakeRaw(fd)
	require.NoError(t, err)

	raw := terminalSettings(t, fd)
	assert.NotEqual(t, before, raw, "MakeRaw changed nothing; a terminal still echoing and still generating signals is not raw")

	require.NoError(t, state.Restore())
	assert.Equal(t, before, terminalSettings(t, fd),
		"the terminal was not put back exactly as it was found")

	// Restoring twice is what makes it safe for every exit path to restore
	// unconditionally rather than reason about whether another already has.
	assert.NoError(t, state.Restore())
	_ = tty
}

func TestTerminal_WindowSizeReadsWhatWasSet(t *testing.T) {
	fd, tty := openTerminal(t)

	require.NoError(t, tty.Resize(132, 50))
	columns, rows, err := platform.WindowSize(fd)
	require.NoError(t, err)
	assert.Equal(t, 132, columns)
	assert.Equal(t, 50, rows)
}

// TestTerminal_WatchReportsAResizeOnce covers the seam a shell client cannot do
// without, and the deduplication that keeps it from flooding the wire.
func TestTerminal_WatchReportsAResizeOnce(t *testing.T) {
	fd, tty := openTerminal(t)
	require.NoError(t, tty.Resize(100, 40))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sizes := make(chan [2]int, 16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		platform.WatchWindowSize(ctx, fd, func(columns, rows int) {
			sizes <- [2]int{columns, rows}
		})
	}()

	// The size is reported once before anything changes, because a client has
	// no other way to learn a size that changed while it was connecting.
	assert.Equal(t, [2]int{100, 40}, receiveSize(t, sizes))

	// The resize, and then the signal the kernel would have sent.
	//
	// It has to be sent by hand here, and that is a property of the test rather
	// than of the code: SIGWINCH goes to the foreground process group of the
	// terminal's own session, and this process is merely holding the master end
	// of a pty rather than sitting on the slave as its controlling terminal.
	// The size really did change and the signal really is the one that would
	// arrive, so the loop under test sees exactly what it sees in production.
	// The end-to-end suite covers the delivery itself, by resizing the terminal
	// a real `fleetctl shell` is attached to.
	require.NoError(t, tty.Resize(132, 50))
	deliverWindowChange(t)
	assert.Equal(t, [2]int{132, 50}, receiveSize(t, sizes))

	// And a second signal with nothing changed reports nothing: a drag produces
	// one of these per intermediate size, and a client that sent a resize for
	// each would spend a session's bandwidth on redundant messages.
	deliverWindowChange(t)
	assertNoSizeReported(t, sizes)

	cancel()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the watch did not return when its context was cancelled")
	}
}

// assertNoSizeReported fails if anything is reported within a short window.
//
// A negative assertion cannot be waited for, so this one is bounded by a short
// sleep rather than by a condition. It is the honest shape for "nothing
// happens": the alternative is a test that proves nothing at all.
func assertNoSizeReported(t *testing.T, sizes <-chan [2]int) {
	t.Helper()
	select {
	case size := <-sizes:
		t.Fatalf("a size was reported for a window that did not change: %v", size)
	case <-time.After(250 * time.Millisecond):
	}
}

// receiveSize waits for the next reported size.
func receiveSize(t *testing.T, sizes <-chan [2]int) [2]int {
	t.Helper()
	select {
	case size := <-sizes:
		return size
	case <-time.After(30 * time.Second):
		t.Fatal("no size was reported")
		return [2]int{}
	}
}
