package platform

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
)

// terminalMode is a Windows console mode word.
type terminalMode = uint32

// pollWindowSize is how often the local console is asked whether it has been
// resized.
//
// Windows has no SIGWINCH, and no console API that reports a size change to a
// process that is not reading input records. Polling is what is left. A quarter
// of a second is below the threshold at which a redraw after a drag reads as
// lag, and it is one GetConsoleScreenBufferInfo call — a handle lookup and a
// struct copy — so the cost of being wrong about the interval is negligible in
// both directions.
const pollWindowSize = 250 * time.Millisecond

func isTerminal(fd uintptr) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(fd), &mode) == nil
}

// makeRaw turns off the console's own input processing.
//
// ENABLE_PROCESSED_INPUT is the one that matters: with it set, the console
// eats Ctrl-C and raises a control event locally instead of handing the byte to
// the reader, which is exactly the interception that would kill `fleetctl
// shell` rather than the remote foreground process. ENABLE_LINE_INPUT and
// ENABLE_ECHO_INPUT are the local line editor and echo, which the remote
// terminal is already doing.
//
// ENABLE_VIRTUAL_TERMINAL_INPUT is set rather than cleared: it makes the
// console encode arrow keys, function keys and modifiers as the escape
// sequences a Unix program on the far end understands, instead of the Windows
// input records nothing on the wire could carry.
func makeRaw(fd uintptr) (*TerminalState, error) {
	handle := windows.Handle(fd)
	var current uint32
	if err := windows.GetConsoleMode(handle, &current); err != nil {
		return nil, fmt.Errorf("platform: reading console mode: %w", err)
	}

	saved := current
	raw := current &^ (windows.ENABLE_ECHO_INPUT | windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT)
	raw |= windows.ENABLE_VIRTUAL_TERMINAL_INPUT
	if err := windows.SetConsoleMode(handle, raw); err != nil {
		return nil, fmt.Errorf("platform: putting the console into raw mode: %w", err)
	}
	return &TerminalState{fd: fd, saved: &saved}, nil
}

// enableTerminalOutput asks the console to interpret escape sequences.
//
// Without ENABLE_VIRTUAL_TERMINAL_PROCESSING a Windows console prints the
// escapes literally, so a remote `vi` arrives as a screenful of `←[2J←[H` and
// nothing is drawn. DISABLE_NEWLINE_AUTO_RETURN goes with it: the remote
// pseudo-terminal already sends a carriage return with every line feed, and the
// console adding its own produces a blank line between every pair of lines.
//
// A handle that is not a console — output redirected to a file — is left alone
// rather than failing the session. The operator asked for a shell; where its
// output goes is their business, and it is [IsTerminal] on the input side that
// decides whether a session can be driven at all.
func enableTerminalOutput(fd uintptr) (*TerminalState, error) {
	handle := windows.Handle(fd)
	var current uint32
	if err := windows.GetConsoleMode(handle, &current); err != nil {
		return &TerminalState{}, nil //nolint:nilerr // not a console: see the doc comment
	}

	saved := current
	if err := windows.SetConsoleMode(handle, current|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING|windows.DISABLE_NEWLINE_AUTO_RETURN); err != nil {
		return nil, fmt.Errorf("platform: enabling virtual terminal output: %w", err)
	}
	return &TerminalState{fd: fd, saved: &saved}, nil
}

func restoreTerminal(fd uintptr, saved *terminalMode) error {
	if err := windows.SetConsoleMode(windows.Handle(fd), *saved); err != nil {
		return fmt.Errorf("platform: restoring console mode: %w", err)
	}
	return nil
}

// windowSize reports the visible window rather than the screen buffer.
//
// They are different on Windows and the difference is the whole point: a
// console's buffer is routinely 9000 lines tall so it can be scrolled back
// through, and telling the remote terminal it has 9000 rows would put every
// full-screen program's status line 8976 lines below the bottom of the window.
func windowSize(fd uintptr) (int, int, error) {
	var info windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(windows.Handle(fd), &info); err != nil {
		return 0, 0, fmt.Errorf("platform: reading console size: %w", err)
	}
	return int(info.Window.Right - info.Window.Left + 1), int(info.Window.Bottom - info.Window.Top + 1), nil
}

// watchWindowSize polls, because Windows delivers no signal for this. See
// pollWindowSize.
func watchWindowSize(ctx context.Context, fd uintptr, onChange func(columns, rows int)) {
	reporter := &sizeReporter{fd: fd, onChange: onChange}

	ticker := time.NewTicker(pollWindowSize)
	defer ticker.Stop()

	reporter.report()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reporter.report()
		}
	}
}
