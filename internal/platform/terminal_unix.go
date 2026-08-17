//go:build unix

package platform

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"golang.org/x/sys/unix"
)

// terminalMode is a Unix terminal's settings.
type terminalMode = unix.Termios

func isTerminal(fd uintptr) bool {
	_, err := unix.IoctlGetTermios(int(fd), ioctlReadTermios) //nolint:gosec // a descriptor is small and non-negative; the conversion is the API's own shape
	return err == nil
}

// makeRaw clears every local interpretation of the input stream.
//
// The flags are the POSIX raw set — the same one cfmakeraw(3) applies — and
// each group is here for a reason worth naming:
//
//   - Iflag: no CR/NL translation and no XON/XOFF, so Ctrl-S and Ctrl-Q reach
//     the remote program instead of freezing the local terminal, and so bytes
//     arrive as they were typed.
//   - Oflag: no output post-processing. The remote pseudo-terminal already
//     turns "\n" into "\r\n" with its own line discipline, and doing it twice
//     is what produces the staircase every naive terminal client starts with.
//   - Lflag: no echo, no line buffering, and — the one that matters most — no
//     ISIG. With ISIG cleared, Ctrl-C is byte 0x03 handed to the reader rather
//     than a SIGINT delivered to this process, which is what carries an
//     interrupt to the remote foreground process instead of killing the client.
//   - Cflag: eight-bit characters with no parity, so a terminal configured for
//     something else does not strip the high bit off UTF-8.
//
// VMIN 1 and VTIME 0 make a read return as soon as one byte is available, which
// is what keeps typing feeling immediate rather than arriving in blocks.
func makeRaw(fd uintptr) (*TerminalState, error) {
	current, err := unix.IoctlGetTermios(int(fd), ioctlReadTermios) //nolint:gosec // see isTerminal
	if err != nil {
		return nil, fmt.Errorf("platform: reading terminal settings: %w", err)
	}

	saved := *current
	raw := *current
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP |
		unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	raw.Oflag &^= unix.OPOST
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0

	if err := unix.IoctlSetTermios(int(fd), ioctlWriteTermios, &raw); err != nil { //nolint:gosec // see isTerminal
		return nil, fmt.Errorf("platform: putting the terminal into raw mode: %w", err)
	}
	return &TerminalState{fd: fd, saved: &saved}, nil
}

// enableTerminalOutput has nothing to do on Unix: a terminal renders escape
// sequences without being asked, and the output flags belong to the same
// termios makeRaw already set. See the portable declaration.
func enableTerminalOutput(uintptr) (*TerminalState, error) { return &TerminalState{}, nil }

func restoreTerminal(fd uintptr, saved *terminalMode) error {
	if err := unix.IoctlSetTermios(int(fd), ioctlWriteTermios, saved); err != nil { //nolint:gosec // see isTerminal
		return fmt.Errorf("platform: restoring terminal settings: %w", err)
	}
	return nil
}

func windowSize(fd uintptr) (int, int, error) {
	ws, err := unix.IoctlGetWinsize(int(fd), unix.TIOCGWINSZ) //nolint:gosec // see isTerminal
	if err != nil {
		return 0, 0, fmt.Errorf("platform: reading terminal size: %w", err)
	}
	return int(ws.Col), int(ws.Row), nil
}

// watchWindowSize waits for SIGWINCH.
//
// The size is reported once before the first signal, because the caller has no
// other way to learn a size that changed between it reading one and this watch
// starting — a window resized during a TLS handshake would otherwise stay wrong
// until the operator resized it again.
func watchWindowSize(ctx context.Context, fd uintptr, onChange func(columns, rows int)) {
	reporter := &sizeReporter{fd: fd, onChange: onChange}

	// Buffered, and Notify drops rather than blocks: a burst of SIGWINCH from
	// one drag only ever needs to result in one size being read, and it is the
	// last one that is right.
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, unix.SIGWINCH)
	defer signal.Stop(ch)

	reporter.report()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			reporter.report()
		}
	}
}
