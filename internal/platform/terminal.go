package platform

import "context"

// The local terminal, from the client's side.
//
// The rest of this package is about the machine the agent runs on. This file is
// about the operator's own terminal, and it is here for the same reason
// everything else is: the calls are per-platform (termios ioctls on Unix,
// console modes on Windows), and a runtime GOOS branch would drag both sets of
// imports into every build.
//
// Nothing here is used by the agent. It exists for `fleetctl shell`, which has
// to put the operator's terminal into raw mode so that every keystroke —
// Ctrl-C included — travels to the remote session as a byte instead of being
// interpreted locally.

// TerminalState is a terminal's settings as they were before [MakeRaw] changed
// them. Restore puts them back.
//
// The zero value restores nothing and reports no error, so a client that never
// entered raw mode can defer Restore unconditionally.
type TerminalState struct {
	// fd is the descriptor the state was captured from.
	fd uintptr
	// saved is the platform's own representation, nil when nothing was
	// captured.
	saved *terminalMode
}

// Restore puts the terminal back the way it was.
//
// It is safe to call more than once and on a zero value: restoring twice is how
// a client that restores on its way out and again from a signal handler ends up
// correct rather than racing, and both paths have to exist. See the four exit
// paths documented on fleetctl's shell command.
func (s *TerminalState) Restore() error {
	if s == nil || s.saved == nil {
		return nil
	}
	return restoreTerminal(s.fd, s.saved)
}

// IsTerminal reports whether fd is an interactive terminal.
//
// It is the check `fleetctl shell` refuses on: a shell whose input is a pipe
// cannot be driven, and the session would sit at a prompt nobody can answer
// until the idle timeout reaped it.
func IsTerminal(fd uintptr) bool { return isTerminal(fd) }

// EnableTerminalOutput prepares fd for output written by a remote terminal.
//
// It is a no-op on Unix, where the settings [MakeRaw] applies belong to the
// terminal rather than to one descriptor of it, and where a terminal renders
// escape sequences without being asked. Windows needs the ask: a console that
// has not been put into virtual-terminal mode prints the escapes rather than
// acting on them, so a remote `vi` arrives as a screenful of `←[2J←[H`.
//
// The returned state restores whatever was changed, on the same terms as
// [MakeRaw].
func EnableTerminalOutput(fd uintptr) (*TerminalState, error) { return enableTerminalOutput(fd) }

// MakeRaw puts fd into raw mode and returns the state needed to undo it.
//
// Raw means the local terminal stops interpreting anything: no line buffering,
// no echo, and — the part that matters most here — no signal generation. Ctrl-C
// typed into a raw terminal is byte 0x03 delivered to the reader, not a SIGINT
// delivered to the process. That is what lets an interrupt reach the *remote*
// foreground process instead of killing the client that was carrying it.
//
// The caller must restore the state on every path out, including a panic. A CLI
// that leaves a terminal in raw mode has left the operator with a shell that
// does not echo what they type and does not respond to Ctrl-C, which is worse
// than never having run.
func MakeRaw(fd uintptr) (*TerminalState, error) { return makeRaw(fd) }

// WindowSize returns fd's terminal size in character cells.
func WindowSize(fd uintptr) (columns, rows int, err error) { return windowSize(fd) }

// WatchWindowSize reports fd's size to onChange whenever it changes, until ctx
// is cancelled. It returns when the watch has stopped.
//
// The mechanism is per-platform and the difference is not cosmetic: Unix
// delivers SIGWINCH, and Windows delivers nothing at all, so the size has to be
// polled there. Both are wrapped here so a caller does not grow a build tag of
// its own — and so the Windows half is a documented poll rather than a resize
// message that silently never arrives.
//
// onChange is called only when the size actually differs from the last one
// reported, so a caller may send a resize on every call without flooding the
// wire: a terminal drag produces a SIGWINCH per intermediate size, and a poll
// produces one per tick whether anything moved or not.
func WatchWindowSize(ctx context.Context, fd uintptr, onChange func(columns, rows int)) {
	watchWindowSize(ctx, fd, onChange)
}

// sizeReporter dedupes sizes for [WatchWindowSize]'s per-platform halves.
type sizeReporter struct {
	fd       uintptr
	onChange func(columns, rows int)
	cols     int
	rows     int
}

// report reads the current size and calls onChange when it has changed.
//
// A read failure is dropped rather than reported: the descriptor is the
// caller's own terminal, the only reasons this fails are that it has gone away
// or was never a terminal, and both are already fatal to the session in a way
// the caller will hear about from its own reads. Sending a resize built from a
// failed read would be worse — a zero size tells the remote terminal it has no
// rows, and every full-screen program on the far end draws nothing.
func (r *sizeReporter) report() {
	cols, rows, err := windowSize(r.fd)
	if err != nil || cols <= 0 || rows <= 0 {
		return
	}
	if cols == r.cols && rows == r.rows {
		return
	}
	r.cols, r.rows = cols, rows
	r.onChange(cols, rows)
}
