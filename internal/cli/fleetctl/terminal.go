package fleetctl

import (
	"context"
	"errors"
	"io"
	"os"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// terminal is the operator's own terminal, as `fleetctl shell` uses it.
//
// It is an interface so a session can be driven without one. That is not
// tidiness: the properties this command has to get right — the terminal is
// restored on a dropped connection, on a signal, and on a panic on a pump
// goroutine — are exactly the ones that cannot be tested against a real
// terminal in a test process, because two of them end with the process gone.
type terminal interface {
	// Read returns the operator's keystrokes, uninterpreted.
	io.Reader
	// Write renders session output.
	io.Writer

	// makeRaw puts the terminal into raw mode and returns the undo. The undo is
	// a function rather than a state because Windows has two things to put back
	// — the input mode and the output mode — and a caller should not have to
	// know that.
	makeRaw() (restore func() error, err error)

	// size is the current window, in the shape the session's open message
	// carries. Nil when it could not be read, which the agent reads as "use the
	// conventional default".
	size() *sandboxdv1.ShellSize

	// watch calls onChange whenever the window is resized, until ctx is done.
	watch(ctx context.Context, onChange func(columns, rows int))
}

// osTerminal is the real one: this process's standard input and output.
type osTerminal struct {
	in  *os.File
	out *os.File
}

// openTerminal returns this process's terminal, refusing when there is not one.
//
// The refusal is the interesting half. A shell whose input is a pipe cannot be
// driven: the far end sits at a prompt nobody can answer until the agent's idle
// timeout reaps it, and the operator sees a command that hangs and then fails
// for a reason that has nothing to do with what they typed. It is also the
// shape a script reaches for when it wanted to run a command rather than open a
// terminal, so the message names the thing that does that.
func openTerminal() (*osTerminal, error) {
	term := &osTerminal{in: os.Stdin, out: os.Stdout}
	if !platform.IsTerminal(term.in.Fd()) {
		return nil, errors.New(
			"stdin is not a terminal, so there is nothing to drive an interactive shell with. " +
				"To run a command and collect its output, use the fleet_exec tool, or `fleetctl shell` from a terminal")
	}
	return term, nil
}

func (t *osTerminal) Read(p []byte) (int, error)  { return t.in.Read(p) }
func (t *osTerminal) Write(p []byte) (int, error) { return t.out.Write(p) }

// makeRaw puts the input side into raw mode and the output side into whatever
// state a remote terminal's escape sequences need.
//
// Both, and in that order, so a failure on the second does not leave the first
// applied: an operator whose terminal was put into raw mode by a command that
// then failed to start would be left typing into a shell that does not echo.
func (t *osTerminal) makeRaw() (func() error, error) {
	input, err := platform.MakeRaw(t.in.Fd())
	if err != nil {
		return nil, err
	}
	output, err := platform.EnableTerminalOutput(t.out.Fd())
	if err != nil {
		return nil, errors.Join(err, input.Restore())
	}
	return func() error { return errors.Join(output.Restore(), input.Restore()) }, nil
}

func (t *osTerminal) size() *sandboxdv1.ShellSize {
	columns, rows, err := platform.WindowSize(t.sizeFd())
	if err != nil {
		return nil
	}
	return &sandboxdv1.ShellSize{
		Columns: uint32(columns), //nolint:gosec // a terminal's dimensions are 16-bit on every platform that reports them
		Rows:    uint32(rows),    //nolint:gosec // as above
	}
}

func (t *osTerminal) watch(ctx context.Context, onChange func(columns, rows int)) {
	platform.WatchWindowSize(ctx, t.sizeFd(), onChange)
}

// sizeFd is the descriptor the window size is read from: the output side, which
// is where Windows keeps it, falling back to the input side for a session whose
// output is redirected.
//
// Unix would answer from either — the size belongs to the terminal rather than
// to a descriptor of it — but Windows would not: a console's dimensions come
// from the screen buffer, and asking the input handle for one fails.
func (t *osTerminal) sizeFd() uintptr {
	if platform.IsTerminal(t.out.Fd()) {
		return t.out.Fd()
	}
	return t.in.Fd()
}
