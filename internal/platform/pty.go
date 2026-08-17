package platform

import (
	"errors"
	"fmt"

	"github.com/aymanbagabas/go-pty"
)

// PTY is an allocated pseudo-terminal: a Unix pty pair, or a Windows ConPTY.
//
// It is the go-pty interface unchanged. Wrapping it would buy nothing and cost
// callers the CommandContext and Resize methods they need, so this package
// contributes the allocation policy and lets the interface through.
type PTY = pty.Pty

// PTYSupported reports whether this platform can allocate a pseudo-terminal.
func PTYSupported() bool {
	p, err := pty.New()
	if err != nil {
		return false
	}
	_ = p.Close()
	return true
}

// ReleasePTYChildEnd closes the parent's copy of the child's end of p, after
// the child has been started.
//
// It is what makes a read of the terminal end when the session does. On Unix a
// pty is a pair of descriptors and go-pty holds both: the child gets its own
// copies of the slave at fork, so the agent's copy is redundant afterwards, and
// leaving it open means the kernel still has a writer for the master — a read
// there blocks forever rather than reporting that the shell exited. Closing it
// is what a Unix program that spawns a terminal has always done, and it is why
// the last line of output arrives before the session's exit status rather than
// being discarded along with the terminal.
//
// It does nothing on Windows: a ConPTY is one pseudo-console handle and a pair
// of pipes, with no second descriptor for the parent to give up. The read there
// ends when the pseudo-console is closed, which is [PTY.Close].
//
// Call it once, after Start. Calling it before would hand the child a terminal
// that has already hung up.
func ReleasePTYChildEnd(p PTY) error { return releasePTYChildEnd(p) }

// OpenPTY allocates a pseudo-terminal. The caller closes it.
//
// A PTY is opt-in, per command. Most commands do not want one: with a
// terminal attached, stdout and stderr merge into a single stream that cannot
// be separated again, output arrives with CRLF line endings and ANSI escapes,
// and the caller loses the distinction that ExecService reports in
// OutputChunk.stream. What a PTY buys is the programs that behave differently
// without one — anything checking isatty, anything that wants to prompt, and
// the REPLs — so it is offered rather than imposed.
func OpenPTY() (PTY, error) {
	p, err := pty.New()
	if err != nil {
		if errors.Is(err, pty.ErrUnsupported) {
			return nil, fmt.Errorf("%w: allocating a pseudo-terminal", ErrUnsupported)
		}
		return nil, fmt.Errorf("platform: allocating a pseudo-terminal: %w", err)
	}
	return p, nil
}
