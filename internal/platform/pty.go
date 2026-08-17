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
