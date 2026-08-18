//go:build unix

package platform

import (
	"fmt"

	"github.com/aymanbagabas/go-pty"
)

// releasePTYChildEnd closes the slave. See the portable declaration.
//
// A pty that is not a Unix one cannot happen here — [OpenPTY] returns what
// pty.New returns, and that is a unixPty on every platform this file builds for
// — but the assertion is checked rather than forced, because a type assertion
// that panics inside an agent handler would take the daemon down over a library
// change that only cost it a tidy shutdown.
func releasePTYChildEnd(p PTY) error {
	unixPTY, ok := p.(pty.UnixPty)
	if !ok {
		return fmt.Errorf("%w: releasing the child end of a %T", ErrUnsupported, p)
	}
	if err := unixPTY.Slave().Close(); err != nil {
		return fmt.Errorf("platform: closing the child end of the pseudo-terminal: %w", err)
	}
	return nil
}
