//go:build !windows

package shell

import (
	"os"
	"syscall"
)

// hangupSignals are what a closing terminal delivers, for the helper that
// refuses to take the hint.
func hangupSignals() []os.Signal { return []os.Signal{syscall.SIGHUP, syscall.SIGTERM} }
