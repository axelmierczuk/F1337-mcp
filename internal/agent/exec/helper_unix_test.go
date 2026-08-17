//go:build !windows

package exec

import (
	"os/signal"
	"syscall"
)

// ignoreTerm makes this process decline SIGTERM, so a test can prove the
// escalation to SIGKILL actually happens rather than trusting that the polite
// signal was enough.
func ignoreTerm() { signal.Ignore(syscall.SIGTERM) }
