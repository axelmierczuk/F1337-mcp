//go:build !windows

package exec

import (
	"os"
	"os/signal"
	"syscall"
	"time"
)

// ignoreTermHelper ignores SIGTERM and waits, so a test can prove the
// escalation to SIGKILL actually happens rather than trusting that the polite
// signal was enough.
func ignoreTermHelper() int {
	signal.Ignore(syscall.SIGTERM)
	// Announce readiness, so the test kills a process that is already ignoring
	// the signal rather than racing the handler's installation.
	if _, err := os.Stdout.WriteString("ready\n"); err != nil {
		return 1
	}
	time.Sleep(600 * time.Second)
	return 0
}
