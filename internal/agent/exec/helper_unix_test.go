//go:build !windows

package exec

import (
	osexec "os/exec"
	"os/signal"
	"syscall"
)

// ignoreTerm makes this process decline SIGTERM, so a test can prove the
// escalation to SIGKILL actually happens rather than trusting that the polite
// signal was enough.
func ignoreTerm() { signal.Ignore(syscall.SIGTERM) }

// detachFromGroup puts the grandchild in a session of its own, so that the
// sweep — which aims at the command's process group — cannot reach it.
func detachFromGroup(cmd *osexec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
