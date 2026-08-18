//go:build unix

package main

import (
	"os/exec"
	"syscall"
)

// processGroup is this process's group id, which the caller compares against
// the leader's pid to decide whether the command was isolated at all.
func processGroup() int { return syscall.Getpgrp() }

// detach puts a child in a session of its own, out of the reach of a signal
// aimed at its parent's process group.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
