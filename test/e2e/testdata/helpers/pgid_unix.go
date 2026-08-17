//go:build unix

package main

import "syscall"

// processGroup is this process's group id, which the caller compares against
// the leader's pid to decide whether the command was isolated at all.
func processGroup() int { return syscall.Getpgrp() }
