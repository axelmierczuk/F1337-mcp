//go:build !unix

package main

import "os/exec"

// processGroup has no meaning off Unix: Windows isolates a process tree with a
// job object rather than a group, and the scenarios that read this number skip
// there. Zero, so the helper still builds on every platform the suite compiles
// it for.
func processGroup() int { return 0 }

// detach has nothing to detach from off Unix: a child there is in the agent's
// job object whether it likes it or not, and the scenarios that need it out of
// the group skip on this platform.
func detach(*exec.Cmd) {}
