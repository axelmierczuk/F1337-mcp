//go:build !windows

package shell

import "github.com/axelmierczuk/fleet-mcp/internal/platform"

// processRunning reports whether a pid names a process that is still running.
//
// On Unix the question and the answer are the same thing: a reaped process is
// gone from the pid table, so "does it exist" is "is it running".
func processRunning(pid int) bool { return platform.ProcessExists(pid) }
