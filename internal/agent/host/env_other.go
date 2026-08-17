//go:build !windows

package host

// probePassthrough is empty on Unix: PATH is the only variable a version probe
// needs, and everything else in the daemon's environment is exactly what it
// must not inherit.
var probePassthrough []string
