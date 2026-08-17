//go:build !linux && !darwin && !windows

package host

// kernelVersion has no portable source on a GOOS the agent is not shipped for.
func kernelVersion() string { return "" }
