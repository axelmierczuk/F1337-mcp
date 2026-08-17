//go:build !linux && !darwin && !windows

package fleetagent

// servicePID has no portable source on a GOOS the agent is not shipped for.
func servicePID() (int, bool) { return 0, false }
