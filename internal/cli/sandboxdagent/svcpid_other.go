//go:build !linux && !darwin && !windows

package sandboxdagent

// servicePID has no portable source on a GOOS the agent is not shipped for.
func servicePID(string) (int, bool) { return 0, false }
