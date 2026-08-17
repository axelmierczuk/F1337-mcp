//go:build !linux && !darwin && !windows

package host

import "runtime"

// platformResources is the fallback for a GOOS the agent is not shipped for.
// It keeps the package building everywhere rather than reporting figures it
// has no way to measure.
func platformResources(string) Resources {
	return Resources{CPUCores: uint32(runtime.NumCPU())} //nolint:gosec // core count does not overflow uint32
}
