//go:build !linux && !darwin && !windows

package host

import "runtime"

// platformResources is the fallback for a GOOS the agent is not shipped for.
// It keeps the package building everywhere rather than reporting figures it
// has no way to measure.
func platformResources(string) Resources {
	return Resources{CPUCores: uint32(runtime.NumCPU())} //nolint:gosec // core count does not overflow uint32
}

// disk has no portable implementation here, but probeDisk names it, so the
// unsupported platform answers "unknown" the same way every other figure does.
func disk(string) (total, available uint64) { return 0, 0 }
