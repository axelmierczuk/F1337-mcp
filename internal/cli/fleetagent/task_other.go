//go:build !windows

package fleetagent

import (
	"fmt"
	"runtime"
)

// newScheduledTask is unreachable off Windows: resolveMechanism refuses
// MechanismTask there before anything asks for one. It returns an error rather
// than panicking so that a future caller which forgets gets a message instead
// of a crash.
func newScheduledTask(UnitParams) (registration, error) {
	return nil, fmt.Errorf("a logon-triggered Scheduled Task is a Windows mechanism; %s has no Task Scheduler", runtime.GOOS)
}

// scheduledTaskInstalled is always false off Windows.
func scheduledTaskInstalled() bool { return false }
