package platform

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// TestProcessGone pins which OpenProcess failures may be reported as
// ErrProcessNotFound.
//
// It is an internal test because the classification is the thing under test,
// not the syscall around it, and there is no portable way to make Windows hand
// back ERROR_ACCESS_DENIED for a process a CI runner is guaranteed to be
// unable to open.
//
// The case that matters is ERROR_ACCESS_DENIED. Folding it into "not found"
// tells a supervisor that a process it may not touch has gone away, so it
// stops trying to stop it and records a still-running process as dead — which
// is a failure reported as success, and the exact confusion ErrProcessNotFound
// exists to prevent.
func TestProcessGone(t *testing.T) {
	t.Parallel()

	gone := []windows.Errno{
		windows.ERROR_INVALID_PARAMETER,
		windows.ERROR_NOT_FOUND,
	}
	for _, err := range gone {
		require.Truef(t, processGone(err), "%v means the pid names no process", err)
	}

	stillThere := []windows.Errno{
		windows.ERROR_ACCESS_DENIED,
		windows.ERROR_INVALID_HANDLE,
		windows.ERROR_NOT_ENOUGH_MEMORY,
	}
	for _, err := range stillThere {
		require.Falsef(t, processGone(err), "%v says nothing about whether the process exists", err)
	}

	require.False(t, processGone(nil))
}
