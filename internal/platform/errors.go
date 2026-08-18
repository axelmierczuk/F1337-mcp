package platform

import (
	"errors"
	"fmt"
)

var (
	// ErrUnsupported reports that an operation has no implementation on this
	// platform. It wraps the standard errors.ErrUnsupported so callers may
	// test for either.
	ErrUnsupported = fmt.Errorf("platform: operation not supported on this platform: %w", errors.ErrUnsupported)

	// ErrProcessNotFound reports that no process with the requested pid
	// exists. It is returned rather than a bare OS error so callers can
	// distinguish "gone" from "could not tell", which is the distinction the
	// supervisor's re-adoption logic turns on.
	ErrProcessNotFound = errors.New("platform: process not found")

	// ErrSignalUnsupported reports that a portable signal has no equivalent on
	// this platform. On Windows only SignalTerm, SignalKill and SignalInt mean
	// anything; the job control signals do not exist.
	ErrSignalUnsupported = fmt.Errorf("platform: signal not supported on this platform: %w", errors.ErrUnsupported)

	// ErrNoProcess reports that a ProcessGroup method needing a live process
	// was called before Adopt, or after the group was closed.
	ErrNoProcess = errors.New("platform: process group has no process attached")

	// ErrGroupClosed reports that a ProcessGroup was used after Close.
	//
	// A sentinel rather than a bare error because a caller can reach it
	// without having made a mistake: a handler that releases its group on the
	// way out, while a goroutine of its own is still waiting for the leader to
	// exit, has given the group up rather than failed at anything. Telling
	// that apart from a signal that could not be delivered is what keeps a
	// broken-guarantee warning meaning one.
	ErrGroupClosed = errors.New("platform: process group is closed")
)
