//go:build !windows

package fs

import (
	"errors"
	"syscall"
)

// isCrossDevice reports whether a failed rename failed because the two paths
// are on different filesystems.
//
// EXDEV is the whole of it on Unix: rename(2) is a directory-entry operation
// and there is no directory spanning two mounts, so the kernel refuses rather
// than silently copying.
func isCrossDevice(err error) bool {
	return errors.Is(err, syscall.EXDEV)
}

// errCrossDevice is the error this platform reports for it, for a test that
// needs to inject the real thing rather than a sentinel isCrossDevice would
// not recognise.
var errCrossDevice error = syscall.EXDEV
