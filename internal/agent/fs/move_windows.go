package fs

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isCrossDevice reports whether a failed rename failed because the two paths
// are on different volumes.
//
// It is not syscall.EXDEV. On Windows the syscall package's E-constants are
// synthetic values from its own error space, not the codes the OS returns, so
// matching EXDEV here would match nothing at all — the kind of check that
// compiles everywhere and works in one place. MoveFileEx reports
// ERROR_NOT_SAME_DEVICE for this, because os.Rename does not pass
// MOVEFILE_COPY_ALLOWED and so will not silently turn a rename into a copy.
func isCrossDevice(err error) bool {
	return errors.Is(err, windows.ERROR_NOT_SAME_DEVICE)
}

// errCrossDevice is the error this platform reports for it, for a test that
// needs to inject the real thing rather than a sentinel isCrossDevice would
// not recognise.
var errCrossDevice error = windows.ERROR_NOT_SAME_DEVICE
