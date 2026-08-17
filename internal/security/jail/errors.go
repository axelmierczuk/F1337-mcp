package jail

import (
	"errors"
	"fmt"
)

var (
	// ErrNotConfigured is returned by every method of a Jail that was never
	// constructed: the zero value, or a nil pointer.
	//
	// It exists so that the failure mode of forgetting to build a jail is a
	// refused request rather than an unconfined one. A jail that defaults to
	// permissive is worse than no jail at all, because the operator believes
	// there is one.
	ErrNotConfigured = errors.New("jail: not configured")

	// ErrNoRoots is returned by New when given no roots. Use Unconfined for
	// the deliberate no-jail state.
	ErrNoRoots = errors.New("jail: no allowed roots configured")

	// ErrOutsideJail is returned when a path resolves outside every root.
	ErrOutsideJail = errors.New("jail: path is outside the allowed roots")

	// ErrDanglingSymlink is returned when a path, or one of its parents, is a
	// symlink whose target does not exist.
	//
	// A dangling link is refused rather than followed lexically because there
	// is nothing to check containment against. Its target does not exist yet,
	// so it could be created — by anyone who can write to the target's parent
	// — after the check and before the use, pointing wherever they like.
	ErrDanglingSymlink = errors.New("jail: path traverses a dangling symlink")

	// ErrInvalidPath is returned for an empty path, or one in a namespace the
	// agent refuses to interpret. See platform.ClassifyPath.
	ErrInvalidPath = errors.New("jail: invalid path")
)

// PathError reports which path failed and why, without leaking the resolved
// location of a path that turned out to be outside the jail — a caller that
// probes with symlinks should not be told where they landed.
type PathError struct {
	// Op is the operation that failed: "resolve", "open".
	Op string
	// Path is the path as the caller supplied it.
	Path string
	// Err is one of the sentinels above, or an underlying OS error.
	Err error
}

func (e *PathError) Error() string {
	return fmt.Sprintf("jail: %s %q: %v", e.Op, e.Path, e.Err)
}

func (e *PathError) Unwrap() error { return e.Err }

func pathError(op, path string, err error) error {
	return &PathError{Op: op, Path: path, Err: err}
}
