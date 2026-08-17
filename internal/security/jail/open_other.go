//go:build !linux

package jail

import (
	"io/fs"
	"os"
)

// openBeneath is the portable fallback: the path was checked by Resolve, and
// is now opened by name. Between those two steps a component can be replaced
// with a symlink pointing anywhere, and nothing here would notice.
//
// macOS has no openat2 and no RESOLVE_BENEATH. Windows has no symlinks in the
// Unix sense but does have directory junctions, which are followed by the same
// APIs. Both are left with the race; see the package documentation.
func openBeneath(_, _, resolved string, flag int, perm fs.FileMode) (*os.File, error) {
	return os.OpenFile(resolved, flag, perm) //nolint:gosec // resolved was checked by Resolve; this is the documented fallback
}

func atomicOpenSupported() bool { return false }
