package jail

import (
	"io/fs"
	"os"
	"path/filepath"
)

// OpenFile opens a path inside the jail, with the flags and permissions of
// os.OpenFile.
//
// Prefer it over Resolve followed by os.OpenFile. On Linux it hands the
// containment check to the kernel via openat2 with RESOLVE_BENEATH, so there
// is no interval in which a component can be swapped for a symlink pointing
// out of the jail. Everywhere else it is exactly Resolve plus os.OpenFile, and
// carries the race documented on the package. [Atomic] says which.
//
// Resolve remains the right call for operations OpenFile cannot express —
// stat, readdir, rename, remove — and for deciding whether a path is
// acceptable before doing anything with it.
func (j *Jail) OpenFile(path string, flag int, perm fs.FileMode) (*os.File, error) {
	if !j.Configured() {
		return nil, pathError("open", path, ErrNotConfigured)
	}

	resolved, err := j.Resolve(path)
	if err != nil {
		return nil, err
	}

	if j.mode == modeUnconfined {
		f, err := os.OpenFile(resolved, flag, perm) //nolint:gosec // an unconfined jail is the operator's explicit choice
		if err != nil {
			return nil, pathError("open", path, err)
		}
		return f, nil
	}

	root, ok := j.rootFor(resolved)
	if !ok {
		// Resolve already checked this; reaching here would mean the two
		// disagreed, which is a bug, not a permission decision.
		return nil, pathError("open", path, ErrOutsideJail)
	}

	rel, err := filepath.Rel(root, resolved)
	if err != nil {
		return nil, pathError("open", path, err)
	}

	f, err := openBeneath(root, rel, resolved, flag, perm)
	if err != nil {
		return nil, pathError("open", path, err)
	}
	return f, nil
}

// Atomic reports whether OpenFile is free of the resolve-then-open race.
//
// It is true only on Linux, with a kernel providing openat2 (5.6 and later)
// and no seccomp filter blocking it. Callers that need to state their
// guarantees honestly — an audit record, or fleet_info — should report it
// rather than assume it.
func (j *Jail) Atomic() bool {
	return j.Confined() && atomicOpenSupported()
}
