package jail

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// openBeneath opens rel relative to root through openat2 with RESOLVE_BENEATH,
// which makes the kernel refuse any resolution step that would leave root —
// including a symlink swapped in after this jail checked the path.
//
// This is the only place in the package where the check and the use are the
// same operation. Everything else resolves, returns, and hopes.
func openBeneath(root, rel, resolved string, flag int, perm fs.FileMode) (*os.File, error) {
	if !atomicOpenSupported() {
		return os.OpenFile(resolved, flag, perm) //nolint:gosec // resolved was checked by Resolve; this is the documented fallback
	}
	if rel == "." {
		// The root itself. It was resolved at construction and is operator
		// controlled, so there is nothing for RESOLVE_BENEATH to protect
		// against, and passing "." to openat2 is needlessly subtle.
		return os.OpenFile(root, flag, perm) //nolint:gosec // root is operator-configured
	}

	dirFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("jail: opening root %q: %w", root, err)
	}
	defer func() { _ = unix.Close(dirFD) }()

	how := unix.OpenHow{
		Flags:   uint64(flag) | unix.O_CLOEXEC, //nolint:gosec // open flags are a bit set, not a signed quantity
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS,
	}
	// openat2 rejects a non-zero mode unless the flags create something. This
	// is stricter than open(2), which ignores mode instead.
	if flag&(unix.O_CREAT|unix.O_TMPFILE) != 0 {
		how.Mode = uint64(perm.Perm())
	}

	fd, err := unix.Openat2(dirFD, rel, &how)
	if err != nil {
		if errors.Is(err, unix.EXDEV) || errors.Is(err, unix.ELOOP) {
			// The kernel refused to resolve outside the root: either the
			// path changed under us since Resolve, or Resolve was wrong.
			// Either way the answer is no.
			return nil, ErrOutsideJail
		}
		return nil, fmt.Errorf("jail: openat2 %q beneath %q: %w", rel, root, err)
	}
	return os.NewFile(uintptr(fd), resolved), nil
}

// atomicOpenSupported probes openat2 once. Kernels before 5.6 return ENOSYS,
// and a seccomp filter that does not know the syscall — Docker's default
// profile did not, for a while — returns EPERM.
var atomicOpenSupported = sync.OnceValue(func() bool {
	fd, err := unix.Openat2(unix.AT_FDCWD, ".", &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH,
	})
	if err != nil {
		return !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EPERM)
	}
	_ = unix.Close(fd)
	return true
})
