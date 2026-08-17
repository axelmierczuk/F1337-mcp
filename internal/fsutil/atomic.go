// Package fsutil holds the small filesystem primitives sandboxd's on-disk
// state depends on: writing a file atomically, and taking an advisory lock
// across processes.
//
// Both exist because more than one process legitimately touches the same
// files. The MCP server, the operator CLI, and a second MCP server started
// against the same config directory all read-modify-write the registry, and
// `fleetctl enroll mint` writes the token store that `fleetctl serve`
// redeems from.
package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteAtomic writes data to path via a temp file in the same directory
// followed by a rename, so a reader never observes a partially written file
// and a crash mid-write leaves the previous contents intact.
//
// The temp file is created in the destination directory, not the system temp
// directory, because rename is only atomic within a filesystem.
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return fmt.Errorf("fsutil: create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // a no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsutil: write %s: %w", tmpPath, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsutil: chmod %s: %w", tmpPath, err)
	}
	// Flush to the storage device before the rename: without it a crash can
	// leave the rename durable but the contents not, which is the one failure
	// this function exists to prevent.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsutil: sync %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("fsutil: close %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("fsutil: rename %s to %s: %w", tmpPath, path, err)
	}
	return nil
}

// Lock takes an exclusive advisory lock covering path, blocking until it is
// available, and returns the function that releases it.
//
// The lock is held on a sidecar file (path + ".lock") rather than on path
// itself, because the files this guards are replaced by rename: a lock on the
// old inode would not be seen by a process that has already opened the new
// one.
//
// Advisory means cooperative. It serializes sandboxd's own processes against
// each other, which is what read-modify-write on a shared config file needs;
// it does not stop an unrelated program from writing the file.
func Lock(path string) (release func() error, err error) {
	lockPath := path + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, fmt.Errorf("fsutil: create directory for %s: %w", lockPath, err)
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // path derived from the caller's own config path
	if err != nil {
		return nil, fmt.Errorf("fsutil: open lock file %s: %w", lockPath, err)
	}
	if err := lockFile(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("fsutil: lock %s: %w", lockPath, err)
	}
	return func() error {
		// Closing the descriptor releases the lock on every platform this
		// targets; unlocking first keeps that explicit rather than implied.
		unlockErr := unlockFile(f)
		closeErr := f.Close()
		if unlockErr != nil {
			return fmt.Errorf("fsutil: unlock %s: %w", lockPath, unlockErr)
		}
		if closeErr != nil {
			return fmt.Errorf("fsutil: close lock file %s: %w", lockPath, closeErr)
		}
		return nil
	}, nil
}
