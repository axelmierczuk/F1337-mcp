package fs

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/axelmierczuk/fleet-mcp/internal/security/jail"
)

// atomicFile is a file being built beside its target, to be renamed over it
// when it is complete.
//
// The guarantees, in the order they matter:
//
//  1. The target is either the old contents or the new contents, never a
//     prefix of the new ones. A reader that opens the target mid-write sees the
//     old file; the rename swaps the name over in one step.
//  2. An abandoned write leaves the original untouched. Close on an
//     uncommitted writer removes the temp file and never touches the target, so
//     a transfer that dies halfway — a cancelled RPC, a killed client, a full
//     disk — costs nothing.
//  3. The contents are on the device before the name is. Commit fsyncs the
//     temp file before renaming, so a crash cannot leave the rename durable and
//     the bytes not.
//
// The temp file is a sibling of the target, not a file in the system temp
// directory, and that is the whole reason this type exists rather than a call
// to os.CreateTemp. Rename is only atomic within a filesystem. Across one it is
// a copy, and a copy interrupted halfway is precisely the truncated file
// guarantee 1 exists to prevent — on a host where /tmp is tmpfs and the target
// is on the data volume, that is every write.
type atomicFile struct {
	jail *jail.Jail
	log  *slog.Logger

	// target is the resolved destination path.
	target string
	// mode is what the target ends up with, applied just before the rename.
	mode fs.FileMode
	// tmpPath is the sibling being written.
	tmpPath string
	file    *os.File

	committed bool
	closed    bool
}

// tempFileMode is what a partly written file is created with, regardless of the
// mode it will end up with.
//
// It is narrow because the temp file is readable at its own name for as long as
// the transfer takes, and a file destined to be 0644 has no reason to be
// world-readable while it is still half of one. Commit applies the real mode
// just before the rename. It is writable because a read-only temp file cannot be
// removed on Windows, which would turn an abandoned write into a stray file
// beside the target — the one thing the cleanup exists to prevent.
const tempFileMode fs.FileMode = 0o600

// createAtomic opens a temp file beside target, which must already be a
// jail-resolved path.
//
// mode is the mode the target ends up with, applied by Commit. A caller
// preserving an existing file's mode passes that mode; a caller creating a new
// file passes the requested one.
func createAtomic(j *jail.Jail, log *slog.Logger, target string, mode fs.FileMode) (*atomicFile, error) {
	dir := filepath.Dir(target)
	base := filepath.Base(target)
	// Long basenames are truncated so the temp name stays inside NAME_MAX; a
	// 255-byte filename plus a suffix is otherwise ENAMETOOLONG on Linux.
	if len(base) > 64 {
		base = base[:64]
	}

	for attempt := 0; attempt < 10; attempt++ {
		tmpPath := filepath.Join(dir, "."+base+".fleet-"+randomSuffix()+".tmp")
		// Through the jail rather than os.OpenFile: on Linux this is an openat2
		// with RESOLVE_BENEATH, so the temp file cannot be redirected out of the
		// jail by a component swapped for a symlink between the resolve and the
		// open.
		f, err := j.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, tempFileMode)
		if err != nil {
			if errors.Is(err, fs.ErrExist) {
				continue
			}
			return nil, fmt.Errorf("create temp file beside %s: %w", target, err)
		}
		return &atomicFile{jail: j, log: log, target: target, mode: mode, tmpPath: tmpPath, file: f}, nil
	}
	return nil, fmt.Errorf("create temp file beside %s: ten names in a row were taken", target)
}

// Write appends to the temp file.
func (a *atomicFile) Write(p []byte) (int, error) { return a.file.Write(p) }

// Name returns the path of the temp file, for diagnostics and tests.
func (a *atomicFile) Name() string { return a.tmpPath }

// Commit flushes the temp file to the device and renames it over the target.
//
// After it returns nil the writer owns nothing: Close becomes a no-op, and the
// temp file is gone because it is now the target.
func (a *atomicFile) Commit() error {
	// The mode is applied here rather than trusted from the open, because the
	// process umask masks the permissions O_CREATE was given. A file the caller
	// asked to be 0644 comes out 0644 whatever the daemon's umask is.
	if runtime.GOOS != "windows" {
		if err := a.file.Chmod(a.mode); err != nil {
			_ = a.file.Close()
			return fmt.Errorf("chmod %s: %w", a.tmpPath, err)
		}
	}
	if err := a.file.Sync(); err != nil {
		_ = a.file.Close()
		return fmt.Errorf("sync %s: %w", a.tmpPath, err)
	}
	if err := a.file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", a.tmpPath, err)
	}
	if err := os.Rename(a.tmpPath, a.target); err != nil {
		return fmt.Errorf("rename %s to %s: %w", a.tmpPath, a.target, err)
	}
	a.committed = true

	// The rename is durable only once the directory entry is. Failing the RPC
	// over it would be wrong — the file is in place and readable — so it is
	// reported rather than returned. On Windows there is no directory handle to
	// flush; see syncDir.
	if err := syncDir(filepath.Dir(a.target)); err != nil {
		a.log.Debug("could not flush the directory entry after rename",
			"path", a.target, "error", err)
	}
	return nil
}

// Close removes the temp file unless it has been committed. It is safe to call
// twice, and is the deferred cleanup every caller must have: without it an
// abandoned stream leaves a dot-file beside the target forever.
func (a *atomicFile) Close() error {
	if a.closed {
		return nil
	}
	a.closed = true
	if a.committed {
		return nil
	}
	closeErr := a.file.Close()
	if err := os.Remove(a.tmpPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return errors.Join(closeErr, fmt.Errorf("remove %s: %w", a.tmpPath, err))
	}
	return closeErr
}

// syncDir flushes a directory entry, so a rename survives a power loss rather
// than only a process crash.
//
// It is a no-op on Windows, which has no directory handle to flush:
// FlushFileBuffers wants a file handle and refuses a directory one. NTFS
// journals the rename itself, so the metadata is durable by another route.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(dir) //nolint:gosec // dir is the parent of an already jail-resolved path
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}

// randomSuffix returns a short filesystem-safe random string.
//
// It is crypto/rand rather than a counter because two agents — or two RPCs —
// racing on the same directory must not pick the same temp name, and because a
// predictable name in a world-writable directory is a name an attacker can
// create first as a symlink. O_EXCL catches that, but not colliding at all is
// better than relying on the catch.
func randomSuffix() string {
	var b [10]byte
	// rand.Read is documented never to fail since Go 1.24; it panics internally
	// rather than returning an error a caller has to handle.
	_, _ = rand.Read(b[:])
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]))
}
