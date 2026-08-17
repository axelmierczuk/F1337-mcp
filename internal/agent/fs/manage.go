package fs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/platform"
)

// renamePath is os.Rename, indirected so a test can make it report a
// cross-device failure. Simulating EXDEV is the only way to exercise the
// fallback without asking the test host for a second filesystem, and the
// fallback is the part where getting it wrong loses a file.
//
// It is deliberately not used by atomicFile.Commit: that rename is always
// within one directory and can never be cross-device, and routing it through
// the same seam would make an injected failure break the writer the fallback
// itself depends on.
var renamePath = os.Rename

// MakeDirectory creates a directory.
//
// An existing directory is not an error — it is the state the caller asked for,
// and reporting created:false says everything a caller needs to distinguish the
// two. An existing *file* at that path is an error, because the caller asked
// for a directory and there is not one.
//
// create_parents means what it means in WriteFile: missing parents are created
// at 0755, and without it a missing parent is a NotFound rather than a silent
// mkdir -p. The named directory itself takes mode, or 0755, applied after
// creation so the daemon's umask cannot narrow what the caller asked for.
func (s *Service) MakeDirectory(ctx context.Context, req *sandboxdv1.MakeDirectoryRequest) (*sandboxdv1.MakeDirectoryResponse, error) {
	resolved, err := s.resolve(req.GetPath())
	if err != nil {
		return nil, err
	}

	release, err := s.locks.lock(ctx, resolved)
	if err != nil {
		return nil, status.FromContextError(err).Err()
	}
	defer release()

	mode := DefaultDirMode
	if req.GetMode() != 0 {
		mode = fs.FileMode(req.GetMode()).Perm()
	}

	if req.GetCreateParents() {
		if err := os.MkdirAll(filepath.Dir(resolved), DefaultDirMode); err != nil {
			return nil, fileError(filepath.Dir(resolved), err)
		}
	}

	mkdirErr := os.Mkdir(resolved, mode)
	switch {
	case mkdirErr == nil:
		if cerr := chmodPath(resolved, mode); cerr != nil {
			return nil, fileError(resolved, cerr)
		}
		return &sandboxdv1.MakeDirectoryResponse{Path: resolved, Created: true}, nil

	case errors.Is(mkdirErr, fs.ErrExist):
		// Already there, or already there as something else. Stat rather than
		// trust the errno: EEXIST says the name is taken, not what took it.
		info, statErr := os.Stat(resolved)
		if statErr != nil {
			return nil, fileError(resolved, statErr)
		}
		if !info.IsDir() {
			return nil, status.Errorf(codes.AlreadyExists,
				"%s already exists and is not a directory", resolved)
		}
		// The mode of a directory that was already there is left alone: the
		// caller asked for it to exist, not to be reconfigured.
		return &sandboxdv1.MakeDirectoryResponse{Path: resolved, Created: false}, nil

	case errors.Is(mkdirErr, fs.ErrNotExist):
		return nil, status.Errorf(codes.NotFound,
			"%s does not exist; set create_parents to create the missing parents", filepath.Dir(resolved))
	}
	return nil, fileError(resolved, mkdirErr)
}

// RemovePath removes a file, a symlink, or a directory.
//
// Three things make this the dangerous RPC, and each is handled explicitly
// rather than left to the filesystem's defaults:
//
//   - Recursion is opt-in. Without it a non-empty directory is a
//     FailedPrecondition naming the flag, not a silent recursive delete. The
//     emptiness is checked rather than inferred from an errno, because the
//     errno for it is not portable and the message would be worse.
//   - A jail root cannot be removed. Removing the root would destroy the
//     confinement while staying inside it, which is the one deletion the jail
//     cannot be expected to survive. An unconfined agent has no roots and so no
//     such refusal — there is nothing to protect and pretending otherwise would
//     be the decoration this repo's exec/jail decision exists to remove.
//   - A symlink is unlinked, never followed. Resolving the final component
//     first — which every content RPC here does — would delete what the link
//     points at, and that is the classic way a delete leaves the jail: a link
//     inside the roots aimed anywhere at all. So containment is checked on the
//     resolved *parent* and the last component is left exactly as the caller
//     wrote it.
func (s *Service) RemovePath(ctx context.Context, req *sandboxdv1.RemovePathRequest) (*sandboxdv1.RemovePathResponse, error) {
	target, err := s.resolveSelf(req.GetPath(), "remove")
	if err != nil {
		return nil, err
	}

	release, err := s.locks.lock(ctx, target)
	if err != nil {
		return nil, status.FromContextError(err).Err()
	}
	defer release()

	// Lstat, so a symlink is a symlink and not the directory it names.
	info, err := os.Lstat(target)
	if err != nil {
		return nil, fileError(target, err)
	}

	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
		// One unlink. A symlink here is removed as a link: nothing reads
		// through it, so a link pointing out of the jail costs the link and
		// nothing else.
		if err := os.Remove(target); err != nil {
			return nil, fileError(target, err)
		}
		return &sandboxdv1.RemovePathResponse{Path: target, EntriesRemoved: 1}, nil
	}

	if err := s.refuseJailRoot(target, "remove"); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(target)
	if err != nil {
		return nil, fileError(target, err)
	}
	if len(entries) == 0 {
		if err := os.Remove(target); err != nil {
			return nil, fileError(target, err)
		}
		return &sandboxdv1.RemovePathResponse{Path: target, EntriesRemoved: 1}, nil
	}
	if !req.GetRecursive() {
		return nil, status.Errorf(codes.FailedPrecondition,
			"%s is a directory holding %d entries; set recursive to remove it and everything under it",
			target, len(entries))
	}

	// Counted before anything is removed, and the count fails the request rather
	// than shrinking silently: a tree this call could not finish reading is one
	// it should not start deleting.
	count, err := countTree(ctx, target)
	if err != nil {
		if cerr := ctxErr(ctx); cerr != nil {
			return nil, cerr
		}
		return nil, status.Errorf(codes.FailedPrecondition,
			"%s could not be inspected before removal, so nothing was removed: %v", target, err)
	}

	// os.RemoveAll rather than a walk that unlinks as it goes. On Unix it
	// descends with openat and O_NOFOLLOW, so a directory swapped for a symlink
	// midway through cannot redirect the deletion outside the tree — a race a
	// hand-rolled Lstat-then-readdir loop loses, and one that matters for a
	// daemon that may be running as root over a directory an ordinary user can
	// write to.
	if err := os.RemoveAll(target); err != nil {
		return nil, fileError(target, err)
	}
	return &sandboxdv1.RemovePathResponse{Path: target, EntriesRemoved: count}, nil
}

// MovePath renames a file, a symlink, or a directory.
//
// Both endpoints go through the jail, not just the destination: a move whose
// source is outside the roots is a read out of them, and one whose destination
// is outside is a write out of them.
//
// Like RemovePath, the last component of each path is left unresolved, so
// moving a symlink moves the link rather than dragging what it points at to a
// new name.
//
// destination is the full path to move to, never a directory to move into. The
// difference is the one that silently does the wrong thing when guessed, so it
// is stated and an existing directory at the destination is refused.
func (s *Service) MovePath(ctx context.Context, req *sandboxdv1.MovePathRequest) (*sandboxdv1.MovePathResponse, error) {
	source, err := s.resolveSelf(req.GetSource(), "move")
	if err != nil {
		return nil, err
	}
	destination, err := s.resolveSelf(req.GetDestination(), "move")
	if err != nil {
		return nil, err
	}
	if platform.EqualPaths(source, destination) {
		return nil, status.Errorf(codes.InvalidArgument,
			"source and destination are both %s, so this move would do nothing", source)
	}

	release, err := s.locks.lockBoth(ctx, source, destination)
	if err != nil {
		return nil, status.FromContextError(err).Err()
	}
	defer release()

	sourceInfo, err := os.Lstat(source)
	if err != nil {
		return nil, fileError(source, err)
	}
	if err := s.refuseJailRoot(source, "move"); err != nil {
		return nil, err
	}

	switch destInfo, err := os.Lstat(destination); {
	case err == nil && destInfo.IsDir() && destInfo.Mode()&fs.ModeSymlink == 0:
		return nil, status.Errorf(codes.FailedPrecondition,
			"%s is an existing directory; destination is the full path to move to rather than a directory to move into, so include the name the moved path should have",
			destination)
	case err == nil && !req.GetOverwrite():
		return nil, status.Errorf(codes.AlreadyExists,
			"%s already exists; set overwrite to replace it", destination)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return nil, fileError(destination, err)
	}

	err = renamePath(source, destination)
	if err == nil {
		return &sandboxdv1.MovePathResponse{Source: source, Destination: destination}, nil
	}
	if !isCrossDevice(err) {
		return nil, fileError(source, err)
	}
	if err := s.moveAcrossDevices(ctx, source, destination, sourceInfo); err != nil {
		return nil, err
	}
	return &sandboxdv1.MovePathResponse{Source: source, Destination: destination}, nil
}

// moveAcrossDevices handles the rename that could not happen, because rename
// does not work across filesystems.
//
// The ordering is the whole of it: the destination is written and committed
// first, and only then is the source unlinked. A failure anywhere before that
// last step leaves the source exactly as it was, which is the outcome that
// matters — the one thing a move must never produce is a deleted source and a
// half-written destination.
//
// A directory is refused rather than copied. Copying a tree across a filesystem
// boundary has partial-failure states with no safe rollback once the
// destination pre-existed, and a wrong answer there loses a directory rather
// than a file. The error names the cause and says the source is untouched, so
// the caller can copy the files individually or pick a destination on the same
// filesystem.
func (s *Service) moveAcrossDevices(ctx context.Context, source, destination string, info fs.FileInfo) error {
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		target, err := os.Readlink(source)
		if err != nil {
			return fileError(source, err)
		}
		// Replacing the destination is the caller's already-checked overwrite;
		// removing it first is what makes os.Symlink able to create the name.
		if err := os.Remove(destination); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fileError(destination, err)
		}
		if err := os.Symlink(target, destination); err != nil {
			return fileError(destination, err)
		}

	case info.Mode().IsRegular():
		if err := s.copyFile(ctx, source, destination, info.Mode().Perm()); err != nil {
			return err
		}

	case info.IsDir():
		return status.Errorf(codes.FailedPrecondition,
			"%s and %s are on different filesystems, and this agent will not copy a directory tree across one: a failure partway through has no safe rollback. The source is untouched — move the files individually, or choose a destination on the same filesystem as the source",
			source, destination)

	default:
		return status.Errorf(codes.FailedPrecondition,
			"%s is not a regular file, a symlink or a directory, and cannot be moved across filesystems", source)
	}

	// Last, and only once the destination is complete.
	if err := os.Remove(source); err != nil {
		return status.Errorf(codes.Internal,
			"%s was copied to %s but the original could not be removed, so both now exist: %v",
			source, destination, err)
	}
	return nil
}

// copyFile streams source into destination through the atomic writer, so a
// cross-device move commits the same way every other write in this package
// does: a sibling temp file, fsynced, renamed into place. A copy interrupted
// halfway leaves no destination at all rather than a partial one.
func (s *Service) copyFile(ctx context.Context, source, destination string, mode fs.FileMode) error {
	in, err := s.jail.OpenFile(source, os.O_RDONLY, 0)
	if err != nil {
		return s.pathError(source, err)
	}
	defer func() { _ = in.Close() }()

	out, err := createAtomic(s.jail, s.log, destination, mode)
	if err != nil {
		return fileError(destination, err)
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, &contextReader{ctx: ctx, r: in}); err != nil {
		return fileError(source, err)
	}
	if err := out.Commit(); err != nil {
		return fileError(destination, err)
	}
	return nil
}

// contextReader stops a long copy when the request is cancelled, so a client
// that hung up does not leave the agent copying a gigabyte to a destination
// nobody will collect.
type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *contextReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// refuseJailRoot rejects an operation on a directory that is one of the jail's
// roots.
//
// It compares against the jail's resolved roots, which are empty on an
// unconfined agent — so this refuses nothing there, which is correct: there is
// no confinement for the removal to destroy.
//
// It is called twice per path, and the two calls do different jobs.
// Service.resolveSelf calls it on the path as written, which is what produces a
// sensible message for the ordinary spelling of a root. The handlers call it
// again on the resolved target, which is what catches the spellings the lexical
// comparison cannot see: a root reached through a symlinked parent, or a root
// nested inside another root.
func (s *Service) refuseJailRoot(target, verb string) error {
	for _, root := range s.jail.Roots() {
		if platform.EqualPaths(target, root) {
			return status.Errorf(codes.PermissionDenied,
				"%s is an allowed root, and this agent will not %s the directory its own confinement is defined by; %s its contents instead",
				target, verb, verb)
		}
	}
	return nil
}

// countTree counts every entry under root, root included, without following
// symlinked directories.
func countTree(ctx context.Context, root string) (uint64, error) {
	var n uint64
	err := filepath.WalkDir(root, func(_ string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		n++
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// chmodPath applies a mode, skipping platforms where it means nothing.
//
// The mode is applied after creation because the process umask masks what
// mkdir was given: a directory the caller asked to be 0700 comes out 0700
// whatever umask the daemon inherited.
func chmodPath(path string, mode fs.FileMode) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}
