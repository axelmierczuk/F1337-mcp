package fs

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

// StatPath reports whether a path exists, and what it is.
//
// A missing path is exists:false, not an error: "does this exist" is the
// question, and answering it with NotFound would make the caller parse an error
// to learn a boolean.
//
// The metadata describes the path itself, with symlinks reported rather than
// followed — is_symlink and symlink_target say what it points at, and a caller
// that wants the target's own size stats the target. metadata.path is the path
// the caller named, made absolute; it is not the resolved path, so that the
// answer is about the thing that was asked about.
func (s *Service) StatPath(ctx context.Context, req *sandboxdv1.StatPathRequest) (*sandboxdv1.StatPathResponse, error) {
	// Resolve first: containment is decided on the fully resolved path, so a
	// link pointing out of the jail is refused here rather than described.
	if _, err := s.resolve(req.GetPath()); err != nil {
		return nil, err
	}
	named, err := s.lexical(req.GetPath())
	if err != nil {
		return nil, err
	}
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}

	info, err := os.Lstat(named)
	if errors.Is(err, fs.ErrNotExist) {
		return &sandboxdv1.StatPathResponse{Exists: false}, nil
	}
	if err != nil {
		return nil, fileError(named, err)
	}

	md := metadataFor(named, info)
	if !md.GetIsDir() && !md.GetIsSymlink() {
		md.IsBinary = s.sniffPath(named)
	}
	return &sandboxdv1.StatPathResponse{Exists: true, Metadata: md}, nil
}

// ListDirectory lists a directory, optionally recursively.
//
// Symlinked directories are reported but never descended into, here and in
// Glob and Grep. A tree whose links form a cycle therefore terminates, and a
// link pointing out of the jail cannot smuggle an outside subtree into the
// listing.
//
// Entry paths are absolute, rooted at the resolved directory. The cap stops the
// walk rather than trimming a completed one, so a recursive listing of a
// million-file tree costs the cap, not the tree — which means the number of
// entries omitted is not known and is reported as zero against a true
// truncated flag.
func (s *Service) ListDirectory(ctx context.Context, req *sandboxdv1.ListDirectoryRequest) (*sandboxdv1.ListDirectoryResponse, error) {
	resolved, err := s.resolve(req.GetPath())
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return nil, fileError(resolved, err)
	}
	if !info.IsDir() {
		return nil, status.Errorf(codes.InvalidArgument, "%s is not a directory", resolved)
	}

	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = s.limits.DefaultListEntries
	}

	entries := make([]*sandboxdv1.FileMetadata, 0, min(limit, 256))
	truncated := false

	add := func(path string, info fs.FileInfo) bool {
		if len(entries) >= limit {
			truncated = true
			return false
		}
		entries = append(entries, metadataFor(path, info))
		return true
	}

	if !req.GetRecursive() {
		dirEntries, err := os.ReadDir(resolved)
		if err != nil {
			return nil, fileError(resolved, err)
		}
		for _, entry := range dirEntries {
			if isHidden(entry.Name()) && !req.GetIncludeHidden() {
				continue
			}
			entryInfo, err := entry.Info()
			if err != nil {
				// A file deleted between readdir and lstat is not a failure of
				// the listing; it is a file that is no longer there.
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				return nil, fileError(filepath.Join(resolved, entry.Name()), err)
			}
			if !add(filepath.Join(resolved, entry.Name()), entryInfo) {
				break
			}
		}
		return &sandboxdv1.ListDirectoryResponse{
			Path:       resolved,
			Entries:    entries,
			Truncation: truncation(truncated, 0, 0),
		}, nil
	}

	walkErr := filepath.WalkDir(resolved, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
				return skipIfDir(d)
			}
			return err
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if path == resolved {
			return nil
		}
		if isHidden(d.Name()) && !req.GetIncludeHidden() {
			return skipIfDir(d)
		}
		entryInfo, err := d.Info()
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return skipIfDir(d)
			}
			return err
		}
		if !add(path, entryInfo) {
			return filepath.SkipAll
		}
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, filepath.SkipAll) {
		if err := ctxErr(ctx); err != nil {
			return nil, err
		}
		return nil, fileError(resolved, walkErr)
	}

	return &sandboxdv1.ListDirectoryResponse{
		Path:       resolved,
		Entries:    entries,
		Truncation: truncation(truncated, 0, 0),
	}, nil
}

// sniffPath reports whether a file looks binary, best-effort: a file that
// cannot be opened is reported as text rather than failing the stat, because
// StatPath's job is to describe what is there and an unreadable file is still
// there.
func (s *Service) sniffPath(path string) bool {
	f, err := os.Open(path) //nolint:gosec // path was resolved through the jail by the caller
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	binary, err := sniffBinary(f)
	return err == nil && binary
}

// skipIfDir tells WalkDir to step over a directory it could not read, or to
// carry on past a file it could not stat.
func skipIfDir(d fs.DirEntry) error {
	if d != nil && d.IsDir() {
		return filepath.SkipDir
	}
	return nil
}

// isHidden reports whether a name is hidden by the dotfile convention.
//
// Windows has its own hidden attribute, which this deliberately does not read:
// the callers are models and tools that think in Unix terms, and a listing
// whose hidden set changes meaning per platform is harder to reason about than
// one that is always "starts with a dot".
func isHidden(name string) bool {
	return strings.HasPrefix(name, ".") && name != "." && name != ".."
}
