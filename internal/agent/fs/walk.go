package fs

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// walkOptions configures the tree walk Glob and Grep share.
type walkOptions struct {
	// root is the already-resolved directory to walk.
	root string
	// respectGitignore reads .gitignore files, including nested ones.
	respectGitignore bool
	// includeDefaultIgnored walks into .git, node_modules, vendor and target.
	includeDefaultIgnored bool
	// descend decides whether to walk into a directory, given its path relative
	// to root with forward slashes. Nil descends everywhere. It is how Glob
	// avoids reading a subtree its pattern could never match.
	descend func(relDir string) bool
}

// walkFunc is called for each file the walk yields, in lexical order. It
// returns false to stop the walk immediately.
type walkFunc func(path, rel string, d fs.DirEntry) (bool, error)

// walkTree walks a directory, yielding files.
//
// Order is lexical and therefore reproducible: a model that runs the same
// search twice and gets results in a different order will behave differently
// for reasons that have nothing to do with the code it is searching.
//
// Symlinked directories are never descended into. That is what makes a tree
// containing a symlink loop terminate rather than hang, and it is also the
// simplest form of the containment rule: a link pointing out of the jail cannot
// graft an outside subtree into the walk if no link is followed at all.
// Symlinked files are yielded only when they resolve inside the jail, which on
// an unconfined agent is every one of them.
//
// Stopping is immediate. When fn returns false the walk returns at once — it
// does not finish and then discard, which is the entire reason Grep's
// max_matches is a bound on work rather than on output.
func (s *Service) walkTree(ctx context.Context, opts walkOptions, fn walkFunc) error {
	stack := &ignoreStack{}
	stopped := false

	err := filepath.WalkDir(opts.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable directory is a hole in the results, not a failed
			// search: a tree with one root-owned subdirectory in it should still
			// be searchable by everyone else.
			if errors.Is(err, fs.ErrPermission) || errors.Is(err, fs.ErrNotExist) {
				return skipIfDir(d)
			}
			return err
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}

		rel, relErr := filepath.Rel(opts.root, path)
		if relErr != nil {
			return skipIfDir(d)
		}
		rel = filepath.ToSlash(rel)

		if d.IsDir() {
			if path == opts.root {
				if opts.respectGitignore {
					stack.push(path)
				}
				return nil
			}
			if !opts.includeDefaultIgnored && defaultIgnoredDirs[d.Name()] {
				return filepath.SkipDir
			}
			if opts.respectGitignore {
				stack.trimTo(filepath.Dir(path))
				if stack.ignored(path, true) {
					return filepath.SkipDir
				}
				stack.push(path)
			}
			if opts.descend != nil && !opts.descend(rel) {
				return filepath.SkipDir
			}
			return nil
		}

		if opts.respectGitignore {
			stack.trimTo(filepath.Dir(path))
			if stack.ignored(path, false) {
				return nil
			}
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			if !s.symlinkInsideJail(path) {
				return nil
			}
		case !d.Type().IsRegular():
			// Sockets, devices and named pipes. Reading one blocks forever or
			// returns something that is not a file's contents.
			return nil
		}

		keepGoing, ferr := fn(path, rel, d)
		if ferr != nil {
			return ferr
		}
		if !keepGoing {
			stopped = true
			return filepath.SkipAll
		}
		return nil
	})

	switch {
	case stopped, err == nil, errors.Is(err, filepath.SkipAll):
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.FromContextError(err).Err()
	}
	return fileError(opts.root, err)
}

// symlinkInsideJail reports whether a symlink's target is a path this agent may
// hand back.
//
// A dangling link is not: there is nothing to check containment against, and
// the target could be created later, pointing anywhere.
func (s *Service) symlinkInsideJail(path string) bool {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	info, err := os.Lstat(target)
	if err != nil || !info.Mode().IsRegular() {
		// A link to a directory is not descended into, and returning it as a
		// file would be a lie about what it is. A link to a device, a socket or
		// a named pipe is refused for the reason the switch below refuses one
		// reached directly: Grep opens what this yields, and opening a FIFO
		// blocks in open(2) with no deadline and no way to cancel it. Checking
		// only IsDir here let a link smuggle one past that switch.
		return false
	}
	return s.jail.ContainsResolved(target)
}

// resolveRoot resolves a search root, defaulting to the jail's working
// directory when the caller names none, and requires it to be a directory.
func (s *Service) resolveRoot(root string) (string, error) {
	if root == "" {
		root = s.jail.WorkingDir()
		if root == "" {
			return "", status.Errorf(codes.InvalidArgument,
				"root is required: this agent has no default working directory to search from")
		}
	}
	resolved, err := s.resolve(root)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fileError(resolved, err)
	}
	if !info.IsDir() {
		return "", status.Errorf(codes.InvalidArgument, "%s is not a directory", resolved)
	}
	return resolved, nil
}
