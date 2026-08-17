package agent

// PROVISIONAL — reconcile with issue #6.
//
// internal/security/jail is the package that owns path confinement, and it is
// landing in a sibling PR. It was not on main when this file was written, and
// the daemon cannot hand downstream services a nil jail, so the interface the
// daemon depends on and a working implementation of it live here, in one file,
// deliberately.
//
// When #6 lands: keep the Jail interface (that is the seam #7, #8 and #11 code
// against), make jail.Jail satisfy it, point NewJail at the real
// implementation, and delete pathJail and its tests. Nothing outside this file
// needs to change.
//
// The implementation below resolves symlinks before checking containment,
// which is the property that matters — the naive order lets any symlink inside
// the jail walk straight out of it. What it does not do is the openat2
// RESOLVE_BENEATH work #6 calls for, so the resolve-then-use race is open here
// and callers must operate on the path Resolve returns rather than the one
// they passed in.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ErrOutsideJail is returned by Jail.Resolve for a path that resolves outside
// every allowed root. Downstream services should map it to
// codes.PermissionDenied.
var ErrOutsideJail = errors.New("path escapes allowed roots")

// Jail confines filesystem access to the agent's allowed roots. Every path in
// every FileService and ExecService call passes through Resolve before a
// syscall touches it.
type Jail interface {
	// Resolve returns the absolute, symlink-resolved form of path, or an
	// error wrapping ErrOutsideJail when it is not contained by a root.
	//
	// Callers must use the returned path for the subsequent syscall. The
	// resolution is not atomic with the use, so operating on the caller's
	// original string re-opens the traversal this exists to close.
	Resolve(path string) (string, error)

	// Roots returns the configured allowed roots, resolved and absolute.
	Roots() []string

	// Enabled reports whether any confinement is in force. False is the
	// explicit --no-jail state, never an accident: Config.Validate refuses an
	// empty root list unless the operator asked for it by name.
	Enabled() bool
}

// NewJail builds the jail for a config's allowed roots. An empty list yields
// the explicit no-jail state.
func NewJail(roots []string) (Jail, error) {
	resolved := make([]string, 0, len(roots))
	for _, root := range roots {
		if root == "" {
			continue
		}
		abs, err := filepath.Abs(root)
		if err != nil {
			return nil, fmt.Errorf("agent: resolve allowed root %s: %w", root, err)
		}
		// A root that does not exist yet is kept in its lexical form: the
		// installer is allowed to name a workspace the operator creates
		// afterwards, and refusing to start over it would be worse than
		// resolving it lazily.
		if target, err := filepath.EvalSymlinks(abs); err == nil {
			abs = target
		}
		resolved = append(resolved, filepath.Clean(abs))
	}
	return &pathJail{roots: resolved}, nil
}

type pathJail struct {
	roots []string
}

func (j *pathJail) Enabled() bool { return len(j.roots) > 0 }

func (j *pathJail) Roots() []string {
	out := make([]string, len(j.roots))
	copy(out, j.roots)
	return out
}

func (j *pathJail) Resolve(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("agent: empty path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("agent: resolve %s: %w", path, err)
	}

	resolved, err := resolveThroughSymlinks(abs)
	if err != nil {
		return "", err
	}
	if !j.Enabled() {
		return resolved, nil
	}
	for _, root := range j.roots {
		if contains(root, resolved) {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("agent: %s: %w (allowed: %s)", path, ErrOutsideJail, strings.Join(j.roots, ", "))
}

// resolveThroughSymlinks returns abs with every symlink in it resolved.
//
// filepath.EvalSymlinks fails on a path that does not exist, which is the
// normal case for a write creating a new file. For those, the nearest existing
// ancestor is resolved and the remaining components are appended to it — so
// containment is decided by where the real directory is, not by where the
// requested string claims to be.
func resolveThroughSymlinks(abs string) (string, error) {
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved, nil
	} else if !os.IsNotExist(err) {
		// A dangling symlink, a permission error partway up, or a non-directory
		// component. None of those is a path the agent should proceed with.
		return "", fmt.Errorf("agent: resolve %s: %w", abs, err)
	}

	var missing []string
	dir := abs
	for {
		parent := filepath.Dir(dir)
		if parent == dir {
			// Walked to the volume root without finding anything that exists.
			return "", fmt.Errorf("agent: resolve %s: no existing ancestor", abs)
		}
		missing = append([]string{filepath.Base(dir)}, missing...)
		dir = parent

		resolved, err := filepath.EvalSymlinks(dir)
		if err == nil {
			// The lexical Clean inside filepath.Abs already collapsed any ".."
			// the caller wrote. Anything left here would have to come from a
			// component literally named "..", which cannot survive Clean —
			// checking anyway costs nothing and documents the invariant.
			for _, part := range missing {
				if part == ".." {
					return "", fmt.Errorf("agent: resolve %s: traversal component after the last existing directory", abs)
				}
			}
			// EvalSymlinks reported the first missing component as absent, but
			// Lstat can still find it — which means it is a symlink whose
			// target does not exist. That is not a path to create a file at:
			// an open() through a dangling link creates the *target*, and the
			// target is somewhere this resolution never got to check.
			first := filepath.Join(resolved, missing[0])
			if _, lerr := os.Lstat(first); lerr == nil {
				return "", fmt.Errorf("agent: resolve %s: %s is a symlink to a path that does not exist", abs, first)
			}
			return filepath.Join(append([]string{resolved}, missing...)...), nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("agent: resolve %s: %w", dir, err)
		}
	}
}

// contains reports whether path is root itself or lies beneath it, comparing
// on component boundaries so that /workspace does not contain /workspace-old.
func contains(root, path string) bool {
	if pathEqual(root, path) {
		return true
	}
	prefix := root
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	if runtime.GOOS == "windows" {
		return strings.HasPrefix(strings.ToLower(path), strings.ToLower(prefix))
	}
	return strings.HasPrefix(path, prefix)
}

func pathEqual(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
