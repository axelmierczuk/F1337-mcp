package jail

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/axelmierczuk/sandboxd-mcp/internal/platform"
)

// mode records how a Jail was built. The zero value is deliberately neither
// "confined" nor "unconfined": an uninitialised Jail refuses everything, so a
// missing constructor call cannot turn into an open filesystem.
type mode uint8

const (
	modeUnset mode = iota
	modeConfined
	modeUnconfined
)

// Config describes a jail.
type Config struct {
	// Roots are the directories filesystem access is confined to. Each must
	// be an absolute local path that already exists and is a directory.
	//
	// Roots are resolved through symlinks at construction, so a root that is
	// itself a symlink confines to the target, and every later containment
	// check compares two fully resolved paths.
	//
	// An empty slice is an error. See Unconfined.
	Roots []string

	// WorkingDir is the directory relative paths resolve against. When empty
	// it defaults to the first root, which is what a sandbox almost always
	// wants; an unconfined jail falls back to the process working directory.
	//
	// It is not required to be inside a root. If it is not, relative paths
	// will resolve outside the jail and be refused, which is the correct
	// outcome and a confusing one — prefer setting it to a root.
	WorkingDir string
}

// Jail confines filesystem access to a set of roots. It is safe for concurrent
// use: it is immutable after construction.
type Jail struct {
	mode mode
	// roots are absolute, cleaned and symlink-resolved.
	roots []string
	// configured keeps the roots as the operator wrote them, for reporting in
	// sandbox_info where the resolved form would be confusing.
	configured []string
	workingDir string
}

// New builds a confined jail.
//
// It returns ErrNoRoots for an empty root list rather than producing a jail
// that permits everything. The no-jail state exists, but it has its own
// constructor and cannot be reached by passing an empty slice, a nil map entry
// or a config file with the key omitted.
func New(cfg Config) (*Jail, error) {
	if len(cfg.Roots) == 0 {
		return nil, ErrNoRoots
	}

	j := &Jail{
		mode:       modeConfined,
		roots:      make([]string, 0, len(cfg.Roots)),
		configured: slices.Clone(cfg.Roots),
	}

	for _, root := range cfg.Roots {
		resolved, err := resolveRoot(root)
		if err != nil {
			return nil, err
		}
		if !slices.ContainsFunc(j.roots, func(existing string) bool {
			return platform.EqualPaths(existing, resolved)
		}) {
			j.roots = append(j.roots, resolved)
		}
	}

	workingDir := cfg.WorkingDir
	if workingDir == "" {
		workingDir = j.roots[0]
	} else {
		resolved, err := resolveRoot(workingDir)
		if err != nil {
			return nil, fmt.Errorf("jail: working directory: %w", err)
		}
		workingDir = resolved
	}
	j.workingDir = workingDir

	return j, nil
}

// Unconfined returns a jail that checks nothing.
//
// It still normalises paths — callers downstream rely on getting an absolute,
// cleaned path back — but every path is permitted. The agent refuses to start
// this way unless explicitly forced, and reports it in sandbox_info, because
// the agent is a remote code execution service and the path jail is the only
// thing between a caller and the rest of the disk.
func Unconfined() *Jail {
	workingDir, err := os.Getwd()
	if err != nil {
		workingDir = ""
	}
	return &Jail{mode: modeUnconfined, workingDir: workingDir}
}

// resolveRoot validates and canonicalises a configured root.
func resolveRoot(root string) (string, error) {
	if kind := platform.ClassifyPath(root); kind != platform.PathLocal {
		return "", fmt.Errorf("jail: root %q must be an absolute local path, got a %s path", root, kind)
	}

	resolved, err := filepath.EvalSymlinks(filepath.Clean(root))
	if err != nil {
		// A root that does not exist is a configuration error, not something
		// to tolerate. Tolerating it would mean the path could be created
		// later — as a symlink to anywhere — and the jail would confine to
		// whatever it pointed at.
		return "", fmt.Errorf("jail: resolving root %q: %w", root, err)
	}

	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("jail: inspecting root %q: %w", root, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("jail: root %q is not a directory", root)
	}
	return resolved, nil
}

// Confined reports whether this jail enforces containment. False only for
// Unconfined; an unconstructed Jail is neither confined nor permissive, and
// answers false here while refusing every path.
func (j *Jail) Confined() bool {
	return j != nil && j.mode == modeConfined
}

// Configured reports whether this jail was built at all. A false result means
// every operation will return ErrNotConfigured.
func (j *Jail) Configured() bool {
	return j != nil && j.mode != modeUnset
}

// Roots returns the resolved allowed roots, which is what
// GetHostInfoResponse.allowed_roots reports. It is empty for an unconfined
// jail — the same empty list the proto documents as "no path jail".
func (j *Jail) Roots() []string {
	if j == nil {
		return nil
	}
	return slices.Clone(j.roots)
}

// ConfiguredRoots returns the roots as the operator wrote them, before symlink
// resolution. Use it in diagnostics where echoing back a path the operator
// never typed would be confusing.
func (j *Jail) ConfiguredRoots() []string {
	if j == nil {
		return nil
	}
	return slices.Clone(j.configured)
}

// WorkingDir returns the directory relative paths resolve against.
func (j *Jail) WorkingDir() string {
	if j == nil {
		return ""
	}
	return j.workingDir
}

// Resolve validates that path is contained by one of the jail's roots and
// returns the resolved absolute path.
//
// The returned path has had every symlink resolved, so it is the path the
// kernel would reach — not the one the caller asked for. Callers must use the
// returned value for the subsequent syscall; re-deriving it from the input
// discards the resolution that made the check meaningful.
//
// A path that does not exist yet is permitted when its nearest existing
// ancestor is inside a root, which is what makes creating a file work. A path
// whose parent is a symlink out of the jail is not, because the ancestor that
// exists is the target of that symlink.
//
// One consequence of cleaning before resolving is worth knowing. ".." is
// collapsed lexically, so a path that mixes a symlink with ".." can name a
// different file than the kernel would have reached on its own: "link/.." is
// the parent of the link, not the parent of its target. That is a difference
// in which file gets used, never in whether the check applies — the check is
// on the final resolved path either way, and that path is what is returned.
// The alternative, resolving ".." against the target, would mean re-walking
// the path a component at a time and reimplementing what the kernel already
// does correctly.
func (j *Jail) Resolve(path string) (string, error) {
	if !j.Configured() {
		return "", pathError("resolve", path, ErrNotConfigured)
	}
	if path == "" {
		return "", pathError("resolve", path, ErrInvalidPath)
	}

	abs, err := platform.NormalizePath(j.workingDir, path)
	if err != nil {
		return "", pathError("resolve", path, fmt.Errorf("%w: %w", ErrInvalidPath, err))
	}
	if j.mode == modeUnconfined {
		return abs, nil
	}

	anchor, remainder, err := resolveAnchor(abs)
	if err != nil {
		return "", pathError("resolve", path, err)
	}

	// The check is on the anchor: the deepest component that actually exists,
	// with every symlink on the way to it already followed by the kernel.
	if !j.ContainsResolved(anchor) {
		return "", pathError("resolve", path, ErrOutsideJail)
	}

	resolved := anchor
	if len(remainder) > 0 {
		resolved = filepath.Join(append([]string{anchor}, remainder...)...)
	}

	// The remainder cannot contain ".." — Clean removed every one of them
	// while the path was still absolute — but the containment of the joined
	// result is asserted rather than assumed. This check costs a string
	// comparison and covers every future change to the code above it.
	if !j.ContainsResolved(resolved) {
		return "", pathError("resolve", path, ErrOutsideJail)
	}
	return resolved, nil
}

// ContainsResolved reports whether an already-resolved absolute path lies
// under one of the roots.
//
// It resolves nothing. Passing it a path that has not been through Resolve, or
// through the kernel's own resolution, checks a string and proves nothing —
// which is the mistake this package exists to prevent. Use it for paths
// obtained by walking inside the jail, where the walk itself did the
// resolution, and use Resolve for anything a caller supplied.
func (j *Jail) ContainsResolved(path string) bool {
	switch {
	case !j.Configured():
		return false
	case j.mode == modeUnconfined:
		return true
	}
	for _, root := range j.roots {
		if platform.HasPathPrefix(path, root) {
			return true
		}
	}
	return false
}

// rootFor returns the root containing an already-resolved path.
func (j *Jail) rootFor(path string) (string, bool) {
	for _, root := range j.roots {
		if platform.HasPathPrefix(path, root) {
			return root, true
		}
	}
	return "", false
}

// resolveAnchor walks up from abs to the deepest component that exists,
// resolves that through symlinks, and returns it together with the components
// that had to be trimmed to find it.
//
// The anchor is what containment is checked against. Everything past it does
// not exist, so it cannot be a symlink and cannot redirect anywhere.
func resolveAnchor(abs string) (anchor string, remainder []string, err error) {
	current := abs
	for {
		info, lerr := os.Lstat(current)
		if lerr == nil {
			resolved, rerr := filepath.EvalSymlinks(current)
			if rerr == nil {
				return resolved, remainder, nil
			}
			if info.Mode()&os.ModeSymlink != 0 && errors.Is(rerr, os.ErrNotExist) {
				return "", nil, ErrDanglingSymlink
			}
			return "", nil, fmt.Errorf("jail: resolving symlinks in %q: %w", current, rerr)
		}

		if !isTraversable(lerr) {
			return "", nil, fmt.Errorf("jail: inspecting %q: %w", current, lerr)
		}

		parent := filepath.Dir(current)
		if parent == current {
			// Walked to the volume root without finding anything that exists.
			// On a working system this cannot happen; if it does, refuse.
			return "", nil, fmt.Errorf("jail: no existing ancestor of %q: %w", abs, os.ErrNotExist)
		}
		remainder = append([]string{filepath.Base(current)}, remainder...)
		current = parent
	}
}

// isTraversable reports whether a failed Lstat means "this component does not
// exist, keep walking up" rather than "give up".
//
// ErrNotExist is the ordinary case on every platform. ENOTDIR is what Unix
// returns when a component along the way is a regular file — /root/notes.txt/x
// — and it has to be walked past too, or a write to a path under a file would
// be refused with an inspection error instead of the ENOTDIR the caller
// deserves from the eventual syscall.
func isTraversable(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}
