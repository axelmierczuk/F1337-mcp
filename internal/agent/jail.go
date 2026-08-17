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

// ErrNoRoots is returned by NewJail when nothing usable is left after the root
// list is normalised.
//
// The no-jail state exists and has its own constructor. It must not be
// reachable by passing an empty slice, a list of empty strings, or a config
// file with the key left out: "confine to nothing" and "confine to everything"
// are one typo apart, and only one of them may be arrived at by accident.
var ErrNoRoots = errors.New("agent: no usable allowed roots; call Unconfined for the explicit no-jail state")

// ErrPathNamespace is returned for a Windows path in a namespace the jail
// refuses to interpret: UNC shares, which are another host's filesystem with
// its own canonicalisation rules, and the \\?\ and \\.\ device namespaces,
// which switch off the normalisation every other layer here assumes.
//
// Refusing them is a decision. Left alone they would be neither rejected nor
// normalised — they would simply fail every containment check for reasons
// nobody chose, which is the same outcome until the day it is not.
var ErrPathNamespace = errors.New("agent: path namespace not supported")

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
	// explicit no-jail state produced by Unconfined, never an accident:
	// NewJail refuses an empty root list and Config.Validate refuses an empty
	// allowed_roots unless the operator asked for it by name.
	Enabled() bool
}

// NewJail builds a jail confined to roots.
//
// Each root is made absolute and resolved through symlinks. A root that does
// not exist yet is resolved as far as it does exist — the installer is allowed
// to name a workspace the operator creates afterwards — because the resolved
// form is what every later containment check compares against. Keeping such a
// root in its lexical form is what makes an agent configured with /tmp/sandboxd
// on macOS refuse every path under its own root once the directory appears:
// /tmp is a symlink to /private/tmp, so the resolved path never matches.
func NewJail(roots []string) (Jail, error) {
	resolved := make([]string, 0, len(roots))
	for _, root := range roots {
		if strings.TrimSpace(root) == "" {
			continue
		}
		if err := checkNamespace(root); err != nil {
			return nil, fmt.Errorf("agent: allowed root %q: %w", root, err)
		}
		abs, err := filepath.Abs(root)
		if err != nil {
			return nil, fmt.Errorf("agent: resolve allowed root %s: %w", root, err)
		}
		resolved = append(resolved, filepath.Clean(resolveRoot(abs)))
	}
	if len(resolved) == 0 {
		return nil, ErrNoRoots
	}
	return &pathJail{roots: resolved, confined: true}, nil
}

// Unconfined returns the explicit no-jail state: a Jail that normalises and
// resolves paths but permits all of them.
//
// It is what `serve --no-jail` gets. It exists as its own constructor so that
// a daemon serving the whole filesystem is something a caller asked for by
// name, rather than what an empty slice quietly decayed into.
func Unconfined() Jail { return &pathJail{} }

type pathJail struct {
	roots []string
	// confined separates Unconfined from a jail that lost its roots. Only
	// NewJail sets it, and NewJail refuses to return without at least one.
	confined bool
}

func (j *pathJail) Enabled() bool { return j.confined }

func (j *pathJail) Roots() []string {
	out := make([]string, len(j.roots))
	copy(out, j.roots)
	return out
}

func (j *pathJail) Resolve(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("agent: empty path")
	}
	if err := checkNamespace(path); err != nil {
		return "", fmt.Errorf("agent: %s: %w", path, err)
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

// resolveRoot returns the resolved form of a configured root, falling back to
// the lexical form when nothing about it can be resolved.
//
// The fallback is deliberately fail-closed rather than fail-open: a root that
// cannot be resolved keeps a string that no resolved path will match, so the
// jail refuses everything under it instead of admitting whatever the path
// turns out to point at later.
func resolveRoot(abs string) string {
	if resolved, err := resolveThroughSymlinks(abs); err == nil {
		return resolved
	}
	return abs
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
	if len(path) <= len(prefix) {
		return false
	}
	return pathEqual(path[:len(prefix)], prefix)
}

// caseInsensitivePaths reports whether path comparison must ignore case.
//
// True only on Windows. macOS volumes are usually case-insensitive too, but
// "usually" is not something a containment check may rest on: APFS can be
// formatted case-sensitive. Comparing case-sensitively where the filesystem is
// insensitive can only refuse a path that was in fact inside a root; it can
// never admit one that was outside. That is the safe direction.
var caseInsensitivePaths = runtime.GOOS == "windows"

func pathEqual(a, b string) bool { return equalPathFold(a, b, caseInsensitivePaths) }

// equalPathFold compares two path fragments, folding ASCII case when fold is
// set.
//
// The folding is ASCII-only on purpose. strings.EqualFold and strings.ToLower
// apply Unicode simple folding, under which U+212A KELVIN SIGN equals "k" — so
// a root of C:\workspace would contain a genuinely different directory named
// C:\wor<U+212A>space, which Windows treats as a separate path. Over-folding a
// containment check admits directories that are outside the jail; under-folding
// only refuses ones that are inside it.
func equalPathFold(a, b string, fold bool) bool {
	if !fold {
		return a == b
	}
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if asciiLower(a[i]) != asciiLower(b[i]) {
			return false
		}
	}
	return true
}

func asciiLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// pathKind classifies the namespace a path names. Only Windows has more than
// two kinds.
type pathKind int

const (
	// pathInvalid is an empty path, or a Windows drive-relative path such as
	// "C:work", whose meaning depends on per-drive current-directory state
	// nothing in the agent tracks.
	pathInvalid pathKind = iota
	// pathRelative is a path resolved against the process working directory.
	pathRelative
	// pathLocal is an absolute path in the ordinary filesystem namespace.
	pathLocal
	// pathUNC is a Windows UNC share path, \\server\share\...
	pathUNC
	// pathDevice is a Windows device-namespace path, \\?\... or \\.\...
	pathDevice
)

func (k pathKind) String() string {
	switch k {
	case pathRelative:
		return "relative"
	case pathLocal:
		return "local"
	case pathUNC:
		return "UNC"
	case pathDevice:
		return "device"
	default:
		return "invalid"
	}
}

// checkNamespace refuses a path the jail will not interpret.
func checkNamespace(p string) error {
	switch kind := classifyPath(p); kind {
	case pathLocal, pathRelative:
		return nil
	default:
		return fmt.Errorf("%w: %s path", ErrPathNamespace, kind)
	}
}

func classifyPath(p string) pathKind {
	if runtime.GOOS == "windows" {
		return classifyWindowsPath(p)
	}
	switch {
	case p == "":
		return pathInvalid
	case filepath.IsAbs(p):
		return pathLocal
	default:
		// A leading backslash is an ordinary filename character on Unix, so
		// `\\?\C:\x` here names a very strangely spelled relative file and is
		// treated as one.
		return pathRelative
	}
}

// classifyWindowsPath applies Windows path rules without help from
// path/filepath, so the classification compiles and can be tested on any host
// rather than only on a Windows runner.
func classifyWindowsPath(p string) pathKind {
	if p == "" {
		return pathInvalid
	}
	s := strings.ReplaceAll(p, "/", `\`)

	if strings.HasPrefix(s, `\\`) {
		rest := s[2:]
		if rest == "?" || rest == "." || strings.HasPrefix(rest, `?\`) || strings.HasPrefix(rest, `.\`) {
			return pathDevice
		}
		return pathUNC
	}
	if len(s) >= 2 && isDriveLetter(s[0]) && s[1] == ':' {
		if len(s) >= 3 && s[2] == '\\' {
			return pathLocal
		}
		// "C:work" is relative to the current directory *of drive C*, which is
		// per-drive state nothing here tracks. Refused rather than guessed at.
		return pathInvalid
	}
	return pathRelative
}

func isDriveLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
