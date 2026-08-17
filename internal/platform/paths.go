package platform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PathSeparator is the separator this platform uses, "/" or "\\". It is the
// value reported in sandboxd.v1.Platform.path_separator.
const PathSeparator = string(os.PathSeparator)

// CaseInsensitivePaths reports whether path comparison on this platform must
// ignore case.
//
// It is true only on Windows. macOS volumes are usually case-insensitive too,
// but "usually" is not a property a containment check can rest on: APFS can be
// formatted case-sensitive, and a mounted volume can differ from the boot one.
// Comparing case-sensitively where the filesystem is insensitive can only ever
// refuse a path that was in fact inside a root — it can never admit one that
// was outside, because matching bytes still imply the same directory. Erring
// that way is the safe direction, so darwin is treated as case-sensitive.
const CaseInsensitivePaths = caseInsensitivePaths

// ErrPathNamespace reports a path in a namespace this agent deliberately
// refuses to operate in: Windows UNC shares and the \\?\ and \\.\ device
// namespaces.
var ErrPathNamespace = errors.New("platform: path namespace not supported")

// PathKind classifies the namespace a path names. Only Windows has more than
// two kinds; on Unix every path is either relative or an ordinary local path.
type PathKind int

const (
	// PathInvalid is an empty path, or one whose form the agent refuses to
	// interpret — a Windows drive-relative path such as `C:work`, whose
	// meaning depends on per-drive current-directory state the agent does not
	// track.
	PathInvalid PathKind = iota
	// PathRelative is a path to be resolved against a base directory.
	PathRelative
	// PathLocal is an absolute path in the ordinary filesystem namespace.
	PathLocal
	// PathUNC is a Windows UNC share path, `\\server\share\...`.
	PathUNC
	// PathDevice is a Windows device-namespace path, `\\?\...` or `\\.\...`.
	PathDevice
)

func (k PathKind) String() string {
	switch k {
	case PathInvalid:
		return "invalid"
	case PathRelative:
		return "relative"
	case PathLocal:
		return "local"
	case PathUNC:
		return "unc"
	case PathDevice:
		return "device"
	default:
		return fmt.Sprintf("PathKind(%d)", int(k))
	}
}

// ClassifyPath reports which namespace p names, under this platform's rules.
//
// The distinction exists so callers can refuse the Windows namespaces
// deliberately instead of by accident. `\\?\C:\x` reaches the same file as
// `C:\x` while bypassing the normalisation the rest of the path stack assumes,
// and a UNC share is a different host's filesystem with its own case and
// canonicalisation rules. A jail that silently accepts either is not confining
// what it thinks it is confining.
func ClassifyPath(p string) PathKind { return classifyPath(p) }

// NormalizePath makes p absolute — relative to base, or to the process working
// directory when base is empty — and cleans it lexically. It performs no
// filesystem access and resolves no symlinks; containment must never be
// decided on its result alone. See internal/security/jail.
//
// Paths in a namespace ClassifyPath rejects produce ErrPathNamespace.
func NormalizePath(base, p string) (string, error) {
	switch kind := ClassifyPath(p); kind {
	case PathInvalid:
		if p == "" {
			return "", errors.New("platform: empty path")
		}
		return "", fmt.Errorf("%w: %s path %q", ErrPathNamespace, kind, p)
	case PathUNC, PathDevice:
		return "", fmt.Errorf("%w: %s path %q", ErrPathNamespace, kind, p)
	case PathLocal:
		return filepath.Clean(p), nil
	case PathRelative:
		if base == "" {
			abs, err := filepath.Abs(p)
			if err != nil {
				return "", fmt.Errorf("platform: resolving %q against the working directory: %w", p, err)
			}
			return abs, nil
		}
		if ClassifyPath(base) != PathLocal {
			return "", fmt.Errorf("platform: base directory %q is not an absolute local path", base)
		}
		return filepath.Join(base, p), nil
	default:
		return "", fmt.Errorf("%w: %s path %q", ErrPathNamespace, kind, p)
	}
}

// EqualPaths reports whether two cleaned absolute paths name the same
// location, applying this platform's case rules.
func EqualPaths(a, b string) bool {
	return equalPathBytes(filepath.Clean(a), filepath.Clean(b))
}

// HasPathPrefix reports whether path is prefix itself or lies beneath it.
//
// Comparison is by whole path component: "/rootabc" is not beneath "/root",
// though its string prefix matches. Getting that wrong is a jail escape, not a
// cosmetic bug.
func HasPathPrefix(path, prefix string) bool {
	if path == "" || prefix == "" {
		return false
	}
	path = filepath.Clean(path)
	prefix = filepath.Clean(prefix)
	if equalPathBytes(path, prefix) {
		return true
	}
	if !strings.HasSuffix(prefix, PathSeparator) {
		prefix += PathSeparator
	}
	if len(path) <= len(prefix) {
		return false
	}
	return equalPathBytes(path[:len(prefix)], prefix)
}

// equalPathBytes compares two paths byte for byte, folding ASCII case where
// the platform is case-insensitive.
//
// Folding is deliberately restricted to ASCII. Windows compares filenames
// through an internal upcase table that also folds many non-ASCII characters,
// and Go's Unicode simple folding is not that table — it treats U+212A KELVIN
// SIGN and 'K' as equal, for one. Over-folding here would let a directory
// whose name merely folds to a root's name be treated as inside that root,
// which is the wrong direction to be wrong in. Under-folding can only refuse a
// path, and in practice does not even do that: filepath.EvalSymlinks on
// Windows returns each component with its on-disk spelling, so a resolved path
// and a resolved root already agree on case.
func equalPathBytes(a, b string) bool {
	if !CaseInsensitivePaths {
		return a == b
	}
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		if foldASCII(a[i]) != foldASCII(b[i]) {
			return false
		}
	}
	return true
}

func foldASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
