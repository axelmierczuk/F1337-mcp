//go:build unix

package platform

import "path/filepath"

const caseInsensitivePaths = false

// classifyPath applies Unix rules: there is one namespace, and a leading
// backslash is an ordinary filename character. `\\?\C:\x` on Unix is a
// relative path naming a very strangely spelled file, and is treated as one.
func classifyPath(p string) PathKind {
	switch {
	case p == "":
		return PathInvalid
	case filepath.IsAbs(p):
		return PathLocal
	default:
		return PathRelative
	}
}
