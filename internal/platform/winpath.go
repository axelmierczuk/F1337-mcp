package platform

import "strings"

// classifyWindowsPath applies Windows path rules with no help from
// path/filepath, so the classification compiles and can be tested on any host
// rather than only on a Windows runner. paths_windows.go is the only caller in
// a real build.
//
// The rules, in the order they are applied:
//
//   - Empty is invalid.
//   - A path starting with two separators is either a device path (`\\?\`,
//     `\\.\`) or a UNC share (`\\server\share`). Both are refused by callers;
//     they are distinguished so the error can say which.
//   - `X:\...` is an ordinary absolute local path.
//   - `X:` followed by anything but a separator is drive-relative — `C:work`
//     means "work, relative to the current directory *of drive C*", a
//     per-drive value nothing in the agent tracks. Refused as invalid rather
//     than guessed at.
//   - Everything else, including a rooted path with no drive such as `\work`,
//     is relative and gets joined onto a base directory.
func classifyWindowsPath(p string) PathKind {
	if p == "" {
		return PathInvalid
	}
	s := strings.ReplaceAll(p, "/", `\`)

	if strings.HasPrefix(s, `\\`) {
		rest := s[2:]
		if rest == "?" || rest == "." ||
			strings.HasPrefix(rest, `?\`) || strings.HasPrefix(rest, `.\`) {
			return PathDevice
		}
		return PathUNC
	}

	if len(s) >= 2 && isDriveLetter(s[0]) && s[1] == ':' {
		if len(s) >= 3 && s[2] == '\\' {
			return PathLocal
		}
		return PathInvalid
	}

	return PathRelative
}

func isDriveLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
