package policy

import (
	"os"
	"path/filepath"
	"strings"
)

// pathSeparators are the characters that make a name a path rather than
// something to look up in PATH. Windows accepts both.
const pathSeparators = `/\`

// patternEscapes reports whether a backslash escapes the next character in a
// rule pattern. It does not here: filepath.Match disables escaping on Windows,
// where a backslash is a path separator, so `C:\Windows\*` is a rule about a
// directory rather than an escape sequence.
const patternEscapes = false

// defaultPathExt is what Windows uses when PATHEXT is unset. It matches the
// system default rather than a subset: a host whose PATHEXT is missing from
// the daemon's environment must still be able to run a .bat, or every command
// that resolves to one stops working for a reason nobody chose.
const defaultPathExt = ".COM;.EXE;.BAT;.CMD"

// extensions splits PATHEXT into the suffixes a bare name may resolve through,
// lowercased for comparison.
func extensions(pathExt string) []string {
	if strings.TrimSpace(pathExt) == "" {
		pathExt = defaultPathExt
	}
	var exts []string
	for _, ext := range strings.Split(pathExt, ";") {
		ext = strings.ToLower(strings.TrimSpace(ext))
		if ext == "" {
			continue
		}
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		exts = append(exts, ext)
	}
	return exts
}

// findExecutable reports the file Windows would run for path.
//
// Windows decides executability by extension, so a name already carrying one
// from PATHEXT is taken as given and anything else is tried against each
// extension in turn — the same order CreateProcess would. A name with an
// extension that is not in PATHEXT is still tried as given, because an
// operator who wrote out a full path to a file meant that file.
func findExecutable(path string, exts []string) (string, bool) {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != "" {
		if regularFile(path) {
			return path, true
		}
		// A dotted name that is not itself runnable ("python3.11") still
		// resolves through PATHEXT, so fall through rather than giving up.
	}
	for _, candidate := range exts {
		if withExt := path + candidate; regularFile(withExt) {
			return withExt, true
		}
	}
	return "", false
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
