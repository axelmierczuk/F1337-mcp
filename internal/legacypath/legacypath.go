// Package legacypath resolves the environment variables and directories that
// the sandboxd → fleet rebrand renamed, preferring the new name and falling
// back to the old one when only the old one is actually there.
//
// The rebrand renamed the config directory, the agent's machine-wide
// directories, and the environment variables that point at them. None of that
// is cosmetic on a host that already joined a fleet: its certificates, its
// registry and its supervisor state all live under the old path. A build that
// simply looked at the new name would find nothing, create an empty directory
// beside the populated old one, and present to the operator as "my whole fleet
// vanished" — with the enrollment still on disk a few characters away.
//
// So the rule everywhere in this package is: the new name wins when it holds
// something, the old name is honoured when it is the only one that does, and
// the operator is told once, per name, which is happening and what to do about
// it. Nothing here moves or copies data. Migrating a directory of private keys
// is the operator's call to make deliberately, not something a daemon should do
// behind them on first start; docs/quickstart.md carries the instructions.
package legacypath

import (
	"log/slog"
	"os"
	"sync"
)

// warned records which deprecation notices have already been emitted, so a
// resolver called on every request logs once per process rather than once per
// call. The key is the old name, which is what the notice is about.
var warned sync.Map

func warnOnce(key, msg string, args ...any) {
	if _, seen := warned.LoadOrStore(key, struct{}{}); seen {
		return
	}
	slog.Warn(msg, args...)
}

// Env returns the value of newName, falling back to oldName when only the
// deprecated variable is set. It returns "" when neither is.
//
// Setting both is not an error: the new name wins silently, which is what an
// operator part-way through a migration — new name exported globally, old one
// still in a service unit — should get.
func Env(newName, oldName string) string {
	if v := os.Getenv(newName); v != "" {
		return v
	}
	v := os.Getenv(oldName)
	if v == "" {
		return ""
	}
	warnOnce("env:"+oldName,
		"the "+oldName+" environment variable is deprecated and will be removed; set "+newName+" instead",
		slog.String("deprecated", oldName),
		slog.String("replacement", newName),
		slog.String("value", v))
	return v
}

// Dir returns which of newDir and oldDir to actually use.
//
// It answers with whichever one holds something, preferring the new name:
//
//   - new directory has contents            → new  (the normal case, and the
//     case after a migration)
//   - new is absent or empty, old has some  → old  (a host enrolled before the
//     rename; logged once)
//   - neither holds anything                → new  (a fresh install starts on
//     the new name)
//
// "Empty" counts as absent deliberately. An empty new directory next to a
// populated old one is the exact shape of the failure this package exists to
// prevent — something creates the new path, the old enrollment stops being
// found, and the fleet appears to have evaporated. Deciding on contents rather
// than existence means an empty directory, however it got there, cannot strand
// a real enrollment.
func Dir(newDir, oldDir string) string {
	if newDir == oldDir || oldDir == "" {
		return newDir
	}
	if hasContents(newDir) {
		return newDir
	}
	if !hasContents(oldDir) {
		return newDir
	}
	warnOnce("dir:"+oldDir,
		"using the pre-rebrand directory "+oldDir+" because "+newDir+" is empty or absent; "+
			"move it with: mv "+oldDir+" "+newDir,
		slog.String("deprecated", oldDir),
		slog.String("replacement", newDir))
	return oldDir
}

// hasContents reports whether dir is a directory with at least one entry.
//
// It reads a single entry rather than the whole directory: the answer is the
// same and a config directory holding a large registry, a CA and a log tree
// should not be walked to decide where to look.
func hasContents(dir string) bool {
	if dir == "" {
		return false
	}
	f, err := os.Open(dir)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	names, err := f.Readdirnames(1)
	// Readdirnames returns io.EOF on an empty directory and ENOTDIR on a plain
	// file; either way there is nothing here to prefer.
	return err == nil && len(names) > 0
}
