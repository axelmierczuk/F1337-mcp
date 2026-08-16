// Package version carries build metadata stamped in at link time.
package version

import "runtime/debug"

// These are set via -ldflags at release time by GoReleaser. The defaults are
// what a `go build` from a working tree produces.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// String returns a human-readable version line.
func String() string {
	return Version + " (" + Commit + ", built " + Date + ")"
}

// FromBuildInfo fills in Commit from the embedded VCS stamp when the binary was
// built without explicit ldflags, so `go install` builds still identify
// themselves usefully.
func FromBuildInfo() {
	if Commit != "unknown" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			Commit = s.Value
		}
	}
}
