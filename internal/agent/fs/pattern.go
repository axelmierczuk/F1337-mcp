package fs

import (
	"errors"
	"path"
	"strings"

	"github.com/axelmierczuk/sandboxd-mcp/internal/platform"
)

// ErrBadPattern reports a glob the agent cannot compile.
var ErrBadPattern = errors.New("fs: bad glob pattern")

// pattern is a compiled glob.
//
// Go's path.Match has no "**", which is the one construct every caller reaches
// for first — "**/*.go" is the example in the tool documentation — so matching
// is done segment by segment here with path.Match handling each segment. The
// rest of the syntax is path.Match's: "*" within a segment, "?", and character
// classes.
type pattern struct {
	segments []string
	fold     bool
}

// compilePattern validates a glob and prepares it for matching.
//
// Every segment is validated up front, so a malformed class returns a clear
// error at request time rather than silently matching nothing on every file in
// the tree.
func compilePattern(p string) (*pattern, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return nil, ErrBadPattern
	}
	// Patterns are written with forward slashes on every platform: they come
	// from a model that learned them on Unix, and a Windows caller should not
	// have to escape backslashes to search its own disk.
	p = strings.ReplaceAll(p, "\\", "/")

	var segments []string
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." {
			continue
		}
		if seg == "**" {
			// Consecutive "**" segments mean what one does, and collapsing them
			// keeps the matcher from branching over an equivalent alternative.
			if len(segments) > 0 && segments[len(segments)-1] == "**" {
				continue
			}
			segments = append(segments, seg)
			continue
		}
		if _, err := path.Match(seg, ""); err != nil {
			return nil, errors.Join(ErrBadPattern, err)
		}
		segments = append(segments, seg)
	}
	if len(segments) == 0 {
		return nil, ErrBadPattern
	}
	return &pattern{segments: segments, fold: platform.CaseInsensitivePaths}, nil
}

// match reports whether a slash-separated relative path matches.
func (p *pattern) match(rel string) bool {
	rel = strings.ReplaceAll(rel, "\\", "/")
	if p.fold {
		rel = strings.ToLower(rel)
	}
	parts := make([]string, 0, 8)
	for _, seg := range strings.Split(rel, "/") {
		if seg == "" || seg == "." {
			continue
		}
		parts = append(parts, seg)
	}
	return matchSegments(p.patternSegments(), parts)
}

// patternSegments returns the segments, case-folded when the platform demands
// it.
func (p *pattern) patternSegments() []string {
	if !p.fold {
		return p.segments
	}
	folded := make([]string, len(p.segments))
	for i, seg := range p.segments {
		folded[i] = strings.ToLower(seg)
	}
	return folded
}

// matchSegments matches pattern segments against path segments, with "**"
// consuming any number of them — including none, so "**/*.go" matches a .go
// file at the root as well as a nested one.
func matchSegments(pat, name []string) bool {
	switch {
	case len(pat) == 0:
		return len(name) == 0
	case pat[0] == "**":
		for i := 0; i <= len(name); i++ {
			if matchSegments(pat[1:], name[i:]) {
				return true
			}
		}
		return false
	case len(name) == 0:
		return false
	}
	ok, err := path.Match(pat[0], name[0])
	if err != nil || !ok {
		return false
	}
	return matchSegments(pat[1:], name[1:])
}

// prefixCanMatch reports whether any path under a directory could still match.
//
// It is what lets a walk skip a subtree instead of visiting every file in it:
// "src/**/*.go" cannot match anything under "docs", and there is no reason to
// read that directory to find out one file at a time.
func (p *pattern) prefixCanMatch(relDir string) bool {
	if relDir == "" || relDir == "." {
		return true
	}
	rel := strings.ReplaceAll(relDir, "\\", "/")
	if p.fold {
		rel = strings.ToLower(rel)
	}
	parts := make([]string, 0, 8)
	for _, seg := range strings.Split(rel, "/") {
		if seg == "" || seg == "." {
			continue
		}
		parts = append(parts, seg)
	}
	return prefixMatch(p.patternSegments(), parts)
}

// prefixMatch reports whether the path segments so far are a viable prefix of
// something the pattern matches.
func prefixMatch(pat, name []string) bool {
	switch {
	case len(name) == 0:
		return true
	case len(pat) == 0:
		return false
	case pat[0] == "**":
		// "**" swallows the rest of the directories, so anything below is still
		// a candidate.
		return true
	}
	ok, err := path.Match(pat[0], name[0])
	if err != nil || !ok {
		return false
	}
	return prefixMatch(pat[1:], name[1:])
}
