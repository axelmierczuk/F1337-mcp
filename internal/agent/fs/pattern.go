package fs

import (
	"errors"
	"path"
	"strings"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
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
	return newMatcher(p.patternSegments(), parts).match(0, 0)
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

// matcher matches pattern segments against path segments, with "**" consuming
// any number of them — including none, so "**/*.go" matches a .go file at the
// root as well as a nested one.
//
// It memoises, and that is not an optimisation. Each "**" branches over every
// remaining path segment, so the plain recursion costs O(depth ^ number of "**")
// — a pattern the caller writes and a tree depth the caller controls. Something
// like "**/*/**/*/**/*/**/*/**/*/**/*" over a thirty-deep tree is tens of
// millions of calls per file, on a request with no deadline and nothing to
// interrupt it. The state here is only the pair of positions, so remembering
// answers makes it O(patternSegments × pathSegments²) and leaves what it matches
// exactly as it was.
type matcher struct {
	pat, name []string
	// seen[i*(len(name)+1)+j] is the answer for match(i, j): 0 unknown, 1 true,
	// 2 false.
	seen []uint8
}

func newMatcher(pat, name []string) *matcher {
	return &matcher{pat: pat, name: name, seen: make([]uint8, (len(pat)+1)*(len(name)+1))}
}

// match reports whether pat[i:] matches name[j:].
func (m *matcher) match(i, j int) bool {
	key := i*(len(m.name)+1) + j
	if answer := m.seen[key]; answer != 0 {
		return answer == 1
	}
	result := m.compute(i, j)
	m.seen[key] = 2
	if result {
		m.seen[key] = 1
	}
	return result
}

func (m *matcher) compute(i, j int) bool {
	switch {
	case i == len(m.pat):
		return j == len(m.name)
	case m.pat[i] == "**":
		for k := j; k <= len(m.name); k++ {
			if m.match(i+1, k) {
				return true
			}
		}
		return false
	case j == len(m.name):
		return false
	}
	ok, err := path.Match(m.pat[i], m.name[j])
	if err != nil || !ok {
		return false
	}
	return m.match(i+1, j+1)
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
