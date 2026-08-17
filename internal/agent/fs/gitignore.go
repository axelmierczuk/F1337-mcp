package fs

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/axelmierczuk/sandboxd-mcp/internal/platform"
)

// gitignoreName is the file the walk reads when respect_gitignore is set.
const gitignoreName = ".gitignore"

// maxIgnoreFileBytes bounds one .gitignore. A repository with a megabyte of
// ignore rules is not a repository this agent needs to read whole.
const maxIgnoreFileBytes = 256 * 1024

// ignoreRule is one line of a .gitignore.
type ignoreRule struct {
	pat *pattern
	// negate is a "!" rule, which re-includes a path an earlier rule excluded.
	negate bool
	// dirOnly is a trailing "/", which matches directories only.
	dirOnly bool
}

// ignoreFile is the rules from one .gitignore, and the directory they are
// relative to.
type ignoreFile struct {
	dir   string
	rules []ignoreRule
}

// ignoreStack is the .gitignore files in force at the current point of a walk,
// outermost first.
//
// Nesting is the reason it is a stack rather than a list: a .gitignore deeper
// in the tree overrides its parents, so the decision is taken from the deepest
// file that has anything to say about the path. Within one file the last
// matching rule wins, which is how "!" re-includes work.
type ignoreStack struct {
	files []ignoreFile
}

// trimTo pops every frame that no longer contains dir.
func (s *ignoreStack) trimTo(dir string) {
	for len(s.files) > 0 && !platform.HasPathPrefix(dir, s.files[len(s.files)-1].dir) {
		s.files = s.files[:len(s.files)-1]
	}
}

// push loads dir's .gitignore, if it has one.
func (s *ignoreStack) push(dir string) {
	rules, ok := loadIgnoreFile(filepath.Join(dir, gitignoreName))
	if !ok {
		return
	}
	s.files = append(s.files, ignoreFile{dir: dir, rules: rules})
}

// ignored reports whether an absolute path is excluded by the rules in force.
func (s *ignoreStack) ignored(path string, isDir bool) bool {
	for i := len(s.files) - 1; i >= 0; i-- {
		file := s.files[i]
		rel, err := filepath.Rel(file.dir, path)
		if err != nil || strings.HasPrefix(rel, "..") {
			continue
		}
		rel = filepath.ToSlash(rel)

		decided, excluded := false, false
		for _, rule := range file.rules {
			if rule.dirOnly && !isDir {
				continue
			}
			if !rule.pat.match(rel) {
				continue
			}
			decided, excluded = true, !rule.negate
		}
		if decided {
			return excluded
		}
	}
	return false
}

// loadIgnoreFile parses a .gitignore, returning false when there is none.
func loadIgnoreFile(path string) ([]ignoreRule, bool) {
	f, err := os.Open(path) //nolint:gosec // path is inside a tree the jail already admitted
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()

	var rules []ignoreRule
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 4096), maxIgnoreFileBytes)
	for scanner.Scan() {
		if rule, ok := parseIgnoreLine(scanner.Text()); ok {
			rules = append(rules, rule)
		}
	}
	return rules, len(rules) > 0
}

// parseIgnoreLine compiles one .gitignore line.
//
// The subset implemented is the one that appears in real ignore files:
// comments, blank lines, "!" negation, a trailing "/" for directories, a
// leading or embedded "/" to anchor to the ignore file's own directory, and
// everything else matching at any depth. Backslash escapes are not
// interpreted, because on Windows a backslash in a path pattern is far more
// often a separator someone typed than an escape they meant.
func parseIgnoreLine(line string) (ignoreRule, bool) {
	trimmed := strings.TrimRight(line, " \t\r")
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return ignoreRule{}, false
	}

	rule := ignoreRule{}
	if strings.HasPrefix(trimmed, "!") {
		rule.negate = true
		trimmed = trimmed[1:]
	}
	if strings.HasSuffix(trimmed, "/") {
		rule.dirOnly = true
		trimmed = strings.TrimSuffix(trimmed, "/")
	}
	if trimmed == "" {
		return ignoreRule{}, false
	}

	// A pattern with no slash in it matches at any depth; one with a slash is
	// anchored to the directory holding the .gitignore. That is git's rule, and
	// the difference between "node_modules" ignoring every one of them and
	// "build/output" ignoring exactly one.
	anchored := strings.Contains(trimmed, "/")
	trimmed = strings.TrimPrefix(trimmed, "/")
	if trimmed == "" {
		return ignoreRule{}, false
	}
	if !anchored {
		trimmed = "**/" + trimmed
	}
	// A directory rule excludes everything under it, and the walk skips the
	// directory itself — but a file rule reached directly still has to match, so
	// both the entry and its contents are covered.
	compiled, err := compilePattern(trimmed)
	if err != nil {
		return ignoreRule{}, false
	}
	rule.pat = compiled
	return rule, true
}

// defaultIgnoredDirs are skipped by Glob and Grep unless the caller asks for
// them. They are the directories that dominate a walk while containing almost
// nothing anyone searches for.
var defaultIgnoredDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"target":       true,
}
