package fs

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"sort"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

// Glob finds files matching a pattern, newest first.
//
// The pattern is anchored at root: "*.go" matches the .go files directly in it
// and does not recurse, and "**/*.go" matches at any depth including the root.
// Anchoring is what makes the two spellings mean different things, and a walk
// that could never match a subtree — "src/**/*.go" under "docs" — skips it
// rather than reading it a file at a time.
//
// Results are files. Directories are what ListDirectory is for, and including
// them here would push real matches past the cap on any pattern ending in "*".
//
// # Ordering, and why this one does not stop early
//
// Results are sorted by modification time, newest first, because the file
// someone is looking for is almost always the one they last touched. That
// ordering cannot be produced by stopping at the first `limit` matches: the
// newest file may be the last one the walk reaches. So Glob walks — bounded by
// Limits.MaxGlobCandidates, and reporting truncation when it hits that bound —
// and sorts what it found. Grep, whose results have no such global ordering, is
// the one that stops the walk the moment its cap is reached.
//
// Ties are broken by path so that two files written in the same filesystem
// timestamp tick come back in the same order every time.
func (s *Service) Glob(ctx context.Context, req *sandboxdv1.GlobRequest) (*sandboxdv1.GlobResponse, error) {
	pat, err := compilePattern(req.GetPattern())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument,
			"pattern %q is not a valid glob: %v; supported syntax is **, *, ?, and character classes",
			req.GetPattern(), errors.Unwrap(err))
	}
	root, err := s.resolveRoot(req.GetRoot())
	if err != nil {
		return nil, err
	}

	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = s.limits.DefaultGlobResults
	}

	type candidate struct {
		path    string
		modTime time.Time
	}
	candidates := make([]candidate, 0, min(limit, 256))
	capped := false

	walkErr := s.walkTree(ctx, walkOptions{
		root:                  root,
		respectGitignore:      req.GetRespectGitignore(),
		includeDefaultIgnored: req.GetIncludeDefaultIgnored(),
		descend:               pat.prefixCanMatch,
	}, func(p, rel string, d fs.DirEntry) (bool, error) {
		if !pat.match(rel) {
			return true, nil
		}
		if len(candidates) >= s.limits.MaxGlobCandidates {
			capped = true
			return false, nil
		}
		var modTime time.Time
		if info, err := d.Info(); err == nil {
			modTime = info.ModTime()
		}
		candidates = append(candidates, candidate{path: p, modTime: modTime})
		return true, nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	sort.Slice(candidates, func(i, j int) bool {
		if !candidates[i].modTime.Equal(candidates[j].modTime) {
			return candidates[i].modTime.After(candidates[j].modTime)
		}
		return candidates[i].path < candidates[j].path
	})

	truncated := capped
	omitted := 0
	if len(candidates) > limit {
		omitted = len(candidates) - limit
		candidates = candidates[:limit]
		truncated = true
	}

	paths := make([]string, 0, len(candidates))
	for _, c := range candidates {
		paths = append(paths, c.path)
	}
	return &sandboxdv1.GlobResponse{
		Paths:      paths,
		Truncation: truncation(truncated, 0, u64(omitted)),
	}, nil
}

// compileIncludeGlob compiles Grep's include_glob, which uses .gitignore
// semantics rather than Glob's.
//
// "*.go" there means "any .go file at any depth", because that is what a caller
// writing `-g '*.go'` means every time. Glob's pattern is anchored instead,
// because "*.go" and "**/*.go" have to be able to mean different things when
// the pattern is the whole request.
func compileIncludeGlob(p string) (*pattern, error) {
	if p == "" {
		return nil, nil
	}
	if !path.IsAbs(p) && !containsSlash(p) {
		p = "**/" + p
	}
	return compilePattern(p)
}

func containsSlash(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' || s[i] == '\\' {
			return true
		}
	}
	return false
}
