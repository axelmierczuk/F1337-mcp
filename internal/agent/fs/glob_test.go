package fs_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

func glob(t *testing.T, svc interface {
	Glob(context.Context, *sandboxdv1.GlobRequest) (*sandboxdv1.GlobResponse, error)
}, req *sandboxdv1.GlobRequest) *sandboxdv1.GlobResponse {
	t.Helper()
	resp, err := svc.Glob(context.Background(), req)
	require.NoError(t, err)
	return resp
}

// relative renders results relative to root, so assertions read as the tree
// rather than as temp-directory noise.
func relative(t *testing.T, root string, paths []string) []string {
	t.Helper()
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		rel, err := filepath.Rel(root, p)
		require.NoError(t, err)
		out = append(out, filepath.ToSlash(rel))
	}
	return out
}

// "**/*.go" finds nested matches; "*.go" does not recurse. The anchoring is
// what makes the two spellings mean different things.
func TestGlob_DoubleStarRecursesAndStarDoesNot(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "top.go"), "")
	writeFile(t, filepath.Join(root, "a", "mid.go"), "")
	writeFile(t, filepath.Join(root, "a", "b", "deep.go"), "")
	writeFile(t, filepath.Join(root, "a", "notes.txt"), "")
	svc := newConfined(t, root)

	recursive := glob(t, svc, &sandboxdv1.GlobRequest{Pattern: "**/*.go", Root: root})
	assert.ElementsMatch(t, []string{"top.go", "a/mid.go", "a/b/deep.go"},
		relative(t, root, recursive.GetPaths()))

	flat := glob(t, svc, &sandboxdv1.GlobRequest{Pattern: "*.go", Root: root})
	assert.Equal(t, []string{"top.go"}, relative(t, root, flat.GetPaths()))

	scoped := glob(t, svc, &sandboxdv1.GlobRequest{Pattern: "a/**/*.go", Root: root})
	assert.ElementsMatch(t, []string{"a/mid.go", "a/b/deep.go"}, relative(t, root, scoped.GetPaths()))
}

func TestGlob_QuestionMarkAndCharacterClasses(t *testing.T) {
	root := tempRoot(t)
	for _, name := range []string{"a1.txt", "a2.txt", "ab.txt", "b1.txt"} {
		writeFile(t, filepath.Join(root, name), "")
	}
	svc := newConfined(t, root)

	assert.ElementsMatch(t, []string{"a1.txt", "a2.txt", "ab.txt"},
		relative(t, root, glob(t, svc, &sandboxdv1.GlobRequest{Pattern: "a?.txt", Root: root}).GetPaths()))
	assert.ElementsMatch(t, []string{"a1.txt", "a2.txt", "b1.txt"},
		relative(t, root, glob(t, svc, &sandboxdv1.GlobRequest{Pattern: "[ab][12].txt", Root: root}).GetPaths()))
}

// Newest first: the file someone is looking for is almost always the one they
// last touched.
func TestGlob_SortsByModificationTimeNewestFirst(t *testing.T) {
	root := tempRoot(t)
	base := time.Now().Add(-time.Hour)
	for i, name := range []string{"oldest.go", "middle.go", "newest.go"} {
		path := writeFile(t, filepath.Join(root, name), "")
		require.NoError(t, os.Chtimes(path, base.Add(time.Duration(i)*time.Minute), base.Add(time.Duration(i)*time.Minute)))
	}
	svc := newConfined(t, root)

	resp := glob(t, svc, &sandboxdv1.GlobRequest{Pattern: "*.go", Root: root})
	assert.Equal(t, []string{"newest.go", "middle.go", "oldest.go"}, relative(t, root, resp.GetPaths()))
}

// Same timestamp, same order every time: a model that runs one search twice and
// gets two orderings behaves differently for no reason in the code.
func TestGlob_TiesAreOrderedDeterministically(t *testing.T) {
	root := tempRoot(t)
	stamp := time.Now().Add(-time.Hour)
	for _, name := range []string{"c.go", "a.go", "b.go"} {
		path := writeFile(t, filepath.Join(root, name), "")
		require.NoError(t, os.Chtimes(path, stamp, stamp))
	}
	svc := newConfined(t, root)

	for i := 0; i < 5; i++ {
		resp := glob(t, svc, &sandboxdv1.GlobRequest{Pattern: "*.go", Root: root})
		assert.Equal(t, []string{"a.go", "b.go", "c.go"}, relative(t, root, resp.GetPaths()))
	}
}

func TestGlob_LimitReportsTruncation(t *testing.T) {
	root := tempRoot(t)
	for i := 0; i < 20; i++ {
		writeFile(t, filepath.Join(root, string(rune('a'+i))+".go"), "")
	}
	svc := newConfined(t, root)

	resp := glob(t, svc, &sandboxdv1.GlobRequest{Pattern: "*.go", Root: root, Limit: 5})

	assert.Len(t, resp.GetPaths(), 5)
	assert.True(t, resp.GetTruncation().GetTruncated())
	assert.Equal(t, uint64(15), resp.GetTruncation().GetLinesOmitted())
}

// .gitignore is honoured when asked and ignored when not, and a nested file
// overrides its parent.
func TestGlob_Gitignore(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, ".gitignore"), "*.log\nbuild/\n")
	writeFile(t, filepath.Join(root, "keep.log"), "")
	writeFile(t, filepath.Join(root, "build", "out.txt"), "")
	writeFile(t, filepath.Join(root, "sub", ".gitignore"), "!*.log\n")
	writeFile(t, filepath.Join(root, "sub", "nested.log"), "")
	writeFile(t, filepath.Join(root, "sub", "code.txt"), "")
	svc := newConfined(t, root)

	ignored := glob(t, svc, &sandboxdv1.GlobRequest{Pattern: "**/*", Root: root, RespectGitignore: true})
	assert.ElementsMatch(t, []string{".gitignore", "sub/.gitignore", "sub/nested.log", "sub/code.txt"},
		relative(t, root, ignored.GetPaths()),
		"the parent excludes *.log and build/, and the nested file re-includes *.log under sub/")

	unfiltered := glob(t, svc, &sandboxdv1.GlobRequest{Pattern: "**/*", Root: root})
	assert.Contains(t, relative(t, root, unfiltered.GetPaths()), "keep.log")
	assert.Contains(t, relative(t, root, unfiltered.GetPaths()), "build/out.txt")
}

func TestGlob_SkipsNoiseDirectoriesUnlessAsked(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "main.go"), "")
	for _, dir := range []string{".git", "node_modules", "vendor", "target"} {
		writeFile(t, filepath.Join(root, dir, "buried.go"), "")
	}
	svc := newConfined(t, root)

	assert.Equal(t, []string{"main.go"},
		relative(t, root, glob(t, svc, &sandboxdv1.GlobRequest{Pattern: "**/*.go", Root: root}).GetPaths()))

	all := glob(t, svc, &sandboxdv1.GlobRequest{Pattern: "**/*.go", Root: root, IncludeDefaultIgnored: true})
	assert.Len(t, all.GetPaths(), 5)
}

func TestGlob_InvalidPatternIsAClearError(t *testing.T) {
	root := tempRoot(t)
	svc := newConfined(t, root)

	for _, pattern := range []string{"", "   ", "[unclosed", "**/[", "a/[a-"} {
		_, err := svc.Glob(context.Background(), &sandboxdv1.GlobRequest{Pattern: pattern, Root: root})
		require.Error(t, err, "pattern %q", pattern)
		assert.Equal(t, codes.InvalidArgument, status.Code(err), "pattern %q", pattern)
	}
}

// A symlink pointing out of the jail is not a way to have a path outside it
// returned, and neither is a symlinked directory.
func TestGlob_NeverReturnsPathsOutsideTheJail(t *testing.T) {
	root := tempRoot(t)
	outside := tempRoot(t)
	writeFile(t, filepath.Join(outside, "secret.txt"), "classified")
	writeFile(t, filepath.Join(root, "inside.txt"), "fine")
	requireSymlink(t, filepath.Join(outside, "secret.txt"), filepath.Join(root, "escape.txt"))
	requireSymlink(t, outside, filepath.Join(root, "escapedir"))

	confined := newConfined(t, root)
	resp := glob(t, confined, &sandboxdv1.GlobRequest{Pattern: "**/*.txt", Root: root})
	assert.Equal(t, []string{"inside.txt"}, relative(t, root, resp.GetPaths()))

	// The unconfined twin: with no jail there is nothing to escape, and the
	// link is an ordinary file. The agent must not pretend otherwise.
	unconfined := newUnconfined(t, root)
	open := glob(t, unconfined, &sandboxdv1.GlobRequest{Pattern: "**/*.txt", Root: root})
	assert.ElementsMatch(t, []string{"inside.txt", "escape.txt"}, relative(t, root, open.GetPaths()))
}

func TestGlob_SymlinkLoopTerminates(t *testing.T) {
	root := tempRoot(t)
	inner := filepath.Join(root, "a", "b")
	require.NoError(t, os.MkdirAll(inner, 0o755))
	writeFile(t, filepath.Join(inner, "file.go"), "")
	requireSymlink(t, filepath.Join(root, "a"), filepath.Join(inner, "loop"))
	svc := newConfined(t, root)

	done := make(chan []string, 1)
	go func() {
		done <- relative(t, root, glob(t, svc, &sandboxdv1.GlobRequest{Pattern: "**/*.go", Root: root}).GetPaths())
	}()
	select {
	case paths := <-done:
		assert.Equal(t, []string{"a/b/file.go"}, paths)
	case <-time.After(10 * time.Second):
		t.Fatal("the walk did not terminate on a symlink loop")
	}
}

func TestGlob_RejectsAMissingOrNonDirectoryRoot(t *testing.T) {
	root := tempRoot(t)
	file := writeFile(t, filepath.Join(root, "f.txt"), "")
	svc := newConfined(t, root)

	_, err := svc.Glob(context.Background(), &sandboxdv1.GlobRequest{Pattern: "*", Root: file})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = svc.Glob(context.Background(), &sandboxdv1.GlobRequest{
		Pattern: "*", Root: filepath.Join(root, "missing")})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// With no root the search starts from the jail's working directory, which for a
// confined agent is its first allowed root.
func TestGlob_DefaultsToTheJailWorkingDirectory(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "found.go"), "")
	svc := newConfined(t, root)

	resp := glob(t, svc, &sandboxdv1.GlobRequest{Pattern: "**/*.go"})
	assert.Equal(t, []string{"found.go"}, relative(t, root, resp.GetPaths()))
}
