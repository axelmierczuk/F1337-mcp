package fs_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	agentfs "github.com/axelmierczuk/sandboxd-mcp/internal/agent/fs"
)

func grep(t *testing.T, svc *agentfs.Service, req *sandboxdv1.GrepRequest) *fakeGrepStream {
	t.Helper()
	stream := newGrepStream(context.Background())
	require.NoError(t, svc.Grep(req, stream))
	require.NotNil(t, stream.summary, "every search ends with a summary")
	return stream
}

func TestGrep_ReportsLineNumbersAndContext(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "a.txt"), "one\ntwo\nneedle\nfour\nfive\n")
	svc := newConfined(t, root)

	stream := grep(t, svc, &sandboxdv1.GrepRequest{Pattern: "needle", Root: root, ContextLines: 1})

	require.Len(t, stream.matches, 1)
	m := stream.matches[0]
	assert.Equal(t, filepath.Join(root, "a.txt"), m.GetPath())
	assert.Equal(t, uint64(3), m.GetLineNumber())
	assert.Equal(t, "needle", m.GetLine())
	assert.Equal(t, []string{"two"}, m.GetBeforeContext())
	assert.Equal(t, []string{"four"}, m.GetAfterContext())
	assert.Equal(t, uint64(1), stream.summary.GetMatchesFound())
	assert.Equal(t, uint64(1), stream.summary.GetFilesSearched())
	assert.False(t, stream.summary.GetTruncation().GetTruncated())
}

func TestGrep_ContextIsClampedAtTheEndsOfAFile(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "a.txt"), "needle\nsecond\n")
	svc := newConfined(t, root)

	stream := grep(t, svc, &sandboxdv1.GrepRequest{Pattern: "needle", Root: root, ContextLines: 3})

	require.Len(t, stream.matches, 1)
	assert.Empty(t, stream.matches[0].GetBeforeContext())
	assert.Equal(t, []string{"second"}, stream.matches[0].GetAfterContext())
}

func TestGrep_CaseInsensitive(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "a.txt"), "Needle\n")
	svc := newConfined(t, root)

	assert.Empty(t, grep(t, svc, &sandboxdv1.GrepRequest{Pattern: "needle", Root: root}).matches)
	assert.Len(t, grep(t, svc,
		&sandboxdv1.GrepRequest{Pattern: "needle", Root: root, CaseInsensitive: true}).matches, 1)
}

// include_glob uses .gitignore semantics: "*.go" means any .go file at any
// depth, which is what a caller writing it means every time.
func TestGrep_IncludeGlob(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "a", "code.go"), "needle\n")
	writeFile(t, filepath.Join(root, "a", "notes.txt"), "needle\n")
	svc := newConfined(t, root)

	stream := grep(t, svc, &sandboxdv1.GrepRequest{Pattern: "needle", Root: root, IncludeGlob: "*.go"})
	assert.Equal(t, []string{filepath.Join(root, "a", "code.go")}, stream.paths())

	scoped := grep(t, svc, &sandboxdv1.GrepRequest{Pattern: "needle", Root: root, IncludeGlob: "a/*.txt"})
	assert.Equal(t, []string{filepath.Join(root, "a", "notes.txt")}, scoped.paths())
}

func TestGrep_FilesOnly(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "a.txt"), "needle\nneedle\nneedle\n")
	writeFile(t, filepath.Join(root, "b.txt"), "nothing\n")
	svc := newConfined(t, root)

	stream := grep(t, svc, &sandboxdv1.GrepRequest{Pattern: "needle", Root: root, FilesOnly: true})

	assert.Equal(t, []string{filepath.Join(root, "a.txt")}, stream.paths())
	assert.Equal(t, uint64(1), stream.summary.GetMatchesFound(),
		"files_only counts files, and stops reading each one at its first match")
	assert.Zero(t, stream.matches[0].GetLineNumber())
}

// A regex over compiled code produces matches that mean nothing and lines that
// render as noise, so binary files are skipped rather than searched.
func TestGrep_SkipsBinaryFiles(t *testing.T) {
	root := tempRoot(t)
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.bin"),
		[]byte("needle\x00needle\n"), 0o644))
	writeFile(t, filepath.Join(root, "b.txt"), "needle\n")
	svc := newConfined(t, root)

	stream := grep(t, svc, &sandboxdv1.GrepRequest{Pattern: "needle", Root: root})

	assert.Equal(t, []string{filepath.Join(root, "b.txt")}, stream.paths())
	assert.Equal(t, uint64(1), stream.summary.GetFilesSearched(),
		"the binary file is not counted as searched, because it was not searched")
}

// max_matches is a bound on work, not a filter over a finished search. The walk
// stops the moment the cap is reached, and files_searched proves it: the tree
// holds 500 more matching files that were never opened.
func TestGrep_MaxMatchesStopsTheWalkEarly(t *testing.T) {
	root := tempRoot(t)
	for i := 0; i < 3; i++ {
		writeFile(t, filepath.Join(root, "aaa", fmt.Sprintf("%03d.txt", i)), "needle\n")
	}
	const buried = 500
	for i := 0; i < buried; i++ {
		writeFile(t, filepath.Join(root, "zzz", fmt.Sprintf("%03d.txt", i)), "needle\n")
	}
	svc := newConfined(t, root)

	stream := grep(t, svc, &sandboxdv1.GrepRequest{Pattern: "needle", Root: root, MaxMatches: 2})

	assert.Len(t, stream.matches, 2)
	assert.Equal(t, uint64(2), stream.summary.GetMatchesFound())
	assert.Equal(t, uint64(2), stream.summary.GetFilesSearched(),
		"the walk stopped at the cap; it did not read all %d files and then truncate", buried+3)
	assert.True(t, stream.summary.GetTruncation().GetTruncated())

	// The same tree without a cap does walk it all, so the number above is a
	// property of the cap rather than of the tree.
	full := grep(t, svc, &sandboxdv1.GrepRequest{Pattern: "needle", Root: root, MaxMatches: 10_000})
	assert.Equal(t, uint64(buried+3), full.summary.GetFilesSearched())
}

// Matches are sent as they are found. The stream is held open on the first
// match while the walk is still running, and the summary afterwards shows how
// much of the tree came later.
func TestGrep_StreamsMatchesBeforeTheWalkCompletes(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "aaa", "first.txt"), "needle\n")
	const rest = 400
	for i := 0; i < rest; i++ {
		writeFile(t, filepath.Join(root, "zzz", fmt.Sprintf("%03d.txt", i)), "needle\n")
	}
	svc := newConfined(t, root)

	firstSent := make(chan struct{})
	release := make(chan struct{})
	stream := newGrepStream(context.Background())
	stream.onMatch = func(*sandboxdv1.GrepMatch) error {
		if len(stream.matches) == 0 {
			close(firstSent)
			<-release
		}
		return nil
	}

	done := make(chan error, 1)
	go func() { done <- svc.Grep(&sandboxdv1.GrepRequest{Pattern: "needle", Root: root}, stream) }()

	select {
	case <-firstSent:
	case err := <-done:
		t.Fatalf("the search finished without delivering a match: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("no match was delivered")
	}

	select {
	case <-done:
		t.Fatal("the walk completed before the first match was delivered")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	require.NoError(t, <-done)
	assert.Greater(t, stream.summary.GetFilesSearched(), uint64(100),
		"the first match was delivered while hundreds of files were still to come")
}

func TestGrep_InvalidRegexIsAClearError(t *testing.T) {
	root := tempRoot(t)
	svc := newConfined(t, root)

	err := svc.Grep(&sandboxdv1.GrepRequest{Pattern: "func(", Root: root}, newGrepStream(context.Background()))
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "RE2")

	err = svc.Grep(&sandboxdv1.GrepRequest{Pattern: "", Root: root}, newGrepStream(context.Background()))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	err = svc.Grep(&sandboxdv1.GrepRequest{Pattern: "x", Root: root, IncludeGlob: "[bad"},
		newGrepStream(context.Background()))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestGrep_Gitignore(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, ".gitignore"), "*.log\n")
	writeFile(t, filepath.Join(root, "app.log"), "needle\n")
	writeFile(t, filepath.Join(root, "app.txt"), "needle\n")
	writeFile(t, filepath.Join(root, "sub", ".gitignore"), "!*.log\n")
	writeFile(t, filepath.Join(root, "sub", "nested.log"), "needle\n")
	svc := newConfined(t, root)

	honoured := grep(t, svc, &sandboxdv1.GrepRequest{Pattern: "needle", Root: root, RespectGitignore: true})
	assert.ElementsMatch(t, []string{
		filepath.Join(root, "app.txt"),
		filepath.Join(root, "sub", "nested.log"),
	}, honoured.paths())

	ignored := grep(t, svc, &sandboxdv1.GrepRequest{Pattern: "needle", Root: root})
	assert.Len(t, ignored.paths(), 3)
}

func TestGrep_SkipsNoiseDirectoriesUnlessAsked(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "main.go"), "needle\n")
	writeFile(t, filepath.Join(root, "node_modules", "dep.js"), "needle\n")
	writeFile(t, filepath.Join(root, ".git", "COMMIT_EDITMSG"), "needle\n")
	svc := newConfined(t, root)

	assert.Equal(t, []string{filepath.Join(root, "main.go")},
		grep(t, svc, &sandboxdv1.GrepRequest{Pattern: "needle", Root: root}).paths())
	assert.Len(t, grep(t, svc,
		&sandboxdv1.GrepRequest{Pattern: "needle", Root: root, IncludeDefaultIgnored: true}).paths(), 3)
}

// Neither the walk nor a symlink is a way to get a path outside the jail back.
func TestGrep_NeverReturnsPathsOutsideTheJail(t *testing.T) {
	root := tempRoot(t)
	outside := tempRoot(t)
	writeFile(t, filepath.Join(outside, "secret.txt"), "needle in the clear\n")
	writeFile(t, filepath.Join(root, "inside.txt"), "needle\n")
	requireSymlink(t, filepath.Join(outside, "secret.txt"), filepath.Join(root, "escape.txt"))
	requireSymlink(t, outside, filepath.Join(root, "escapedir"))

	confined := newConfined(t, root)
	stream := grep(t, confined, &sandboxdv1.GrepRequest{Pattern: "needle", Root: root})
	assert.Equal(t, []string{filepath.Join(root, "inside.txt")}, stream.paths())

	// Searching outside the jail directly is refused rather than answered.
	err := confined.Grep(&sandboxdv1.GrepRequest{Pattern: "needle", Root: outside},
		newGrepStream(context.Background()))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	// Unconfined, there is nothing to escape and nothing to refuse.
	unconfined := newUnconfined(t, root)
	open := grep(t, unconfined, &sandboxdv1.GrepRequest{Pattern: "needle", Root: outside})
	assert.Equal(t, []string{filepath.Join(outside, "secret.txt")}, open.paths())
}

func TestGrep_SymlinkLoopTerminates(t *testing.T) {
	root := tempRoot(t)
	inner := filepath.Join(root, "a", "b")
	require.NoError(t, os.MkdirAll(inner, 0o755))
	writeFile(t, filepath.Join(inner, "file.txt"), "needle\n")
	requireSymlink(t, filepath.Join(root, "a"), filepath.Join(inner, "loop"))
	svc := newConfined(t, root)

	done := make(chan *fakeGrepStream, 1)
	go func() { done <- grep(t, svc, &sandboxdv1.GrepRequest{Pattern: "needle", Root: root}) }()
	select {
	case stream := <-done:
		assert.Equal(t, []string{filepath.Join(inner, "file.txt")}, stream.paths())
	case <-time.After(10 * time.Second):
		t.Fatal("the walk did not terminate on a symlink loop")
	}
}

// Same tree, same order, every time.
func TestGrep_ResultsAreOrderedDeterministically(t *testing.T) {
	root := tempRoot(t)
	for _, name := range []string{"c", "a", "b"} {
		writeFile(t, filepath.Join(root, name, "f.txt"), "needle\n")
	}
	svc := newConfined(t, root)

	want := []string{
		filepath.Join(root, "a", "f.txt"),
		filepath.Join(root, "b", "f.txt"),
		filepath.Join(root, "c", "f.txt"),
	}
	for i := 0; i < 5; i++ {
		assert.Equal(t, want, grep(t, svc, &sandboxdv1.GrepRequest{Pattern: "needle", Root: root}).paths())
	}
}

// A CRLF file greps as lines, not as lines with a stray control character; the
// file itself is untouched.
func TestGrep_HandlesCRLFFiles(t *testing.T) {
	root := tempRoot(t)
	content := "alpha\r\nneedle\r\nomega\r\n"
	path := writeFile(t, filepath.Join(root, "crlf.txt"), content)
	svc := newConfined(t, root)

	stream := grep(t, svc, &sandboxdv1.GrepRequest{Pattern: "needle", Root: root, ContextLines: 1})

	require.Len(t, stream.matches, 1)
	assert.Equal(t, "needle", stream.matches[0].GetLine())
	assert.Equal(t, []string{"alpha"}, stream.matches[0].GetBeforeContext())
	assert.Equal(t, content, readBack(t, path))
}
