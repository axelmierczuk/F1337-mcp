//go:build !windows

package fs_test

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
)

// Opening a named pipe blocks inside open(2) until a writer appears. Nothing
// times it out, a cancelled request cannot interrupt it, and the handler
// goroutine is stranded for the life of the process — so every RPC that opens a
// path a caller can name has to refuse one rather than discover it after the
// open.
//
// These tests run everywhere but Windows, which has no mkfifo and reaches the
// same code through the same regular-file checks.

// mkfifo creates a named pipe, skipping the test where the platform will not.
func mkfifo(t *testing.T, path string) string {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Skipf("mkfifo %s: %v", path, err)
	}
	return path
}

// withinTimeout runs fn and fails if it has not returned in time. The goroutine
// is abandoned rather than waited for: a regression here blocks in a syscall
// that nothing can interrupt, so the only way to report it is to stop waiting.
func withinTimeout(t *testing.T, what string, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatalf("%s blocked on a named pipe instead of refusing it", what)
		return nil
	}
}

func TestReadFile_RefusesANamedPipe(t *testing.T) {
	root := tempRoot(t)
	pipe := mkfifo(t, filepath.Join(root, "pipe"))
	svc := newConfined(t, root)

	err := withinTimeout(t, "ReadFile", func() error {
		return svc.ReadFile(&sandboxdv1.ReadFileRequest{Path: pipe}, newReadStream(context.Background()))
	})

	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "not a regular file")
}

func TestEditFile_RefusesANamedPipe(t *testing.T) {
	root := tempRoot(t)
	pipe := mkfifo(t, filepath.Join(root, "pipe"))
	svc := newConfined(t, root)

	err := withinTimeout(t, "EditFile", func() error {
		_, err := svc.EditFile(context.Background(),
			&sandboxdv1.EditFileRequest{Path: pipe, OldString: "a", NewString: "b"})
		return err
	})

	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// WriteFile never opens its target — it commits a sibling over it — so the
// hazard here is the other one: replacing a device or a pipe with a regular
// file, and blocking in the append that reads the original back.
func TestWriteFile_RefusesANamedPipeTarget(t *testing.T) {
	root := tempRoot(t)
	pipe := mkfifo(t, filepath.Join(root, "pipe"))
	svc := newConfined(t, root)

	for _, appendMode := range []bool{false, true} {
		err := withinTimeout(t, "WriteFile", func() error {
			return svc.WriteFile(writeStreamFor(context.Background(),
				&sandboxdv1.WriteFileHeader{Path: pipe, Append: appendMode}, []byte("x"), 4))
		})
		require.Error(t, err, "append=%v", appendMode)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err), "append=%v", appendMode)
	}

	info, err := os.Lstat(pipe)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeNamedPipe, "and the pipe is still a pipe")
}

// StatPath describes what is there, and describing a pipe must not open it to
// sniff whether it is text.
func TestStatPath_DescribesANamedPipeWithoutOpeningIt(t *testing.T) {
	root := tempRoot(t)
	pipe := mkfifo(t, filepath.Join(root, "pipe"))
	svc := newConfined(t, root)

	var resp *sandboxdv1.StatPathResponse
	err := withinTimeout(t, "StatPath", func() error {
		var err error
		resp, err = svc.StatPath(context.Background(), &sandboxdv1.StatPathRequest{Path: pipe})
		return err
	})

	require.NoError(t, err)
	assert.True(t, resp.GetExists())
	assert.False(t, resp.GetMetadata().GetIsBinary(), "nothing was read to decide this")
}

// The walk already skipped a pipe reached directly. A symlink to one was
// admitted, because the containment check asked whether the target was a
// directory rather than whether it was a regular file — and Grep opens what the
// walk yields.
func TestGrep_DoesNotOpenANamedPipeReachedThroughASymlink(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "a.txt"), "needle\n")
	require.NoError(t, os.Mkdir(filepath.Join(root, "sub"), 0o755))
	pipe := mkfifo(t, filepath.Join(root, "sub", "pipe"))
	requireSymlink(t, pipe, filepath.Join(root, "pipelink"))
	svc := newConfined(t, root)

	stream := newGrepStream(context.Background())
	err := withinTimeout(t, "Grep", func() error {
		return svc.Grep(&sandboxdv1.GrepRequest{Pattern: "needle", Root: root}, stream)
	})

	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join(root, "a.txt")}, stream.paths())
}

// Glob yields the same set, so a pipe behind a link is not returned as a file.
func TestGlob_DoesNotReturnANamedPipeReachedThroughASymlink(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "real.txt"), "")
	pipe := mkfifo(t, filepath.Join(root, "pipe"))
	requireSymlink(t, pipe, filepath.Join(root, "link.txt"))
	svc := newConfined(t, root)

	resp := glob(t, svc, &sandboxdv1.GlobRequest{Pattern: "*.txt", Root: root})
	assert.Equal(t, []string{"real.txt"}, relative(t, root, resp.GetPaths()))
}

// The ignore stack opens every .gitignore it finds, which is a file name anyone
// who can write into the tree chooses.
func TestGrep_DoesNotReadANamedPipeGitignore(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "a.txt"), "needle\n")
	mkfifo(t, filepath.Join(root, ".gitignore"))
	svc := newConfined(t, root)

	stream := newGrepStream(context.Background())
	err := withinTimeout(t, "Grep", func() error {
		return svc.Grep(&sandboxdv1.GrepRequest{
			Pattern: "needle", Root: root, RespectGitignore: true}, stream)
	})

	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join(root, "a.txt")}, stream.paths())
}
