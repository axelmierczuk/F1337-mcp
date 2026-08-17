package fs_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
)

func TestEditFile_ReplacesAUniqueMatch(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "code.go"), "package main\n\nfunc main() {\n\tprintln(\"hi\")\n}\n")
	svc := newConfined(t, root)

	resp, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path:      path,
		OldString: "println(\"hi\")",
		NewString: "println(\"hello\")",
	})
	require.NoError(t, err)

	assert.Equal(t, uint32(1), resp.GetReplacements())
	assert.Equal(t, "package main\n\nfunc main() {\n\tprintln(\"hello\")\n}\n", readBack(t, path))
	assert.Contains(t, resp.GetDiff(), "-\tprintln(\"hi\")")
	assert.Contains(t, resp.GetDiff(), "+\tprintln(\"hello\")")
	assert.Contains(t, resp.GetDiff(), "@@", "the diff is unified, with a hunk header")
	assert.Empty(t, tempSiblings(t, root))
}

// The uniqueness rule, and the reason it exists: with two candidates, a
// replacement would pick one and the caller would find out which by reading the
// diff afterwards.
func TestEditFile_TwoOccurrencesFailAndLeaveTheFileUnmodified(t *testing.T) {
	root := tempRoot(t)
	original := "value := 1\nother := 2\nvalue := 1\n"
	path := writeFile(t, filepath.Join(root, "dup.go"), original)
	svc := newConfined(t, root)

	resp, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path:      path,
		OldString: "value := 1",
		NewString: "value := 3",
	})

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "occurs 2 times",
		"the error names the count so the caller knows to add context")
	assert.Contains(t, status.Convert(err).Message(), "lines 1, 3")
	assert.Equal(t, original, readBack(t, path), "a rejected edit does not touch the file")
	assert.Empty(t, tempSiblings(t, root))
}

func TestEditFile_ReplaceAllReplacesEveryOccurrence(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "dup.go"), "a := 1\nb := 1\nc := 1\n")
	svc := newConfined(t, root)

	resp, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path:       path,
		OldString:  ":= 1",
		NewString:  ":= 2",
		ReplaceAll: true,
	})
	require.NoError(t, err)

	assert.Equal(t, uint32(3), resp.GetReplacements())
	assert.Equal(t, "a := 2\nb := 2\nc := 2\n", readBack(t, path))
}

func TestEditFile_ZeroOccurrencesFailsAndLeavesTheFileUnmodified(t *testing.T) {
	root := tempRoot(t)
	original := "one\ntwo\n"
	path := writeFile(t, filepath.Join(root, "f.txt"), original)
	svc := newConfined(t, root)

	_, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path:      path,
		OldString: "three",
		NewString: "four",
	})

	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "does not appear")
	assert.Equal(t, original, readBack(t, path))
}

// The usual cause of a failed match is whitespace, so a near miss is named
// rather than left for the caller to find by bisection.
func TestEditFile_ZeroOccurrencesFlagsAWhitespaceNearMiss(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "f.go"), "func main() {\n\t\tif x {\n\t\t}\n}\n")
	svc := newConfined(t, root)

	_, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path:      path,
		OldString: "    if x {", // four spaces where the file has two tabs
		NewString: "    if y {",
	})

	require.Error(t, err)
	msg := status.Convert(err).Message()
	assert.Contains(t, msg, "line 2")
	assert.Contains(t, msg, "whitespace")
}

func TestEditFile_MultiLineOldString(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "f.go"),
		"func a() {\n\treturn 1\n}\n\nfunc b() {\n\treturn 2\n}\n")
	svc := newConfined(t, root)

	resp, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path:      path,
		OldString: "func b() {\n\treturn 2\n}",
		NewString: "func b() {\n\t// changed\n\treturn 22\n}",
	})
	require.NoError(t, err)

	assert.Equal(t, uint32(1), resp.GetReplacements())
	assert.Equal(t, "func a() {\n\treturn 1\n}\n\nfunc b() {\n\t// changed\n\treturn 22\n}\n", readBack(t, path))
	assert.Contains(t, resp.GetDiff(), "+\t// changed")
	assert.Contains(t, resp.GetDiff(), "-\treturn 2")
}

// A CRLF file keeps its endings across an edit, and a match composed with LF
// against it is diagnosed rather than half-applied.
func TestEditFile_CRLF(t *testing.T) {
	root := tempRoot(t)

	t.Run("endings are preserved", func(t *testing.T) {
		path := writeFile(t, filepath.Join(root, "keep.txt"), "alpha\r\nbeta\r\ngamma\r\n")
		svc := newConfined(t, root)

		_, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
			Path:      path,
			OldString: "beta",
			NewString: "BETA",
		})
		require.NoError(t, err)
		assert.Equal(t, "alpha\r\nBETA\r\ngamma\r\n", readBack(t, path),
			"not one terminator was rewritten")
	})

	t.Run("an LF old_string against a CRLF file is diagnosable", func(t *testing.T) {
		original := "alpha\r\nbeta\r\ngamma\r\n"
		path := writeFile(t, filepath.Join(root, "mismatch.txt"), original)
		svc := newConfined(t, root)

		_, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
			Path:      path,
			OldString: "alpha\nbeta",
			NewString: "alpha\nBETA",
		})

		require.Error(t, err)
		msg := status.Convert(err).Message()
		assert.Contains(t, msg, "CRLF", "the error names the cause rather than saying not found")
		assert.Equal(t, original, readBack(t, path), "and the file is untouched")
	})

	t.Run("an LF new_string into a CRLF file is refused", func(t *testing.T) {
		original := "alpha\r\nbeta\r\n"
		path := writeFile(t, filepath.Join(root, "newmix.txt"), original)
		svc := newConfined(t, root)

		_, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
			Path:      path,
			OldString: "beta",
			NewString: "beta\nadded",
		})

		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.Contains(t, status.Convert(err).Message(), "CRLF")
		assert.Equal(t, original, readBack(t, path),
			"the agent will not mix endings into a file behind the caller's back")
	})

	t.Run("a CRLF new_string into an LF file is refused", func(t *testing.T) {
		original := "alpha\nbeta\n"
		path := writeFile(t, filepath.Join(root, "lf.txt"), original)
		svc := newConfined(t, root)

		_, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
			Path:      path,
			OldString: "beta",
			NewString: "beta\r\nadded",
		})

		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.Equal(t, original, readBack(t, path))
	})
}

func TestEditFile_PreservesMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "script.sh"), "#!/bin/sh\necho hi\n")
	require.NoError(t, os.Chmod(path, 0o755))
	svc := newConfined(t, root)

	_, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path:      path,
		OldString: "echo hi",
		NewString: "echo hello",
	})
	require.NoError(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm(),
		"an executable script is still executable after an edit")
}

func TestEditFile_RejectsANoOpAndAnEmptyOldString(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "f.txt"), "same\n")
	svc := newConfined(t, root)

	_, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path: path, OldString: "same", NewString: "same",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "identical")

	_, err = svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path: path, OldString: "", NewString: "x",
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Equal(t, "same\n", readBack(t, path))
}

func TestEditFile_RefusesFilesThatAreNotUTF8(t *testing.T) {
	root := tempRoot(t)
	path := filepath.Join(root, "bin.dat")
	original := []byte{'a', 'b', 0xff, 0xfe, 'c'}
	require.NoError(t, os.WriteFile(path, original, 0o644))
	svc := newConfined(t, root)

	_, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path: path, OldString: "ab", NewString: "cd",
	})

	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "UTF-8")
	back, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, original, back)
}

func TestEditFile_RefusesFilesOverTheEditLimit(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "huge.txt"), strings.Repeat("x", 4096))
	svc := agentfsService(t, root, 1024)

	_, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path: path, OldString: "x", NewString: "y", ReplaceAll: true,
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// Two edits to the same file must not interleave: each has to read what the
// other wrote, not the file as it was before both started.
func TestEditFile_ConcurrentEditsDoNotLoseEachOther(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "shared.txt"),
		"alpha = 0\nbeta = 0\ngamma = 0\ndelta = 0\n")
	svc := newConfined(t, root)

	edits := []struct{ from, to string }{
		{"alpha = 0", "alpha = 1"},
		{"beta = 0", "beta = 2"},
		{"gamma = 0", "gamma = 3"},
		{"delta = 0", "delta = 4"},
	}

	var wg sync.WaitGroup
	errs := make([]error, len(edits))
	start := make(chan struct{})
	for i, edit := range edits {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, errs[i] = svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
				Path: path, OldString: edit.from, NewString: edit.to,
			})
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "edit %d", i)
	}
	assert.Equal(t, "alpha = 1\nbeta = 2\ngamma = 3\ndelta = 4\n", readBack(t, path),
		"every edit survives; none was computed against a file another had already replaced")
	assert.Empty(t, tempSiblings(t, root))
}

// A concurrent write and edit of one path serialise too, so neither lands on
// top of a file the other had already read.
func TestEditFile_SerialisesAgainstWriteFile(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "shared.txt"), "start\n")
	svc := newConfined(t, root)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = svc.WriteFile(writeStreamFor(context.Background(),
			&sandboxdv1.WriteFileHeader{Path: path}, []byte("written\n"), 4))
	}()
	go func() {
		defer wg.Done()
		_, _ = svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
			Path: path, OldString: "start", NewString: "edited",
		})
	}()
	wg.Wait()

	// Either order is legitimate; a mixture of the two is not.
	final := readBack(t, path)
	assert.Contains(t, []string{"written\n", "edited\n"}, final,
		"the file holds one call's whole result, never a blend of both")
	assert.Empty(t, tempSiblings(t, root))
}

func TestEditFile_DiffIsTrimmedRatherThanWholeFile(t *testing.T) {
	root := tempRoot(t)
	var b strings.Builder
	for i := 0; i < 200; i++ {
		b.WriteString("filler\n")
	}
	b.WriteString("needle\n")
	for i := 0; i < 200; i++ {
		b.WriteString("filler\n")
	}
	path := writeFile(t, filepath.Join(root, "long.txt"), b.String())
	svc := newConfined(t, root)

	resp, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path: path, OldString: "needle", NewString: "thread",
	})
	require.NoError(t, err)

	lines := strings.Count(resp.GetDiff(), "\n")
	assert.Less(t, lines, 12, "a one-line change in a 401-line file is a small diff, not a whole-file one")
	assert.Contains(t, resp.GetDiff(), "-needle")
	assert.Contains(t, resp.GetDiff(), "+thread")
}

func TestEditFile_MissingFile(t *testing.T) {
	root := tempRoot(t)
	svc := newConfined(t, root)

	_, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path: filepath.Join(root, "gone.txt"), OldString: "a", NewString: "b",
	})
	assert.Equal(t, codes.NotFound, status.Code(err))
}
