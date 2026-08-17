package fs_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

// Distant replacements produce separate hunks, and the second hunk's new-side
// line numbers account for the lines the first one added.
func TestDiff_SeparateHunksTrackLineDrift(t *testing.T) {
	root := tempRoot(t)
	var b strings.Builder
	for i := 1; i <= 40; i++ {
		if i == 5 || i == 30 {
			b.WriteString("target\n")
			continue
		}
		b.WriteString("filler\n")
	}
	path := writeFile(t, filepath.Join(root, "f.txt"), b.String())
	svc := newConfined(t, root)

	resp, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path:       path,
		OldString:  "target",
		NewString:  "one\ntwo",
		ReplaceAll: true,
	})
	require.NoError(t, err)

	diff := resp.GetDiff()
	assert.Equal(t, uint32(2), resp.GetReplacements())
	assert.Equal(t, 2, strings.Count(diff, "@@ -"), "two distant changes are two hunks")
	assert.Contains(t, diff, "@@ -2,7 +2,8 @@", "the first hunk starts three lines of context above line 5")
	assert.Contains(t, diff, "@@ -27,7 +28,8 @@",
		"the second hunk's new-side numbering is shifted by the line the first one added")
	assert.Equal(t, 2, strings.Count(diff, "-target"))
	assert.Equal(t, 2, strings.Count(diff, "+one"))
}

// Two replacements on one line are one hunk: emitting the line as removed twice
// would produce a diff that does not apply.
func TestDiff_TwoChangesOnOneLineAreOneHunk(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "f.txt"), "one\nx = a + a\ntwo\n")
	svc := newConfined(t, root)

	resp, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path: path, OldString: "a", NewString: "b", ReplaceAll: true,
	})
	require.NoError(t, err)

	diff := resp.GetDiff()
	assert.Equal(t, 1, strings.Count(diff, "@@ -"))
	assert.Equal(t, 1, strings.Count(diff, "-x = a + a"))
	assert.Equal(t, 1, strings.Count(diff, "+x = b + b"))
	assert.Equal(t, "one\nx = b + b\ntwo\n", readBack(t, path))
}

// A deletion shows the removed lines and adds nothing back.
func TestDiff_Deletion(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "f.txt"), "keep\ndrop me\nkeep too\n")
	svc := newConfined(t, root)

	resp, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path: path, OldString: "drop me\n", NewString: "",
	})
	require.NoError(t, err)

	assert.Equal(t, "keep\nkeep too\n", readBack(t, path))
	assert.Contains(t, resp.GetDiff(), "-drop me")
	assert.NotContains(t, resp.GetDiff(), "+drop me")
}

// A very large replace_all is trimmed rather than emitted whole: the diff goes
// into a model's context.
func TestDiff_IsCappedWithANote(t *testing.T) {
	root := tempRoot(t)
	var b strings.Builder
	for i := 0; i < 400; i++ {
		b.WriteString("target\n\n\n\n\n\n\n\n")
	}
	path := writeFile(t, filepath.Join(root, "f.txt"), b.String())
	svc := newConfined(t, root)

	resp, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path: path, OldString: "target", NewString: "replaced", ReplaceAll: true,
	})
	require.NoError(t, err)

	assert.Equal(t, uint32(400), resp.GetReplacements())
	assert.Contains(t, resp.GetDiff(), "diff trimmed at")
	assert.Less(t, strings.Count(resp.GetDiff(), "\n"), 200)
	assert.Equal(t, 400, strings.Count(readBack(t, path), "replaced"),
		"the trimmed diff describes a complete edit; only the description was cut")
}

// The diff header names the file, and CRLF lines render without their carriage
// returns while the file keeps them.
func TestDiff_HeaderAndCRLFRendering(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "crlf.txt"), "alpha\r\nbeta\r\ngamma\r\n")
	svc := newConfined(t, root)

	resp, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path: path, OldString: "beta", NewString: "BETA",
	})
	require.NoError(t, err)

	diff := resp.GetDiff()
	assert.True(t, strings.HasPrefix(diff, "--- "+path+"\n+++ "+path+"\n"))
	assert.NotContains(t, diff, "\r", "the rendering drops carriage returns")
	assert.Contains(t, readBack(t, path), "\r\n", "the file keeps them")
}
