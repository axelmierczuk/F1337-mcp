package fs_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

func TestStatPath_ReportsMetadata(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "file.txt"), "twelve bytes")
	svc := newConfined(t, root)

	resp, err := svc.StatPath(context.Background(), &sandboxdv1.StatPathRequest{Path: path})
	require.NoError(t, err)

	require.True(t, resp.GetExists())
	md := resp.GetMetadata()
	assert.Equal(t, path, md.GetPath())
	assert.Equal(t, uint64(12), md.GetSizeBytes())
	assert.False(t, md.GetIsDir())
	assert.False(t, md.GetIsSymlink())
	assert.False(t, md.GetIsBinary())
	assert.NotZero(t, md.GetModifiedAt().GetSeconds())
	if runtime.GOOS != "windows" {
		assert.Equal(t, uint32(0o644), md.GetMode())
	}
}

// A missing path is a false, not an error. Making the caller parse a NotFound
// to learn a boolean is what this avoids.
func TestStatPath_MissingIsNotAnError(t *testing.T) {
	root := tempRoot(t)
	svc := newConfined(t, root)

	resp, err := svc.StatPath(context.Background(),
		&sandboxdv1.StatPathRequest{Path: filepath.Join(root, "nothing-here")})

	require.NoError(t, err)
	assert.False(t, resp.GetExists())
	assert.Nil(t, resp.GetMetadata())
}

func TestStatPath_ReportsDirectoriesAndBinaries(t *testing.T) {
	root := tempRoot(t)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "dir"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "bin"), []byte{0, 1, 2, 3}, 0o644))
	svc := newConfined(t, root)

	dir, err := svc.StatPath(context.Background(),
		&sandboxdv1.StatPathRequest{Path: filepath.Join(root, "dir")})
	require.NoError(t, err)
	assert.True(t, dir.GetMetadata().GetIsDir())

	bin, err := svc.StatPath(context.Background(),
		&sandboxdv1.StatPathRequest{Path: filepath.Join(root, "bin")})
	require.NoError(t, err)
	assert.True(t, bin.GetMetadata().GetIsBinary())
}

// A symlink is described, not followed: is_symlink and its target, so a caller
// can tell a link from the thing it points at.
func TestStatPath_DescribesSymlinks(t *testing.T) {
	root := tempRoot(t)
	target := writeFile(t, filepath.Join(root, "target.txt"), "content")
	link := filepath.Join(root, "link.txt")
	requireSymlink(t, target, link)
	svc := newConfined(t, root)

	resp, err := svc.StatPath(context.Background(), &sandboxdv1.StatPathRequest{Path: link})
	require.NoError(t, err)

	require.True(t, resp.GetExists())
	assert.True(t, resp.GetMetadata().GetIsSymlink())
	assert.Equal(t, target, resp.GetMetadata().GetSymlinkTarget())
	assert.Equal(t, link, resp.GetMetadata().GetPath())
}

func TestListDirectory_ListsEntries(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "b.txt"), "b")
	writeFile(t, filepath.Join(root, "a.txt"), "a")
	writeFile(t, filepath.Join(root, ".hidden"), "h")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "sub"), 0o755))
	svc := newConfined(t, root)

	resp, err := svc.ListDirectory(context.Background(), &sandboxdv1.ListDirectoryRequest{Path: root})
	require.NoError(t, err)

	assert.Equal(t, root, resp.GetPath())
	assert.Equal(t, []string{
		filepath.Join(root, "a.txt"),
		filepath.Join(root, "b.txt"),
		filepath.Join(root, "sub"),
	}, entryPaths(resp.GetEntries()), "entries come back sorted, and hidden ones are left out by default")
	assert.False(t, resp.GetTruncation().GetTruncated())

	withHidden, err := svc.ListDirectory(context.Background(),
		&sandboxdv1.ListDirectoryRequest{Path: root, IncludeHidden: true})
	require.NoError(t, err)
	assert.Len(t, withHidden.GetEntries(), 4)
}

func TestListDirectory_Recursive(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "a", "b", "deep.txt"), "deep")
	svc := newConfined(t, root)

	flat, err := svc.ListDirectory(context.Background(),
		&sandboxdv1.ListDirectoryRequest{Path: root})
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join(root, "a")}, entryPaths(flat.GetEntries()))

	deep, err := svc.ListDirectory(context.Background(),
		&sandboxdv1.ListDirectoryRequest{Path: root, Recursive: true})
	require.NoError(t, err)
	assert.Equal(t, []string{
		filepath.Join(root, "a"),
		filepath.Join(root, "a", "b"),
		filepath.Join(root, "a", "b", "deep.txt"),
	}, entryPaths(deep.GetEntries()))
}

// The cap stops the walk rather than trimming a completed one, and the response
// says it was capped.
func TestListDirectory_RecursiveRespectsCapAndReportsTruncation(t *testing.T) {
	root := tempRoot(t)
	for i := 0; i < 40; i++ {
		writeFile(t, filepath.Join(root, fmt.Sprintf("d%02d", i), "f.txt"), "x")
	}
	svc := newConfined(t, root)

	resp, err := svc.ListDirectory(context.Background(),
		&sandboxdv1.ListDirectoryRequest{Path: root, Recursive: true, Limit: 10})
	require.NoError(t, err)

	assert.Len(t, resp.GetEntries(), 10)
	assert.True(t, resp.GetTruncation().GetTruncated())
}

func TestListDirectory_ReportsSymlinkEntries(t *testing.T) {
	root := tempRoot(t)
	target := writeFile(t, filepath.Join(root, "real.txt"), "real")
	requireSymlink(t, target, filepath.Join(root, "alias.txt"))
	svc := newConfined(t, root)

	resp, err := svc.ListDirectory(context.Background(), &sandboxdv1.ListDirectoryRequest{Path: root})
	require.NoError(t, err)

	var alias *sandboxdv1.FileMetadata
	for _, entry := range resp.GetEntries() {
		if filepath.Base(entry.GetPath()) == "alias.txt" {
			alias = entry
		}
	}
	require.NotNil(t, alias)
	assert.True(t, alias.GetIsSymlink())
	assert.Equal(t, target, alias.GetSymlinkTarget())
}

// A symlink loop in a listed tree terminates, because a symlinked directory is
// reported but never descended into.
func TestListDirectory_SymlinkLoopTerminates(t *testing.T) {
	root := tempRoot(t)
	inner := filepath.Join(root, "a", "b")
	require.NoError(t, os.MkdirAll(inner, 0o755))
	requireSymlink(t, filepath.Join(root, "a"), filepath.Join(inner, "loop"))
	svc := newConfined(t, root)

	resp, err := svc.ListDirectory(context.Background(),
		&sandboxdv1.ListDirectoryRequest{Path: root, Recursive: true, Limit: 5000})
	require.NoError(t, err)
	assert.Len(t, resp.GetEntries(), 3, "a, a/b and the loop link itself, and no cycle")
}

func TestListDirectory_RejectsAFile(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "f.txt"), "x")
	svc := newConfined(t, root)

	_, err := svc.ListDirectory(context.Background(), &sandboxdv1.ListDirectoryRequest{Path: path})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func entryPaths(entries []*sandboxdv1.FileMetadata) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.GetPath())
	}
	return out
}
