package fs_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	agentfs "github.com/axelmierczuk/sandboxd-mcp/internal/agent/fs"
)

// A write commits by renaming a sibling over the target, and a rename over a
// symlink replaces the link with a regular file. So a write to a symlinked path
// has to land on the file the link names, in both jail modes.
//
// The confined agent gets this from the jail, which resolves every symlink
// before returning a path. The unconfined one — the *default* agent, since the
// jail is only wired in with exec disabled — gets a normalised path with its
// symlinks intact, and without the service resolving the last component itself
// the write unlinked the symlink, wrote a new file where it stood, and left the
// file the caller meant to change untouched.
func TestWriteFile_WritesThroughASymlinkInBothJailModes(t *testing.T) {
	for _, mode := range []struct {
		name string
		svc  func(*testing.T, string) *agentfs.Service
	}{
		{"confined", newConfined},
		{"unconfined", newUnconfined},
	} {
		t.Run(mode.name, func(t *testing.T) {
			root := tempRoot(t)
			target := writeFile(t, filepath.Join(root, "real.txt"), "original\n")
			if runtime.GOOS != "windows" {
				require.NoError(t, os.Chmod(target, 0o640))
			}
			link := filepath.Join(root, "link.txt")
			requireSymlink(t, target, link)
			svc := mode.svc(t, root)

			stream := writeStreamFor(context.Background(),
				&sandboxdv1.WriteFileHeader{Path: link}, []byte("new\n"), 4)
			require.NoError(t, svc.WriteFile(stream))

			info, err := os.Lstat(link)
			require.NoError(t, err)
			assert.NotZero(t, info.Mode()&os.ModeSymlink,
				"the link is still a link; the write went through it rather than over it")
			assert.Equal(t, "new\n", readBack(t, target), "and landed in the file it names")
			assert.Equal(t, target, stream.resp.GetPath(),
				"the response names the file that was written, not the link")
			assert.False(t, stream.resp.GetCreated(), "the file it names already existed")

			if runtime.GOOS != "windows" {
				st, err := os.Stat(target)
				require.NoError(t, err)
				assert.Equal(t, os.FileMode(0o640), st.Mode().Perm(),
					"the target keeps its own mode, and never picks up the symlink's 0777")
			}
		})
	}
}

// The same for an append, which reads the current contents back into the temp
// file first: it has to read the file it is about to commit to.
func TestWriteFile_AppendsThroughASymlink(t *testing.T) {
	root := tempRoot(t)
	target := writeFile(t, filepath.Join(root, "log.txt"), "first\n")
	link := filepath.Join(root, "link.txt")
	requireSymlink(t, target, link)
	svc := newUnconfined(t, root)

	require.NoError(t, svc.WriteFile(writeStreamFor(context.Background(),
		&sandboxdv1.WriteFileHeader{Path: link, Append: true}, []byte("second\n"), 3)))

	info, err := os.Lstat(link)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeSymlink)
	assert.Equal(t, "first\nsecond\n", readBack(t, target))
}

// A dangling symlink has nothing to write through, so the write lands on the
// name — but the new file must not inherit the link's own permission bits,
// which are 0777 on Linux.
func TestWriteFile_DanglingSymlinkDoesNotDonateItsMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	root := tempRoot(t)
	link := filepath.Join(root, "dangling.txt")
	requireSymlink(t, filepath.Join(root, "nowhere.txt"), link)
	svc := newUnconfined(t, root)

	require.NoError(t, svc.WriteFile(writeStreamFor(context.Background(),
		&sandboxdv1.WriteFileHeader{Path: link}, []byte("x\n"), 4)))

	info, err := os.Stat(link)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm(),
		"a file created where a dangling link stood takes the default mode, not lrwxrwxrwx")
}

// EditFile commits the same way, and got the same treatment: it read the
// symlink's target and wrote the result over the link, so the edit landed in a
// file nobody asked for while the file that was read kept its old contents.
func TestEditFile_EditsThroughASymlinkInBothJailModes(t *testing.T) {
	for _, mode := range []struct {
		name string
		svc  func(*testing.T, string) *agentfs.Service
	}{
		{"confined", newConfined},
		{"unconfined", newUnconfined},
	} {
		t.Run(mode.name, func(t *testing.T) {
			root := tempRoot(t)
			target := writeFile(t, filepath.Join(root, "real.txt"), "before\n")
			link := filepath.Join(root, "link.txt")
			requireSymlink(t, target, link)
			svc := mode.svc(t, root)

			resp, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
				Path: link, OldString: "before", NewString: "after"})
			require.NoError(t, err)

			info, err := os.Lstat(link)
			require.NoError(t, err)
			assert.NotZero(t, info.Mode()&os.ModeSymlink, "the link is still a link")
			assert.Equal(t, "after\n", readBack(t, target),
				"the edit landed in the file the link names, which is the file it was read from")
			assert.Equal(t, target, resp.GetPath())
		})
	}
}

// Two writes naming one file through two spellings take one lock, so the second
// cannot commit on top of a file the first had already read.
func TestWriteFile_SymlinkAndTargetShareOneLock(t *testing.T) {
	root := tempRoot(t)
	target := writeFile(t, filepath.Join(root, "real.txt"), "alpha = 0\nbeta = 0\n")
	link := filepath.Join(root, "link.txt")
	requireSymlink(t, target, link)
	svc := newUnconfined(t, root)

	done := make(chan error, 2)
	go func() {
		_, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
			Path: link, OldString: "alpha = 0", NewString: "alpha = 1"})
		done <- err
	}()
	go func() {
		_, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
			Path: target, OldString: "beta = 0", NewString: "beta = 2"})
		done <- err
	}()
	require.NoError(t, <-done)
	require.NoError(t, <-done)

	assert.Equal(t, "alpha = 1\nbeta = 2\n", readBack(t, target),
		"both edits survive: naming the file through a link is not a way to dodge its lock")
}
