package fs_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	agentfs "github.com/axelmierczuk/sandboxd-mcp/internal/agent/fs"
)

// --- MakeDirectory ---------------------------------------------------------

func TestMakeDirectory_CreatesAndIsIdempotent(t *testing.T) {
	root := tempRoot(t)
	svc := newConfined(t, root)
	path := filepath.Join(root, "made")

	first, err := svc.MakeDirectory(context.Background(), &sandboxdv1.MakeDirectoryRequest{Path: path})
	require.NoError(t, err)
	assert.Equal(t, path, first.GetPath())
	assert.True(t, first.GetCreated())
	assert.DirExists(t, path)

	// An existing directory is the state the caller asked for, not an error.
	second, err := svc.MakeDirectory(context.Background(), &sandboxdv1.MakeDirectoryRequest{Path: path})
	require.NoError(t, err)
	assert.False(t, second.GetCreated(), "created:false is how the caller tells the two apart")
}

// An existing file at that path is an error: the caller asked for a directory
// and there is not one.
func TestMakeDirectory_RefusesAnExistingFile(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "taken"), "i am a file\n")
	svc := newConfined(t, root)

	_, err := svc.MakeDirectory(context.Background(), &sandboxdv1.MakeDirectoryRequest{Path: path})

	require.Error(t, err)
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "not a directory")
	assert.Equal(t, "i am a file\n", readBack(t, path), "and the file is untouched")
}

// create_parents means what it means in WriteFile.
func TestMakeDirectory_CreateParents(t *testing.T) {
	root := tempRoot(t)
	svc := newConfined(t, root)

	deep := filepath.Join(root, "a", "b", "c")
	resp, err := svc.MakeDirectory(context.Background(),
		&sandboxdv1.MakeDirectoryRequest{Path: deep, CreateParents: true})
	require.NoError(t, err)
	assert.True(t, resp.GetCreated())
	assert.DirExists(t, deep)

	// Without it, a missing parent is a NotFound rather than a silent mkdir -p.
	orphan := filepath.Join(root, "x", "y")
	_, err = svc.MakeDirectory(context.Background(), &sandboxdv1.MakeDirectoryRequest{Path: orphan})
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.NoDirExists(t, orphan)
	assert.NoDirExists(t, filepath.Join(root, "x"))
}

func TestMakeDirectory_AppliesMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	root := tempRoot(t)
	svc := newConfined(t, root)

	private := filepath.Join(root, "private")
	_, err := svc.MakeDirectory(context.Background(),
		&sandboxdv1.MakeDirectoryRequest{Path: private, Mode: 0o700})
	require.NoError(t, err)
	info, err := os.Stat(private)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(),
		"the mode is applied after creation, so the daemon's umask cannot narrow it")

	defaulted := filepath.Join(root, "defaulted")
	_, err = svc.MakeDirectory(context.Background(), &sandboxdv1.MakeDirectoryRequest{Path: defaulted})
	require.NoError(t, err)
	info, err = os.Stat(defaulted)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())
}

// --- RemovePath ------------------------------------------------------------

func TestRemovePath_RemovesAFile(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "gone.txt"), "x")
	svc := newConfined(t, root)

	resp, err := svc.RemovePath(context.Background(), &sandboxdv1.RemovePathRequest{Path: path})
	require.NoError(t, err)

	assert.Equal(t, uint64(1), resp.GetEntriesRemoved())
	assert.NoFileExists(t, path)
}

func TestRemovePath_MissingIsNotFound(t *testing.T) {
	root := tempRoot(t)
	svc := newConfined(t, root)

	_, err := svc.RemovePath(context.Background(),
		&sandboxdv1.RemovePathRequest{Path: filepath.Join(root, "never-existed")})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// Recursion is opt-in. A non-empty directory without it is an error naming the
// flag, and nothing is removed.
func TestRemovePath_NonEmptyDirectoryNeedsRecursive(t *testing.T) {
	root := tempRoot(t)
	dir := filepath.Join(root, "tree")
	writeFile(t, filepath.Join(dir, "a.txt"), "a")
	writeFile(t, filepath.Join(dir, "sub", "b.txt"), "b")
	svc := newConfined(t, root)

	_, err := svc.RemovePath(context.Background(), &sandboxdv1.RemovePathRequest{Path: dir})

	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "recursive")
	assert.FileExists(t, filepath.Join(dir, "a.txt"), "nothing was removed")
	assert.FileExists(t, filepath.Join(dir, "sub", "b.txt"))
}

func TestRemovePath_EmptyDirectoryNeedsNoFlag(t *testing.T) {
	root := tempRoot(t)
	dir := filepath.Join(root, "empty")
	require.NoError(t, os.Mkdir(dir, 0o755))
	svc := newConfined(t, root)

	resp, err := svc.RemovePath(context.Background(), &sandboxdv1.RemovePathRequest{Path: dir})
	require.NoError(t, err)

	assert.Equal(t, uint64(1), resp.GetEntriesRemoved())
	assert.NoDirExists(t, dir)
}

func TestRemovePath_RecursiveCountsWhatItRemoved(t *testing.T) {
	root := tempRoot(t)
	dir := filepath.Join(root, "tree")
	// tree, tree/sub, tree/a.txt, tree/sub/b.txt, tree/sub/c.txt = 5 entries.
	writeFile(t, filepath.Join(dir, "a.txt"), "a")
	writeFile(t, filepath.Join(dir, "sub", "b.txt"), "b")
	writeFile(t, filepath.Join(dir, "sub", "c.txt"), "c")
	svc := newConfined(t, root)

	resp, err := svc.RemovePath(context.Background(),
		&sandboxdv1.RemovePathRequest{Path: dir, Recursive: true})
	require.NoError(t, err)

	assert.Equal(t, uint64(5), resp.GetEntriesRemoved(),
		"the directory itself and everything under it")
	assert.NoDirExists(t, dir)
}

// The escape case. Removing a symlink removes the link; it never traverses to
// the target, which is how a delete would otherwise leave the jail.
func TestRemovePath_UnlinksASymlinkAndNeverItsTarget(t *testing.T) {
	root := tempRoot(t)
	outside := tempRoot(t)
	secret := writeFile(t, filepath.Join(outside, "secret.txt"), "classified\n")
	link := filepath.Join(root, "escape.txt")
	requireSymlink(t, secret, link)
	svc := newConfined(t, root)

	resp, err := svc.RemovePath(context.Background(), &sandboxdv1.RemovePathRequest{Path: link})
	require.NoError(t, err)

	assert.Equal(t, uint64(1), resp.GetEntriesRemoved())
	assert.NoFileExists(t, link, "the link is gone")
	assert.Equal(t, "classified\n", readBack(t, secret),
		"and the file it pointed at, outside the jail, is untouched")
}

// The case the jail cannot catch, and therefore the one worth a test of its
// own: a symlink pointing at a file *inside* the roots. Resolving the last
// component would delete a legitimate file instead of the link, and no
// containment check would object — silent data loss rather than a refusal.
func TestRemovePath_UnlinksASymlinkToAFileInsideTheJail(t *testing.T) {
	root := tempRoot(t)
	target := writeFile(t, filepath.Join(root, "real.txt"), "keep me\n")
	link := filepath.Join(root, "alias.txt")
	requireSymlink(t, target, link)
	svc := newConfined(t, root)

	resp, err := svc.RemovePath(context.Background(), &sandboxdv1.RemovePathRequest{Path: link})
	require.NoError(t, err)

	assert.Equal(t, uint64(1), resp.GetEntriesRemoved())
	assert.NoFileExists(t, link)
	assert.Equal(t, "keep me\n", readBack(t, target),
		"the file the link named is still there; only the link was removed")
}

// The same for a directory link inside the roots: removing it recursively must
// not empty the directory it names.
func TestRemovePath_RecursiveDoesNotFollowAnInsideSymlinkedDirectory(t *testing.T) {
	root := tempRoot(t)
	realDir := filepath.Join(root, "real")
	kept := writeFile(t, filepath.Join(realDir, "keep.txt"), "keep me\n")
	link := filepath.Join(root, "alias")
	requireSymlink(t, realDir, link)
	svc := newConfined(t, root)

	resp, err := svc.RemovePath(context.Background(),
		&sandboxdv1.RemovePathRequest{Path: link, Recursive: true})
	require.NoError(t, err)

	assert.Equal(t, uint64(1), resp.GetEntriesRemoved())
	assert.NoDirExists(t, link)
	assert.Equal(t, "keep me\n", readBack(t, kept), "the directory it named is intact")
}

// The same for a symlink to a directory: the link goes, the tree behind it does
// not — even with recursive set, which is when it would be most destructive.
func TestRemovePath_RecursiveDoesNotFollowASymlinkedDirectory(t *testing.T) {
	root := tempRoot(t)
	outside := tempRoot(t)
	kept := writeFile(t, filepath.Join(outside, "keep.txt"), "still here\n")
	link := filepath.Join(root, "escapedir")
	requireSymlink(t, outside, link)
	svc := newConfined(t, root)

	resp, err := svc.RemovePath(context.Background(),
		&sandboxdv1.RemovePathRequest{Path: link, Recursive: true})
	require.NoError(t, err)

	assert.Equal(t, uint64(1), resp.GetEntriesRemoved())
	assert.NoDirExists(t, link)
	assert.Equal(t, "still here\n", readBack(t, kept))
	assert.DirExists(t, outside)
}

// A symlink *inside* a tree being removed recursively is unlinked with the
// tree, and what it points at survives.
func TestRemovePath_RecursiveUnlinksNestedSymlinksWithoutFollowingThem(t *testing.T) {
	root := tempRoot(t)
	outside := tempRoot(t)
	kept := writeFile(t, filepath.Join(outside, "keep.txt"), "still here\n")

	dir := filepath.Join(root, "tree")
	writeFile(t, filepath.Join(dir, "a.txt"), "a")
	requireSymlink(t, outside, filepath.Join(dir, "outlink"))
	requireSymlink(t, kept, filepath.Join(dir, "outfile"))
	svc := newConfined(t, root)

	_, err := svc.RemovePath(context.Background(),
		&sandboxdv1.RemovePathRequest{Path: dir, Recursive: true})
	require.NoError(t, err)

	assert.NoDirExists(t, dir)
	assert.Equal(t, "still here\n", readBack(t, kept))
	assert.DirExists(t, outside)
}

// Removing the root would destroy the confinement while staying inside it.
func TestRemovePath_RefusesTheJailRoot(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "keep.txt"), "x")
	svc := newConfined(t, root)

	for _, spelling := range []string{root, root + string(filepath.Separator) + "."} {
		_, err := svc.RemovePath(context.Background(),
			&sandboxdv1.RemovePathRequest{Path: spelling, Recursive: true})
		require.Error(t, err, "spelling %q", spelling)
		assert.Equal(t, codes.PermissionDenied, status.Code(err), "spelling %q", spelling)
		assert.Contains(t, status.Convert(err).Message(), "allowed root")
	}
	assert.DirExists(t, root)
	assert.FileExists(t, filepath.Join(root, "keep.txt"))

	// A directory *inside* the root removes normally, so the refusal is about
	// the root and not about directories.
	inner := filepath.Join(root, "inner")
	require.NoError(t, os.Mkdir(inner, 0o755))
	_, err := svc.RemovePath(context.Background(), &sandboxdv1.RemovePathRequest{Path: inner})
	require.NoError(t, err)
}

// The unconfined twin: no roots, so no root to refuse, and no invented one.
func TestRemovePath_UnconfinedHasNoRootToRefuse(t *testing.T) {
	root := tempRoot(t)
	target := filepath.Join(root, "sub")
	writeFile(t, filepath.Join(target, "f.txt"), "x")
	svc := newUnconfined(t, root)

	_, err := svc.RemovePath(context.Background(),
		&sandboxdv1.RemovePathRequest{Path: target, Recursive: true})
	require.NoError(t, err)
	assert.NoDirExists(t, target)
}

func TestRemovePath_RefusesAFilesystemRoot(t *testing.T) {
	root := tempRoot(t)
	svc := newUnconfined(t, root)

	fsRoot := "/"
	if runtime.GOOS == "windows" {
		fsRoot = filepath.VolumeName(root) + `\`
	}
	_, err := svc.RemovePath(context.Background(), &sandboxdv1.RemovePathRequest{Path: fsRoot})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "filesystem root")
}

// --- MovePath --------------------------------------------------------------

func TestMovePath_RenamesAFile(t *testing.T) {
	root := tempRoot(t)
	src := writeFile(t, filepath.Join(root, "from.txt"), "contents\n")
	dst := filepath.Join(root, "to.txt")
	svc := newConfined(t, root)

	resp, err := svc.MovePath(context.Background(),
		&sandboxdv1.MovePathRequest{Source: src, Destination: dst})
	require.NoError(t, err)

	assert.Equal(t, src, resp.GetSource())
	assert.Equal(t, dst, resp.GetDestination())
	assert.NoFileExists(t, src)
	assert.Equal(t, "contents\n", readBack(t, dst))
}

func TestMovePath_RenamesADirectory(t *testing.T) {
	root := tempRoot(t)
	src := filepath.Join(root, "from")
	writeFile(t, filepath.Join(src, "inner", "f.txt"), "deep\n")
	dst := filepath.Join(root, "to")
	svc := newConfined(t, root)

	_, err := svc.MovePath(context.Background(),
		&sandboxdv1.MovePathRequest{Source: src, Destination: dst})
	require.NoError(t, err)

	assert.NoDirExists(t, src)
	assert.Equal(t, "deep\n", readBack(t, filepath.Join(dst, "inner", "f.txt")))
}

func TestMovePath_Overwrite(t *testing.T) {
	root := tempRoot(t)
	src := writeFile(t, filepath.Join(root, "from.txt"), "new\n")
	dst := writeFile(t, filepath.Join(root, "to.txt"), "old\n")
	svc := newConfined(t, root)

	_, err := svc.MovePath(context.Background(),
		&sandboxdv1.MovePathRequest{Source: src, Destination: dst})
	require.Error(t, err)
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
	assert.Equal(t, "old\n", readBack(t, dst), "and nothing was replaced")
	assert.FileExists(t, src)

	_, err = svc.MovePath(context.Background(),
		&sandboxdv1.MovePathRequest{Source: src, Destination: dst, Overwrite: true})
	require.NoError(t, err)
	assert.Equal(t, "new\n", readBack(t, dst))
	assert.NoFileExists(t, src)
}

// destination names the full path to move to, not a directory to move into.
// Guessing that would be the silent wrong thing, so it is refused with the fix
// in the message.
func TestMovePath_RefusesAnExistingDirectoryDestination(t *testing.T) {
	root := tempRoot(t)
	src := writeFile(t, filepath.Join(root, "from.txt"), "x\n")
	dst := filepath.Join(root, "adir")
	require.NoError(t, os.Mkdir(dst, 0o755))
	svc := newConfined(t, root)

	for _, overwrite := range []bool{false, true} {
		_, err := svc.MovePath(context.Background(),
			&sandboxdv1.MovePathRequest{Source: src, Destination: dst, Overwrite: overwrite})
		require.Error(t, err, "overwrite=%v", overwrite)
		assert.Contains(t, status.Convert(err).Message(), "full path to move to")
	}
	assert.FileExists(t, src)
	assert.DirExists(t, dst)
}

func TestMovePath_MissingSourceAndNoOpMove(t *testing.T) {
	root := tempRoot(t)
	svc := newConfined(t, root)

	_, err := svc.MovePath(context.Background(), &sandboxdv1.MovePathRequest{
		Source: filepath.Join(root, "nope"), Destination: filepath.Join(root, "somewhere")})
	assert.Equal(t, codes.NotFound, status.Code(err))

	same := writeFile(t, filepath.Join(root, "same.txt"), "x\n")
	_, err = svc.MovePath(context.Background(),
		&sandboxdv1.MovePathRequest{Source: same, Destination: same})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Equal(t, "x\n", readBack(t, same))
}

// Moving a symlink moves the link, not what it points at.
func TestMovePath_MovesASymlinkWithoutFollowingIt(t *testing.T) {
	root := tempRoot(t)
	outside := tempRoot(t)
	secret := writeFile(t, filepath.Join(outside, "secret.txt"), "classified\n")
	src := filepath.Join(root, "escape.txt")
	requireSymlink(t, secret, src)
	dst := filepath.Join(root, "moved.txt")
	svc := newConfined(t, root)

	_, err := svc.MovePath(context.Background(),
		&sandboxdv1.MovePathRequest{Source: src, Destination: dst})
	require.NoError(t, err)

	assert.NoFileExists(t, src)
	target, err := os.Readlink(dst)
	require.NoError(t, err, "the destination is still a link")
	assert.Equal(t, secret, target)
	assert.Equal(t, "classified\n", readBack(t, secret), "and its target never moved")
}

// And the inside-the-jail case for a move, where no containment check would
// object to dragging the target somewhere else instead of the link.
func TestMovePath_MovesASymlinkToAnInsideFileWithoutFollowingIt(t *testing.T) {
	root := tempRoot(t)
	target := writeFile(t, filepath.Join(root, "real.txt"), "stay put\n")
	src := filepath.Join(root, "alias.txt")
	requireSymlink(t, target, src)
	dst := filepath.Join(root, "moved-alias.txt")
	svc := newConfined(t, root)

	_, err := svc.MovePath(context.Background(),
		&sandboxdv1.MovePathRequest{Source: src, Destination: dst})
	require.NoError(t, err)

	assert.NoFileExists(t, src)
	got, err := os.Readlink(dst)
	require.NoError(t, err, "the destination is a link, not a copy of the target")
	assert.Equal(t, target, got)
	assert.Equal(t, "stay put\n", readBack(t, target), "and the target never moved")
}

func TestMovePath_RefusesTheJailRootAsSource(t *testing.T) {
	root := tempRoot(t)
	svc := newConfined(t, root)

	_, err := svc.MovePath(context.Background(),
		&sandboxdv1.MovePathRequest{Source: root, Destination: filepath.Join(root, "elsewhere")})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.DirExists(t, root)
}

// Both endpoints go through the jail, not just the destination.
func TestMovePath_JailsBothEndpoints(t *testing.T) {
	root := tempRoot(t)
	outside := tempRoot(t)
	inside := writeFile(t, filepath.Join(root, "inside.txt"), "in\n")
	outsideFile := writeFile(t, filepath.Join(outside, "outside.txt"), "out\n")
	svc := newConfined(t, root)

	// Source outside.
	_, err := svc.MovePath(context.Background(), &sandboxdv1.MovePathRequest{
		Source: outsideFile, Destination: filepath.Join(root, "stolen.txt")})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	// Destination outside.
	_, err = svc.MovePath(context.Background(), &sandboxdv1.MovePathRequest{
		Source: inside, Destination: filepath.Join(outside, "leaked.txt")})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	// Destination reached through a symlink that leaves the jail.
	requireSymlink(t, outside, filepath.Join(root, "escapedir"))
	_, err = svc.MovePath(context.Background(), &sandboxdv1.MovePathRequest{
		Source: inside, Destination: filepath.Join(root, "escapedir", "leaked.txt")})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	assert.Equal(t, "in\n", readBack(t, inside), "nothing moved")
	assert.Equal(t, "out\n", readBack(t, outsideFile))
	assert.NoFileExists(t, filepath.Join(outside, "leaked.txt"))
}

// --- MovePath across filesystems -------------------------------------------

// The platform's own cross-device error is what the detection looks for, so the
// injection below exercises the real branch rather than a sentinel that only
// this test recognises.
func TestMovePath_CrossDeviceDetectionMatchesThePlatformError(t *testing.T) {
	assert.True(t, agentfs.IsCrossDeviceForTest(agentfs.CrossDeviceErrorForTest()))
	assert.False(t, agentfs.IsCrossDeviceForTest(os.ErrPermission))
}

// A file that cannot be renamed is copied and then unlinked — in that order, so
// a failure never leaves the source gone and the destination half-written.
func TestMovePath_CrossDeviceCopiesAFileThenRemovesTheSource(t *testing.T) {
	root := tempRoot(t)
	content := strings.Repeat("across the boundary\n", 5000)
	src := writeFile(t, filepath.Join(root, "from.bin"), content)
	if runtime.GOOS != "windows" {
		require.NoError(t, os.Chmod(src, 0o640))
	}
	dst := filepath.Join(root, "sub", "to.bin")
	require.NoError(t, os.Mkdir(filepath.Join(root, "sub"), 0o755))
	svc := newConfined(t, root)

	defer agentfs.SetRenameForTest(func(string, string) error {
		return agentfs.CrossDeviceErrorForTest()
	})()

	_, err := svc.MovePath(context.Background(),
		&sandboxdv1.MovePathRequest{Source: src, Destination: dst})
	require.NoError(t, err)

	assert.NoFileExists(t, src, "the source is unlinked only after the copy committed")
	assert.Equal(t, content, readBack(t, dst))
	assert.Empty(t, tempSiblings(t, filepath.Join(root, "sub")),
		"the copy commits through the atomic writer and leaves nothing behind")
	if runtime.GOOS != "windows" {
		info, err := os.Stat(dst)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o640), info.Mode().Perm(), "the mode travels with the file")
	}
}

// The failure the ordering exists to prevent: the copy dies partway and the
// source must still be there.
//
// The copy is failed mid-flight rather than before it starts — the rename hook
// cancels the request, so the transfer aborts inside io.Copy, after the
// destination's temp file has been created. A test that failed earlier than
// that would assert the source survives a move that never began, which proves
// nothing about the ordering.
func TestMovePath_CrossDeviceFailureLeavesTheSourceIntact(t *testing.T) {
	root := tempRoot(t)
	content := strings.Repeat("irreplaceable\n", 20_000)
	src := writeFile(t, filepath.Join(root, "from.txt"), content)
	dst := filepath.Join(root, "to.txt")
	svc := newConfined(t, root)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer agentfs.SetRenameForTest(func(string, string) error {
		cancel()
		return agentfs.CrossDeviceErrorForTest()
	})()

	_, err := svc.MovePath(ctx, &sandboxdv1.MovePathRequest{Source: src, Destination: dst})

	require.Error(t, err)
	assert.Equal(t, content, readBack(t, src),
		"the source survives a cross-device move that failed while copying")
	assert.NoFileExists(t, dst, "and no partial destination is left behind")
	assert.Empty(t, tempSiblings(t, root), "nor the temp file the copy was using")
}

// The same guarantee against a real filesystem refusal rather than a cancelled
// request: a destination directory the agent cannot write to.
func TestMovePath_CrossDeviceUnwritableDestinationLeavesTheSourceIntact(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permission bits do not deny writes on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores the permission bits this test depends on")
	}
	root := tempRoot(t)
	src := writeFile(t, filepath.Join(root, "from.txt"), "irreplaceable\n")
	locked := filepath.Join(root, "locked")
	require.NoError(t, os.Mkdir(locked, 0o500))
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	dst := filepath.Join(locked, "to.txt")
	svc := newConfined(t, root)

	defer agentfs.SetRenameForTest(func(string, string) error {
		return agentfs.CrossDeviceErrorForTest()
	})()

	_, err := svc.MovePath(context.Background(),
		&sandboxdv1.MovePathRequest{Source: src, Destination: dst})

	require.Error(t, err)
	assert.Equal(t, "irreplaceable\n", readBack(t, src))
	assert.NoFileExists(t, dst)
	assert.Empty(t, tempSiblings(t, locked))
}

// A destination whose parent is a file is an ordinary error, before any copy.
func TestMovePath_RefusesADestinationUnderAFile(t *testing.T) {
	root := tempRoot(t)
	src := writeFile(t, filepath.Join(root, "from.txt"), "x\n")
	blocker := writeFile(t, filepath.Join(root, "blocker"), "not a directory\n")
	svc := newConfined(t, root)

	_, err := svc.MovePath(context.Background(), &sandboxdv1.MovePathRequest{
		Source: src, Destination: filepath.Join(blocker, "to.txt")})

	require.Error(t, err)
	assert.Equal(t, "x\n", readBack(t, src))
	assert.Equal(t, "not a directory\n", readBack(t, blocker))
}

func TestMovePath_CrossDeviceMovesASymlink(t *testing.T) {
	root := tempRoot(t)
	target := writeFile(t, filepath.Join(root, "target.txt"), "pointed at\n")
	src := filepath.Join(root, "link")
	requireSymlink(t, target, src)
	dst := filepath.Join(root, "moved-link")
	svc := newConfined(t, root)

	defer agentfs.SetRenameForTest(func(string, string) error {
		return agentfs.CrossDeviceErrorForTest()
	})()

	_, err := svc.MovePath(context.Background(),
		&sandboxdv1.MovePathRequest{Source: src, Destination: dst})
	require.NoError(t, err)

	assert.NoFileExists(t, src)
	got, err := os.Readlink(dst)
	require.NoError(t, err)
	assert.Equal(t, target, got)
	assert.Equal(t, "pointed at\n", readBack(t, target))
}

// A directory across a filesystem boundary is refused rather than half-copied,
// and the error says the source is untouched.
func TestMovePath_CrossDeviceRefusesADirectory(t *testing.T) {
	root := tempRoot(t)
	src := filepath.Join(root, "tree")
	writeFile(t, filepath.Join(src, "f.txt"), "kept\n")
	dst := filepath.Join(root, "moved")
	svc := newConfined(t, root)

	defer agentfs.SetRenameForTest(func(string, string) error {
		return agentfs.CrossDeviceErrorForTest()
	})()

	_, err := svc.MovePath(context.Background(),
		&sandboxdv1.MovePathRequest{Source: src, Destination: dst})

	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	msg := status.Convert(err).Message()
	assert.Contains(t, msg, "different filesystems")
	assert.Contains(t, msg, "source is untouched")
	assert.Equal(t, "kept\n", readBack(t, filepath.Join(src, "f.txt")))
	assert.NoDirExists(t, dst)
}

// --- Concurrency and wiring ------------------------------------------------

// Two moves crossing take their locks in the same order, so they queue instead
// of deadlocking on each other.
func TestMovePath_CrossingMovesDoNotDeadlock(t *testing.T) {
	root := tempRoot(t)
	a := writeFile(t, filepath.Join(root, "a.txt"), "a\n")
	b := writeFile(t, filepath.Join(root, "b.txt"), "b\n")
	svc := newConfined(t, root)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 25; i++ {
			_, _ = svc.MovePath(context.Background(),
				&sandboxdv1.MovePathRequest{Source: a, Destination: b, Overwrite: true})
			_, _ = svc.MovePath(context.Background(),
				&sandboxdv1.MovePathRequest{Source: b, Destination: a, Overwrite: true})
		}
	}()
	for i := 0; i < 25; i++ {
		_, _ = svc.MovePath(context.Background(),
			&sandboxdv1.MovePathRequest{Source: b, Destination: a, Overwrite: true})
		_, _ = svc.MovePath(context.Background(),
			&sandboxdv1.MovePathRequest{Source: a, Destination: b, Overwrite: true})
	}
	<-done
}

// The three RPCs answer over a real connection, which is what changed: they
// used to be the embedded Unimplemented stubs.
func TestOverGRPC_MakeRemoveAndMove(t *testing.T) {
	root := tempRoot(t)
	client := serveOverGRPC(t, newConfined(t, root))
	ctx := context.Background()

	made, err := client.MakeDirectory(ctx, &sandboxdv1.MakeDirectoryRequest{
		Path: filepath.Join(root, "a", "b"), CreateParents: true})
	require.NoError(t, err)
	assert.True(t, made.GetCreated())

	src := writeFile(t, filepath.Join(root, "a", "b", "f.txt"), "x\n")
	moved, err := client.MovePath(ctx, &sandboxdv1.MovePathRequest{
		Source: src, Destination: filepath.Join(root, "a", "moved.txt")})
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(root, "a", "moved.txt"), moved.GetDestination())

	removed, err := client.RemovePath(ctx, &sandboxdv1.RemovePathRequest{
		Path: filepath.Join(root, "a"), Recursive: true})
	require.NoError(t, err)
	assert.Equal(t, uint64(3), removed.GetEntriesRemoved(), "a, a/b and a/moved.txt")
	assert.NoDirExists(t, filepath.Join(root, "a"))
}

// Every path in these three goes through the jail, in the confined
// configuration and only there. This mirrors the table the other RPCs are held
// to.
func TestJail_ManagementRPCsRefusePathsOutsideTheRoots(t *testing.T) {
	root := tempRoot(t)
	outside := tempRoot(t)
	target := writeFile(t, filepath.Join(outside, "secret.txt"), "classified\n")
	svc := newConfined(t, root)
	ctx := context.Background()

	cases := []struct {
		name string
		run  func() error
	}{
		{"MakeDirectory", func() error {
			_, err := svc.MakeDirectory(ctx, &sandboxdv1.MakeDirectoryRequest{
				Path: filepath.Join(outside, "made")})
			return err
		}},
		{"RemovePath", func() error {
			_, err := svc.RemovePath(ctx, &sandboxdv1.RemovePathRequest{Path: target})
			return err
		}},
		{"MovePath", func() error {
			_, err := svc.MovePath(ctx, &sandboxdv1.MovePathRequest{
				Source: target, Destination: filepath.Join(root, "here.txt")})
			return err
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.run()
			require.Error(t, err)
			assert.Equal(t, codes.PermissionDenied, status.Code(err))
			assert.Contains(t, status.Convert(err).Message(), "outside the allowed roots")
		})
	}
	assert.Equal(t, "classified\n", readBack(t, target))
	assert.NoDirExists(t, filepath.Join(outside, "made"))
}

// The unconfined twin: no roots, so no rejection to make and none invented.
func TestJail_ManagementRPCsUnconfinedRefuseNothing(t *testing.T) {
	root := tempRoot(t)
	outside := tempRoot(t)
	svc := newUnconfined(t, root)
	ctx := context.Background()

	made := filepath.Join(outside, "made")
	_, err := svc.MakeDirectory(ctx, &sandboxdv1.MakeDirectoryRequest{Path: made})
	require.NoError(t, err)
	assert.DirExists(t, made)

	src := writeFile(t, filepath.Join(outside, "from.txt"), "x\n")
	dst := filepath.Join(root, "to.txt")
	_, err = svc.MovePath(ctx, &sandboxdv1.MovePathRequest{Source: src, Destination: dst})
	require.NoError(t, err, "an unconfined agent has no roots to refuse a path against")
	assert.Equal(t, "x\n", readBack(t, dst))

	_, err = svc.RemovePath(ctx, &sandboxdv1.RemovePathRequest{Path: made})
	require.NoError(t, err)
}

// A directory holding many entries is counted correctly, so entries_removed is
// not a small-tree accident.
func TestRemovePath_RecursiveOnALargerTree(t *testing.T) {
	root := tempRoot(t)
	dir := filepath.Join(root, "big")
	const dirs, filesPer = 8, 12
	for d := 0; d < dirs; d++ {
		for f := 0; f < filesPer; f++ {
			writeFile(t, filepath.Join(dir, fmt.Sprintf("d%02d", d), fmt.Sprintf("f%02d.txt", f)), "x")
		}
	}
	svc := newConfined(t, root)

	resp, err := svc.RemovePath(context.Background(),
		&sandboxdv1.RemovePathRequest{Path: dir, Recursive: true})
	require.NoError(t, err)

	assert.Equal(t, uint64(1+dirs+dirs*filesPer), resp.GetEntriesRemoved())
	assert.NoDirExists(t, dir)
}
