package fs_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	agentfs "github.com/axelmierczuk/sandboxd-mcp/internal/agent/fs"
	"github.com/axelmierczuk/sandboxd-mcp/internal/security/jail"
)

// The second audit round. Each test here corresponds to a defect the round
// found; each was confirmed to fail with its fix reverted rather than assumed
// to.

// --- EditFile: the result was not bounded, only the input -------------------

// MaxEditBytes capped the file an edit could read and said nothing about what it
// could produce. replace_all multiplies by len(new_string)/len(old_string), and
// old_string may be a single byte: a 1 MiB file wrote 64 MiB, and at the 16 MiB
// ceiling with a kilobyte replacement it is 16 GiB — held in memory, written to
// disk, and returned inside a diff.
func TestEditFile_RefusesAReplacementThatWouldOutgrowTheLimit(t *testing.T) {
	root := tempRoot(t)
	const limit = 1 << 20
	original := strings.Repeat("a", limit/4)
	path := writeFile(t, filepath.Join(root, "a.txt"), original)
	svc := agentfsService(t, root, limit)

	_, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path: path, OldString: "a", NewString: strings.Repeat("b", 64), ReplaceAll: true})

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "over the")
	assert.Equal(t, original, readBack(t, path), "and the file is exactly as it was")

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, int64(len(original)), info.Size(),
		"nothing was written; the refusal happens before the result is built")
}

// The bound is on the result, so a replacement that shrinks the file is fine
// even when the file is already near the ceiling.
func TestEditFile_AllowsAReplacementThatShrinksTheFile(t *testing.T) {
	root := tempRoot(t)
	const limit = 1 << 20
	path := writeFile(t, filepath.Join(root, "a.txt"), strings.Repeat("aa", limit/4))
	svc := agentfsService(t, root, limit)

	resp, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path: path, OldString: "aa", NewString: "a", ReplaceAll: true})

	require.NoError(t, err)
	assert.Equal(t, uint32(limit/4), resp.GetReplacements())
	assert.Equal(t, strings.Repeat("a", limit/4), readBack(t, path))
}

// Without replace_all exactly one occurrence is replaced, so the bound has to be
// computed for one rather than for every match in the file.
func TestEditFile_SizeBoundCountsOnlyTheReplacementsItWillMake(t *testing.T) {
	root := tempRoot(t)
	const limit = 1 << 20
	path := writeFile(t, filepath.Join(root, "a.txt"), strings.Repeat("a\n", limit/8)+"unique")
	svc := agentfsService(t, root, limit)

	resp, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path: path, OldString: "unique", NewString: strings.Repeat("z", 4096)})

	require.NoError(t, err, "one replacement of 6 bytes by 4 KiB fits, even though a-times-all would not")
	assert.Equal(t, uint32(1), resp.GetReplacements())
}

// --- EditFile: the diff embedded whole lines --------------------------------

// The diff is capped at a number of lines and was not capped at their length. A
// hunk is expanded to whole lines on both sides, so one small replacement in a
// file whose line is megabytes long — minified JavaScript, a packed JSON
// document, a base64 blob — put that line in the diff twice. At the edit ceiling
// that exceeds the 32 MiB gRPC message limit, and the write has already been
// committed by the time the response fails to send.
func TestEditFile_DiffDoesNotEmbedAWholeLongLine(t *testing.T) {
	root := tempRoot(t)
	const half = 1 << 20
	line := strings.Repeat("x", half)
	path := writeFile(t, filepath.Join(root, "min.js"), line+"NEEDLE"+line)
	svc := newConfined(t, root)

	resp, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path: path, OldString: "NEEDLE", NewString: "FOUND"})
	require.NoError(t, err)

	assert.Less(t, len(resp.GetDiff()), 8*1024,
		"a 6-byte replacement returns a diff a model can read, not two megabytes of one line")
	assert.Contains(t, resp.GetDiff(), "bytes elided",
		"and the trimming is marked rather than silent")
	assert.Contains(t, resp.GetDiff(), "FOUND", "the change itself is still visible")
	assert.True(t, utf8.ValidString(resp.GetDiff()),
		"the diff travels in a proto3 string, which refuses to marshal invalid UTF-8")
	assert.Equal(t, line+"FOUND"+line, readBack(t, path), "and the edit itself is byte-exact")
}

// The elision cuts at byte offsets, which can land inside a rune.
func TestEditFile_DiffElisionStaysValidUTF8(t *testing.T) {
	root := tempRoot(t)
	// "…" is three bytes, so every cut offset in this line lands mid-rune for two
	// offsets out of three.
	line := strings.Repeat("…", 4000)
	path := writeFile(t, filepath.Join(root, "runes.txt"), line+"MARK"+line)
	svc := newConfined(t, root)

	resp, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path: path, OldString: "MARK", NewString: "DONE"})
	require.NoError(t, err)
	assert.True(t, utf8.ValidString(resp.GetDiff()))
}

// The full path, so the assertion covers proto marshalling rather than only the
// string this process built.
func TestOverGRPC_EditOfALongLineFitsInAMessage(t *testing.T) {
	root := tempRoot(t)
	line := strings.Repeat("x", 4<<20)
	path := writeFile(t, filepath.Join(root, "bundle.min.js"), line+"NEEDLE"+line)
	client := serveOverGRPC(t, newConfined(t, root))

	resp, err := client.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path: path, OldString: "NEEDLE", NewString: "FOUND"})

	require.NoError(t, err, "an 8 MiB single-line file produced a 16 MiB diff, over the message cap")
	assert.Less(t, len(resp.GetDiff()), 8*1024)
}

// --- EditFile: a replace_all across a whole file ----------------------------

// The line cap and the new byte cap have to compose: a replace_all with tens of
// thousands of hunks is trimmed, still reports every replacement, and still
// renders as a diff.
func TestEditFile_ManyReplacementsAreCountedInFullAndDiffedInPart(t *testing.T) {
	root := tempRoot(t)
	const lines = 20_000
	path := writeFile(t, filepath.Join(root, "many.txt"), strings.Repeat("a\n", lines))
	svc := newConfined(t, root)

	resp, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
		Path: path, OldString: "a", NewString: "b", ReplaceAll: true})
	require.NoError(t, err)

	assert.Equal(t, uint32(lines), resp.GetReplacements(),
		"every replacement is counted, however few the diff shows")
	assert.Equal(t, strings.Repeat("b\n", lines), readBack(t, path))
	assert.Less(t, len(resp.GetDiff()), 64*1024, "the diff is trimmed rather than proportional")
	assert.Contains(t, resp.GetDiff(), "diff trimmed")
	assert.True(t, utf8.ValidString(resp.GetDiff()))
}

// --- MovePath: a failed rename was attributed to the source -----------------

// rename takes two paths and fails for reasons belonging to either. Reporting
// every failure against the source produced "<source> does not exist" about a
// file sitting right there, whenever it was the destination's parent that was
// missing — and a model told its source is gone acts on that.
func TestMovePath_MissingDestinationParentBlamesTheDestination(t *testing.T) {
	root := tempRoot(t)
	src := writeFile(t, filepath.Join(root, "from.txt"), "still here\n")
	svc := newConfined(t, root)

	_, err := svc.MovePath(context.Background(), &sandboxdv1.MovePathRequest{
		Source: src, Destination: filepath.Join(root, "missing", "to.txt")})

	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
	msg := status.Convert(err).Message()
	assert.Contains(t, msg, "destination's parent directory does not exist")
	assert.NotContains(t, msg, src+" does not exist",
		"the source exists; saying otherwise sends the caller after the wrong file")
	assert.Equal(t, "still here\n", readBack(t, src))
}

// --- MovePath: the jail-root check on the resolved source was untested -------

// resolveSelf refuses a root by the name the caller wrote, and MovePath refuses
// it again on the resolved target. Round one added the second check and a test
// for RemovePath's half of it; MovePath's half had none, so deleting it broke
// nothing — and what it stops is a jail root being renamed out from under the
// confinement it defines.
//
// Reaching a root through a symlinked parent needs that parent to be inside a
// root itself, which means nested roots: the path the caller wrote is not
// textually a root, the jail resolves it happily, and what it resolves to is one.
func TestMovePath_RefusesAnAllowedRootReachedThroughASymlinkedParent(t *testing.T) {
	outer := tempRoot(t)
	inner := filepath.Join(outer, "inner")
	require.NoError(t, os.Mkdir(inner, 0o755))
	writeFile(t, filepath.Join(inner, "keep.txt"), "x")
	requireSymlink(t, outer, filepath.Join(outer, "alias"))

	confinement, err := jail.New(jail.Config{Roots: []string{outer, inner}})
	require.NoError(t, err)
	svc := agentfs.NewService(confinement, testLogger(), agentfs.Limits{})

	_, err = svc.MovePath(context.Background(), &sandboxdv1.MovePathRequest{
		Source:      filepath.Join(outer, "alias", "inner"),
		Destination: filepath.Join(outer, "elsewhere")})

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "is an allowed root")
	assert.DirExists(t, inner, "the root is still where the confinement says it is")
	assert.FileExists(t, filepath.Join(inner, "keep.txt"))
	assert.NoDirExists(t, filepath.Join(outer, "elsewhere"))

	// A path inside that root still moves, so the refusal is about the root and
	// not about everything reached through the alias.
	_, err = svc.MovePath(context.Background(), &sandboxdv1.MovePathRequest{
		Source:      filepath.Join(outer, "alias", "inner", "keep.txt"),
		Destination: filepath.Join(inner, "moved.txt")})
	require.NoError(t, err)
	assert.Equal(t, "x", readBack(t, filepath.Join(inner, "moved.txt")))
}

// --- MovePath: the cross-device symlink branch cleared the destination first --

// The file branch commits through the atomic writer, so a failure leaves the
// destination exactly as it was. The symlink branch removed the destination and
// then created a link in its place, so a failure between the two left the caller
// with neither the old destination nor a new one — from a move whose whole
// contract is that a failure costs nothing. It also ignored cancellation, which
// is how this test reaches the window.
func TestMovePath_CrossDeviceSymlinkFailureKeepsTheDestination(t *testing.T) {
	root := tempRoot(t)
	target := writeFile(t, filepath.Join(root, "target.txt"), "pointed at\n")
	src := filepath.Join(root, "link")
	requireSymlink(t, target, src)
	dst := writeFile(t, filepath.Join(root, "occupied"), "the destination the caller still has\n")
	svc := newConfined(t, root)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer agentfs.SetRenameForTest(func(string, string) error {
		cancel()
		return agentfs.CrossDeviceErrorForTest()
	})()

	_, err := svc.MovePath(ctx, &sandboxdv1.MovePathRequest{
		Source: src, Destination: dst, Overwrite: true})

	require.Error(t, err)
	assert.Equal(t, "the destination the caller still has\n", readBack(t, dst),
		"a move that failed leaves the destination it was going to replace")
	assert.Equal(t, "pointed at\n", readBack(t, target), "and the source link is untouched")
	_, lerr := os.Lstat(src)
	assert.NoError(t, lerr)
	assert.Empty(t, tempSiblings(t, root), "and nothing is left beside it")
}

// The success path still replaces the destination, and commits by rename rather
// than leaving a temp link behind.
func TestMovePath_CrossDeviceSymlinkOverwritesTheDestination(t *testing.T) {
	root := tempRoot(t)
	target := writeFile(t, filepath.Join(root, "target.txt"), "pointed at\n")
	src := filepath.Join(root, "link")
	requireSymlink(t, target, src)
	dst := writeFile(t, filepath.Join(root, "occupied"), "replaced\n")
	svc := newConfined(t, root)

	defer agentfs.SetRenameForTest(func(string, string) error {
		return agentfs.CrossDeviceErrorForTest()
	})()

	_, err := svc.MovePath(context.Background(), &sandboxdv1.MovePathRequest{
		Source: src, Destination: dst, Overwrite: true})
	require.NoError(t, err)

	got, err := os.Readlink(dst)
	require.NoError(t, err)
	assert.Equal(t, target, got)
	assert.NoFileExists(t, src)
	assert.Empty(t, tempSiblings(t, root))
}

// --- Writes: a symlinked parent was a second name for one file --------------

// Round one made a write resolve its last component, so a link and the file it
// names take one path lock. The same divergence is one level up: unconfined,
// "dir/f" and "link/f" are two strings for one file, so two concurrent edits
// take two locks and the second discards the first. Confined this never showed,
// because the jail returns a path with every symlink already followed.
func TestEditFile_SymlinkedParentAndRealParentShareOneLock(t *testing.T) {
	root := tempRoot(t)
	realDir := filepath.Join(root, "realdir")
	require.NoError(t, os.Mkdir(realDir, 0o755))
	target := writeFile(t, filepath.Join(realDir, "conf.txt"), "alpha = 0\nbeta = 0\n")
	requireSymlink(t, realDir, filepath.Join(root, "linkdir"))
	svc := newUnconfined(t, root)

	done := make(chan error, 2)
	go func() {
		_, err := svc.EditFile(context.Background(), &sandboxdv1.EditFileRequest{
			Path: filepath.Join(root, "linkdir", "conf.txt"), OldString: "alpha = 0", NewString: "alpha = 1"})
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
		"both edits survive: naming a parent directory through a link is not a way to dodge the file's lock")
}

// And the path a write reports is the file it landed on, whichever spelling
// named it.
func TestWriteFile_ReportsTheResolvedPathThroughASymlinkedParent(t *testing.T) {
	root := tempRoot(t)
	realDir := filepath.Join(root, "realdir")
	require.NoError(t, os.Mkdir(realDir, 0o755))
	target := writeFile(t, filepath.Join(realDir, "f.txt"), "old\n")
	requireSymlink(t, realDir, filepath.Join(root, "linkdir"))
	svc := newUnconfined(t, root)

	stream := writeStreamFor(context.Background(),
		&sandboxdv1.WriteFileHeader{Path: filepath.Join(root, "linkdir", "f.txt")}, []byte("new\n"), 4)
	require.NoError(t, svc.WriteFile(stream))

	assert.Equal(t, target, stream.resp.GetPath())
	assert.Equal(t, "new\n", readBack(t, target))
}

// A path whose parent does not exist yet is still creatable: resolving the
// parent must not turn create_parents into a NotFound.
func TestWriteFile_CreateParentsStillWorksUnderTheParentResolution(t *testing.T) {
	root := tempRoot(t)
	svc := newUnconfined(t, root)
	path := filepath.Join(root, "a", "b", "c.txt")

	require.NoError(t, svc.WriteFile(writeStreamFor(context.Background(),
		&sandboxdv1.WriteFileHeader{Path: path, CreateParents: true}, []byte("made\n"), 4)))
	assert.Equal(t, "made\n", readBack(t, path))
}

// --- Glob: the matcher was exponential in the number of "**" ----------------

// Each "**" branches over every remaining path segment, so a pattern the caller
// writes cost O(depth ^ number of "**") — millions of calls per file on a tree
// the caller can create, on a request with no deadline and nothing to interrupt
// it. Memoising leaves what it matches unchanged and makes it polynomial.
func TestGlob_APathologicalPatternDoesNotHangTheHandler(t *testing.T) {
	root := tempRoot(t)
	deep := root
	for i := 0; i < 32; i++ {
		deep = filepath.Join(deep, fmt.Sprintf("d%d", i))
	}
	require.NoError(t, os.MkdirAll(deep, 0o755))
	writeFile(t, filepath.Join(deep, "found.go"), "package deep\n")

	// A pattern that cannot match is the expensive one: a match short-circuits at
	// the first placement that works, while a near-miss explores every one of
	// them — here C(32,15), around 5.7e8 — before answering no.
	pattern := strings.Repeat("**/*/", 15) + "**/absent.go"
	svc := newConfined(t, root)

	done := make(chan *sandboxdv1.GlobResponse, 1)
	errs := make(chan error, 1)
	go func() {
		resp, err := svc.Glob(context.Background(), &sandboxdv1.GlobRequest{Pattern: pattern, Root: root})
		if err != nil {
			errs <- err
			return
		}
		done <- resp
	}()

	select {
	case resp := <-done:
		assert.Empty(t, resp.GetPaths())
	case err := <-errs:
		t.Fatalf("glob failed: %v", err)
	case <-time.After(20 * time.Second):
		// The goroutine is abandoned rather than waited for: unmemoised this runs
		// for long enough that waiting is the same as hanging.
		t.Fatal("a caller-supplied glob pattern pinned the handler; the matcher is not memoised")
	}

	// The same shape of pattern, matching, still finds what it always found.
	found, err := svc.Glob(context.Background(), &sandboxdv1.GlobRequest{
		Pattern: strings.Repeat("**/*/", 15) + "**/found.go", Root: root})
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join(deep, "found.go")}, found.GetPaths())
}

// --- Grep: a line that is not valid UTF-8 failed the whole stream -----------

// GrepMatch.line is a proto3 string, and marshalling one that is not valid UTF-8
// fails. The binary sniff only reads the first 8 KiB, so an ordinary log with a
// stray latin-1 byte a megabyte in passes it and then broke the search — over
// gRPC the stream dies with an encoding error after the match was already found.
func TestOverGRPC_GrepSurvivesAnInvalidUTF8Line(t *testing.T) {
	root := tempRoot(t)
	head := strings.Repeat("clean ascii line\n", 700) // past the 8 KiB sniff window
	writeFile(t, filepath.Join(root, "app.log"), head+"needle \xff latin1\n")
	client := serveOverGRPC(t, newConfined(t, root))

	stream, err := client.Grep(context.Background(), &sandboxdv1.GrepRequest{Pattern: "needle", Root: root})
	require.NoError(t, err)

	var matches []*sandboxdv1.GrepMatch
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err, "the stream must not die on a byte the caller cannot see")
		if m := resp.GetMatch(); m != nil {
			matches = append(matches, m)
		}
	}

	require.Len(t, matches, 1)
	assert.True(t, utf8.ValidString(matches[0].GetLine()))
	assert.Contains(t, matches[0].GetLine(), "needle")
	assert.Contains(t, matches[0].GetLine(), "�", "the byte is shown as unrepresentable, not dropped silently")
}

// Context lines go through the same field, and are collected from lines that
// were never matched against.
func TestOverGRPC_GrepContextLinesAreValidUTF8(t *testing.T) {
	root := tempRoot(t)
	head := strings.Repeat("clean ascii line\n", 700)
	writeFile(t, filepath.Join(root, "app.log"), head+"before \xfe bad\nneedle\nafter \xfd bad\n")
	client := serveOverGRPC(t, newConfined(t, root))

	stream, err := client.Grep(context.Background(),
		&sandboxdv1.GrepRequest{Pattern: "needle", Root: root, ContextLines: 1})
	require.NoError(t, err)

	var matches []*sandboxdv1.GrepMatch
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		if m := resp.GetMatch(); m != nil {
			matches = append(matches, m)
		}
	}

	require.Len(t, matches, 1)
	for _, line := range append(matches[0].GetBeforeContext(), matches[0].GetAfterContext()...) {
		assert.True(t, utf8.ValidString(line), "context line %q", line)
	}
}
