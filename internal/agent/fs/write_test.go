package fs_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
)

// The round trip: what goes in comes back out byte for byte.
func TestWriteFile_RoundTripsBytes(t *testing.T) {
	root := tempRoot(t)
	svc := newConfined(t, root)
	path := filepath.Join(root, "out.txt")
	content := []byte("bytes in, bytes out\n\x01 not quite\n")

	stream := writeStreamFor(context.Background(),
		&sandboxdv1.WriteFileHeader{Path: path}, content, 7)
	require.NoError(t, svc.WriteFile(stream))

	require.NotNil(t, stream.resp)
	assert.Equal(t, path, stream.resp.GetPath())
	assert.Equal(t, uint64(len(content)), stream.resp.GetBytesWritten())
	assert.True(t, stream.resp.GetCreated())

	back := readAll(t, svc, &sandboxdv1.ReadFileRequest{Path: path, Raw: true})
	assert.Equal(t, content, back.content)
	assert.Empty(t, tempSiblings(t, root))
}

// The temp file is a sibling of the target, not a file in the system temp
// directory. Across filesystems the rename would be a copy, and a copy
// interrupted halfway is the truncated file this design exists to prevent.
func TestWriteFile_TempFileIsASiblingOfTheTarget(t *testing.T) {
	root := tempRoot(t)
	dir := filepath.Join(root, "nested")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	svc := newConfined(t, root)
	path := filepath.Join(dir, "target.txt")

	var sawSibling []string
	stream := writeStreamFor(context.Background(),
		&sandboxdv1.WriteFileHeader{Path: path}, []byte("abcdefghij"), 2)
	stream.onRecv = func(i int) {
		if i == 2 {
			sawSibling = tempSiblings(t, dir)
		}
	}
	require.NoError(t, svc.WriteFile(stream))

	require.Len(t, sawSibling, 1, "the in-progress write lives beside its target, in %s", dir)
	assert.Empty(t, tempSiblings(t, dir), "and is gone once the rename has happened")
	assert.Equal(t, "abcdefghij", readBack(t, path))
}

// The guarantee that matters most: a transfer that dies partway leaves the
// original file exactly as it was.
func TestWriteFile_InterruptedTransferLeavesTheOriginalIntact(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "precious.txt"), "the original contents\n")
	svc := newConfined(t, root)

	stream := writeStreamFor(context.Background(),
		&sandboxdv1.WriteFileHeader{Path: path},
		[]byte(strings.Repeat("replacement data\n", 64)), 16)
	// Header plus two chunks, then the client dies.
	stream.failAfter = 3
	stream.failErr = errors.New("connection reset by peer")

	err := svc.WriteFile(stream)

	require.Error(t, err)
	assert.Equal(t, "the original contents\n", readBack(t, path),
		"an interrupted write must not have touched the target")
	assert.Empty(t, tempSiblings(t, root), "and must not leave its temp file behind")
	assert.Nil(t, stream.resp, "and must not report success")
}

// The same for a cancelled context, which is what a client hanging up actually
// produces over gRPC.
func TestWriteFile_CancelledStreamLeavesTheOriginalIntact(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "precious.txt"), "original\n")
	svc := newConfined(t, root)

	ctx, cancel := context.WithCancel(context.Background())
	stream := writeStreamFor(ctx, &sandboxdv1.WriteFileHeader{Path: path},
		[]byte(strings.Repeat("x", 4096)), 64)
	stream.failAfter = 4
	stream.failErr = context.Canceled
	stream.onRecv = func(i int) {
		if i == 3 {
			cancel()
		}
	}
	defer cancel()

	require.Error(t, svc.WriteFile(stream))
	assert.Equal(t, "original\n", readBack(t, path))
	assert.Empty(t, tempSiblings(t, root))
}

func TestWriteFile_FailIfExists(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "taken.txt"), "already here\n")
	svc := newConfined(t, root)

	stream := writeStreamFor(context.Background(),
		&sandboxdv1.WriteFileHeader{Path: path, FailIfExists: true}, []byte("new"), 8)
	err := svc.WriteFile(stream)

	assert.Equal(t, codes.AlreadyExists, status.Code(err))
	assert.Equal(t, "already here\n", readBack(t, path))
}

func TestWriteFile_CreateParents(t *testing.T) {
	root := tempRoot(t)
	svc := newConfined(t, root)
	path := filepath.Join(root, "a", "b", "c.txt")

	stream := writeStreamFor(context.Background(),
		&sandboxdv1.WriteFileHeader{Path: path, CreateParents: true}, []byte("deep"), 8)
	require.NoError(t, svc.WriteFile(stream))
	assert.Equal(t, "deep", readBack(t, path))

	// Without it, a missing parent is an error rather than a surprise mkdir.
	missing := filepath.Join(root, "x", "y.txt")
	err := svc.WriteFile(writeStreamFor(context.Background(),
		&sandboxdv1.WriteFileHeader{Path: missing}, []byte("no"), 8))
	require.Error(t, err)
	assert.NoFileExists(t, missing)
}

func TestWriteFile_Append(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "log.txt"), "first\n")
	svc := newConfined(t, root)

	stream := writeStreamFor(context.Background(),
		&sandboxdv1.WriteFileHeader{Path: path, Append: true}, []byte("second\n"), 3)
	require.NoError(t, svc.WriteFile(stream))

	assert.Equal(t, "first\nsecond\n", readBack(t, path))
	assert.Equal(t, uint64(7), stream.resp.GetBytesWritten(),
		"bytes_written is what this call sent, not the resulting file size")
	assert.False(t, stream.resp.GetCreated())
}

// An interrupted append is the case where getting it wrong is least visible:
// the original must survive whole, not half-extended.
func TestWriteFile_InterruptedAppendLeavesTheOriginalIntact(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "log.txt"), "first\n")
	svc := newConfined(t, root)

	stream := writeStreamFor(context.Background(),
		&sandboxdv1.WriteFileHeader{Path: path, Append: true},
		[]byte(strings.Repeat("more\n", 100)), 5)
	stream.failAfter = 3
	stream.failErr = errors.New("client gone")

	require.Error(t, svc.WriteFile(stream))
	assert.Equal(t, "first\n", readBack(t, path))
	assert.Empty(t, tempSiblings(t, root))
}

func TestWriteFile_PreservesExistingMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "secret.txt"), "sensitive\n")
	require.NoError(t, os.Chmod(path, 0o600))
	svc := newConfined(t, root)

	stream := writeStreamFor(context.Background(),
		// A mode on the header is for new files, and must not widen this one.
		&sandboxdv1.WriteFileHeader{Path: path, Mode: 0o666}, []byte("rewritten\n"), 4)
	require.NoError(t, svc.WriteFile(stream))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"overwriting a 0600 file must not turn it 0666")
}

func TestWriteFile_AppliesModeToNewFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	root := tempRoot(t)
	svc := newConfined(t, root)

	explicit := filepath.Join(root, "explicit.txt")
	require.NoError(t, svc.WriteFile(writeStreamFor(context.Background(),
		&sandboxdv1.WriteFileHeader{Path: explicit, Mode: 0o600}, []byte("x"), 8)))
	info, err := os.Stat(explicit)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	// The default is applied through the umask rather than around it, so a
	// daemon running under umask 022 still produces 0644.
	defaulted := filepath.Join(root, "defaulted.txt")
	require.NoError(t, svc.WriteFile(writeStreamFor(context.Background(),
		&sandboxdv1.WriteFileHeader{Path: defaulted}, []byte("x"), 8)))
	info, err = os.Stat(defaulted)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
}

// CRLF content is content. The agent stores the bytes it was given.
func TestWriteFile_CRLFRoundTripsUnchanged(t *testing.T) {
	root := tempRoot(t)
	svc := newConfined(t, root)
	path := filepath.Join(root, "crlf.txt")
	content := []byte("alpha\r\nbeta\r\ngamma\r\n")

	require.NoError(t, svc.WriteFile(writeStreamFor(context.Background(),
		&sandboxdv1.WriteFileHeader{Path: path}, content, 5)))

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, content, raw, "no line ending was rewritten on the way in")

	back := readAll(t, svc, &sandboxdv1.ReadFileRequest{Path: path})
	assert.Equal(t, content, back.content, "nor on the way out")
}

func TestWriteFile_RequiresAHeaderFirst(t *testing.T) {
	root := tempRoot(t)
	svc := newConfined(t, root)

	chunkFirst := &fakeWriteStream{ctx: context.Background(), msgs: []*sandboxdv1.WriteFileRequest{
		{Event: &sandboxdv1.WriteFileRequest_Chunk{Chunk: []byte("no header")}},
	}}
	assert.Equal(t, codes.InvalidArgument, status.Code(svc.WriteFile(chunkFirst)))

	empty := &fakeWriteStream{ctx: context.Background()}
	assert.Equal(t, codes.InvalidArgument, status.Code(svc.WriteFile(empty)))

	twoHeaders := &fakeWriteStream{ctx: context.Background(), msgs: []*sandboxdv1.WriteFileRequest{
		{Event: &sandboxdv1.WriteFileRequest_Header{Header: &sandboxdv1.WriteFileHeader{Path: filepath.Join(root, "a")}}},
		{Event: &sandboxdv1.WriteFileRequest_Header{Header: &sandboxdv1.WriteFileHeader{Path: filepath.Join(root, "b")}}},
	}}
	assert.Equal(t, codes.InvalidArgument, status.Code(svc.WriteFile(twoHeaders)))
}

func TestWriteFile_RejectsADirectoryTarget(t *testing.T) {
	root := tempRoot(t)
	svc := newConfined(t, root)
	assert.Equal(t, codes.InvalidArgument, status.Code(svc.WriteFile(writeStreamFor(
		context.Background(), &sandboxdv1.WriteFileHeader{Path: root}, []byte("x"), 8))))
}

// 100 MB in the other direction, with the same live-heap assertion.
func TestWriteFile_LargeStreamIsNotBufferedWhole(t *testing.T) {
	if testing.Short() {
		t.Skip("streams 100 MB")
	}
	root := tempRoot(t)
	svc := newConfined(t, root)
	path := filepath.Join(root, "large.bin")

	const total = 100 << 20
	baseline := liveHeap()
	var peak uint64

	stream := &generatedWriteStream{
		ctx:       context.Background(),
		header:    &sandboxdv1.WriteFileHeader{Path: path},
		total:     total,
		chunkSize: 64 << 10,
		fill:      'z',
		onChunk: func(sent int) {
			if sent%(16<<20) < 64<<10 {
				if live := liveHeap(); live > peak {
					peak = live
				}
			}
		},
	}
	require.NoError(t, svc.WriteFile(stream))

	assert.Equal(t, uint64(total), stream.resp.GetBytesWritten())
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, int64(total), info.Size())
	assert.Less(t, peak, baseline+32<<20,
		"live heap during the write (%d) must not track the 100 MB payload (baseline %d)", peak, baseline)
}
