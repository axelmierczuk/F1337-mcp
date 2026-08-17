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

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	agentfs "github.com/axelmierczuk/fleet-mcp/internal/agent/fs"
)

func readAll(t *testing.T, svc *agentfs.Service, req *sandboxdv1.ReadFileRequest) *fakeReadStream {
	t.Helper()
	stream := newReadStream(context.Background())
	require.NoError(t, svc.ReadFile(req, stream))
	return stream
}

func TestReadFile_ReturnsContentAndMetadata(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "hello.txt"), "one\ntwo\nthree\n")
	svc := newConfined(t, root)

	stream := readAll(t, svc, &sandboxdv1.ReadFileRequest{Path: path})

	assert.Equal(t, "one\ntwo\nthree\n", string(stream.content))
	require.NotNil(t, stream.metadata)
	assert.Equal(t, path, stream.metadata.GetPath())
	assert.Equal(t, uint64(14), stream.metadata.GetSizeBytes())
	assert.False(t, stream.metadata.GetIsDir())
	assert.False(t, stream.metadata.GetIsBinary())

	require.NotNil(t, stream.result)
	assert.Equal(t, uint64(3), stream.result.GetLinesReturned())
	assert.Equal(t, uint64(3), stream.result.GetTotalLines())
	assert.True(t, stream.result.GetTotalLinesExact())
	assert.False(t, stream.result.GetTruncation().GetTruncated())
}

// The window is the window, and total_lines describes the file rather than the
// window.
func TestReadFile_LineWindow(t *testing.T) {
	root := tempRoot(t)
	var b strings.Builder
	for i := 1; i <= 100; i++ {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	path := writeFile(t, filepath.Join(root, "many.txt"), b.String())
	svc := newConfined(t, root)

	stream := readAll(t, svc, &sandboxdv1.ReadFileRequest{Path: path, OffsetLines: 10, LimitLines: 3})

	assert.Equal(t, "line 10\nline 11\nline 12\n", string(stream.content))
	assert.Equal(t, uint64(3), stream.result.GetLinesReturned())
	assert.Equal(t, uint64(100), stream.result.GetTotalLines())
	assert.True(t, stream.result.GetTotalLinesExact())
	assert.True(t, stream.result.GetTruncation().GetTruncated(),
		"a window that stops before the end of the file has to say so")
	assert.Equal(t, uint64(88), stream.result.GetTruncation().GetLinesOmitted())
}

// A file with no trailing newline still has a last line.
func TestReadFile_UnterminatedFinalLine(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "tail.txt"), "a\nb")
	svc := newConfined(t, root)

	stream := readAll(t, svc, &sandboxdv1.ReadFileRequest{Path: path})

	assert.Equal(t, "a\nb", string(stream.content))
	assert.Equal(t, uint64(2), stream.result.GetLinesReturned())
	assert.Equal(t, uint64(2), stream.result.GetTotalLines())
	assert.True(t, stream.result.GetTotalLinesExact())
}

// A line routinely spans more than one read, and a file larger than one chunk
// routinely ends on a newline. Counting from the last segment of each buffer
// would report one line too many for both.
func TestReadFile_CountsLinesAcrossChunkBoundaries(t *testing.T) {
	root := tempRoot(t)

	// One line longer than the read buffer, terminated.
	long := writeFile(t, filepath.Join(root, "long-line.txt"), strings.Repeat("x", 70_000)+"\n")
	// Many lines, well over one buffer, terminated.
	many := writeFile(t, filepath.Join(root, "many-lines.txt"), strings.Repeat("0123456789\n", 20_000))
	// The same again with no final newline.
	unterminated := writeFile(t, filepath.Join(root, "unterminated.txt"),
		strings.Repeat("0123456789\n", 20_000)+"tail")

	svc := newConfined(t, root)

	one := readAll(t, svc, &sandboxdv1.ReadFileRequest{Path: long, MaxBytes: 1 << 20})
	assert.Equal(t, uint64(1), one.result.GetTotalLines())
	assert.Equal(t, uint64(1), one.result.GetLinesReturned())
	assert.Len(t, one.content, 70_001, "a line longer than the buffer still streams whole")

	full := readAll(t, svc, &sandboxdv1.ReadFileRequest{Path: many, LimitLines: 50_000, MaxBytes: 8 << 20})
	assert.Equal(t, uint64(20_000), full.result.GetTotalLines())
	assert.Equal(t, uint64(20_000), full.result.GetLinesReturned())

	tail := readAll(t, svc, &sandboxdv1.ReadFileRequest{Path: unterminated, LimitLines: 50_000, MaxBytes: 8 << 20})
	assert.Equal(t, uint64(20_001), tail.result.GetTotalLines())
	assert.True(t, strings.HasSuffix(string(tail.content), "tail"))
}

func TestReadFile_EmptyFile(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "empty.txt"), "")
	svc := newConfined(t, root)

	stream := readAll(t, svc, &sandboxdv1.ReadFileRequest{Path: path})

	assert.Empty(t, stream.content)
	assert.Equal(t, uint64(0), stream.result.GetTotalLines())
	assert.True(t, stream.result.GetTotalLinesExact())
}

func TestReadFile_OffsetPastEndReturnsNothing(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "short.txt"), "a\nb\n")
	svc := newConfined(t, root)

	stream := readAll(t, svc, &sandboxdv1.ReadFileRequest{Path: path, OffsetLines: 99})

	assert.Empty(t, stream.content)
	assert.Equal(t, uint64(0), stream.result.GetLinesReturned())
	assert.Equal(t, uint64(2), stream.result.GetTotalLines())
}

// Past the counting bound, total_lines is a lower bound and says so. The flag
// is the whole point: a caller rendering "line 12 of N" must not print N.
func TestReadFile_TotalLinesBoundIsReported(t *testing.T) {
	root := tempRoot(t)
	var b strings.Builder
	for i := 0; i < 5000; i++ {
		b.WriteString("0123456789012345678901234567890123456789\n")
	}
	path := writeFile(t, filepath.Join(root, "big.txt"), b.String())

	// A counting bound below the file's size, standing in for the 32 MiB
	// production one without writing 32 MiB.
	svc := agentfs.NewService(mustJail(t, root), testLogger(), agentfs.Limits{LineCountLimitBytes: 1024})

	stream := readAll(t, svc, &sandboxdv1.ReadFileRequest{Path: path, LimitLines: 2})

	assert.Equal(t, uint64(2), stream.result.GetLinesReturned())
	assert.False(t, stream.result.GetTotalLinesExact(),
		"a file over the counting bound must not claim an exact line count")
	assert.Less(t, stream.result.GetTotalLines(), uint64(5000),
		"the reported count is what the read passed on the way, not the whole file")
	assert.True(t, stream.result.GetTruncation().GetTruncated())
}

// Under the bound the count is exact, so the ordinary case keeps a usable
// number.
func TestReadFile_TotalLinesExactUnderBound(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "small.txt"), strings.Repeat("x\n", 400))
	svc := newConfined(t, root)

	stream := readAll(t, svc, &sandboxdv1.ReadFileRequest{Path: path, LimitLines: 2})

	assert.Equal(t, uint64(400), stream.result.GetTotalLines())
	assert.True(t, stream.result.GetTotalLinesExact())
}

// A binary file is reported, not mangled: the metadata still arrives, and the
// content does not.
func TestReadFile_BinaryFlaggedNotMangled(t *testing.T) {
	root := tempRoot(t)
	path := filepath.Join(root, "image.bin")
	content := []byte{0x89, 'P', 'N', 'G', 0x00, 0x1a, 0x0a, 0xff, 0xfe}
	require.NoError(t, os.WriteFile(path, content, 0o644))
	svc := newConfined(t, root)

	stream := newReadStream(context.Background())
	err := svc.ReadFile(&sandboxdv1.ReadFileRequest{Path: path}, stream)

	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.NotNil(t, stream.metadata, "the metadata is sent before the refusal, so the caller learns why")
	assert.True(t, stream.metadata.GetIsBinary())
	assert.Empty(t, stream.content, "not one byte of a binary file is returned as text")

	// raw returns it byte-identical.
	rawStream := readAll(t, svc, &sandboxdv1.ReadFileRequest{Path: path, Raw: true})
	assert.Equal(t, content, rawStream.content)
	assert.True(t, rawStream.metadata.GetIsBinary())
}

// Invalid UTF-8 with no NUL byte is binary too: returning it as text produces
// replacement characters a model then reasons about.
func TestReadFile_InvalidUTF8IsBinary(t *testing.T) {
	root := tempRoot(t)
	path := filepath.Join(root, "latin1.txt")
	require.NoError(t, os.WriteFile(path, []byte("caf\xe9 au lait\n"), 0o644))
	svc := newConfined(t, root)

	err := svc.ReadFile(&sandboxdv1.ReadFileRequest{Path: path}, newReadStream(context.Background()))
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// A multi-byte rune straddling the 8 KiB sniff window is not invalid UTF-8.
func TestReadFile_RuneAcrossSniffBoundaryIsText(t *testing.T) {
	root := tempRoot(t)
	// Pad so that a three-byte rune starts at byte 8190 and ends at 8192.
	content := strings.Repeat("a", 8190) + "€" + strings.Repeat("b", 100)
	path := writeFile(t, filepath.Join(root, "wide.txt"), content)
	svc := newConfined(t, root)

	stream := readAll(t, svc, &sandboxdv1.ReadFileRequest{Path: path})
	assert.False(t, stream.metadata.GetIsBinary())
	assert.Equal(t, content, string(stream.content))
}

func TestReadFile_MaxBytesTruncates(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "long.txt"), strings.Repeat("abcdefghij\n", 100))
	svc := newConfined(t, root)

	stream := readAll(t, svc, &sandboxdv1.ReadFileRequest{Path: path, MaxBytes: 25})

	assert.Len(t, stream.content, 25)
	assert.True(t, stream.result.GetTruncation().GetTruncated())
	assert.Positive(t, stream.result.GetTruncation().GetBytesOmitted())
}

// CRLF survives a read untouched. The agent must not decide a file's line
// endings for it.
func TestReadFile_CRLFUnchanged(t *testing.T) {
	root := tempRoot(t)
	content := "first\r\nsecond\r\nthird\r\n"
	path := writeFile(t, filepath.Join(root, "crlf.txt"), content)
	svc := newConfined(t, root)

	stream := readAll(t, svc, &sandboxdv1.ReadFileRequest{Path: path})
	assert.Equal(t, content, string(stream.content))
	assert.Equal(t, uint64(3), stream.result.GetTotalLines())

	windowed := readAll(t, svc, &sandboxdv1.ReadFileRequest{Path: path, OffsetLines: 2, LimitLines: 1})
	assert.Equal(t, "second\r\n", string(windowed.content),
		"a windowed read returns the line's own terminator, not a normalised one")
}

func TestReadFile_RawRejectsLineWindow(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "a.txt"), "x\n")
	svc := newConfined(t, root)

	err := svc.ReadFile(&sandboxdv1.ReadFileRequest{Path: path, Raw: true, LimitLines: 3},
		newReadStream(context.Background()))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestReadFile_RejectsDirectoryAndMissing(t *testing.T) {
	root := tempRoot(t)
	svc := newConfined(t, root)

	err := svc.ReadFile(&sandboxdv1.ReadFileRequest{Path: root}, newReadStream(context.Background()))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	err = svc.ReadFile(&sandboxdv1.ReadFileRequest{Path: filepath.Join(root, "nope.txt")},
		newReadStream(context.Background()))
	assert.Equal(t, codes.NotFound, status.Code(err))

	err = svc.ReadFile(&sandboxdv1.ReadFileRequest{}, newReadStream(context.Background()))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// A 100 MB file streams. The assertion is on live heap after a forced
// collection, sampled while the stream is still running: a handler that
// buffered the file would hold it whether or not the collector ran, so this
// distinguishes streaming from buffering rather than measuring allocation
// noise.
func TestReadFile_LargeFileIsNotBufferedWhole(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 100 MB")
	}
	root := tempRoot(t)
	path := filepath.Join(root, "large.bin")
	writeLargeFile(t, path, 100<<20)
	svc := newConfined(t, root)

	baseline := liveHeap()
	var peak, chunks uint64

	stream := newReadStream(context.Background())
	stream.discard = true
	stream.onChunk = func([]byte) error {
		chunks++
		if chunks%256 == 0 {
			if live := liveHeap(); live > peak {
				peak = live
			}
		}
		return nil
	}
	require.NoError(t, svc.ReadFile(&sandboxdv1.ReadFileRequest{Path: path, Raw: true, MaxBytes: 200 << 20}, stream))

	assert.Greater(t, chunks, uint64(1000), "a 100 MB file has to arrive as many chunks, not one")
	assert.Less(t, peak, baseline+32<<20,
		"live heap during the read (%d) must not track the 100 MB file size (baseline %d)", peak, baseline)
}

// liveHeap forces a collection and reports what is still reachable. Cumulative
// allocation would count every chunk ever sent and prove nothing; what matters
// is whether the handler is holding the file.
func liveHeap() uint64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// writeLargeFile writes size bytes of text without holding them.
func writeLargeFile(t *testing.T, path string, size int) {
	t.Helper()
	f, err := os.Create(path) //nolint:gosec // path is inside the test's own temp directory
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()

	block := []byte(strings.Repeat("sandboxd streams this file rather than buffering it.\n", 512))
	for written := 0; written < size; {
		n := min(len(block), size-written)
		m, err := f.Write(block[:n])
		require.NoError(t, err)
		written += m
	}
}
