package fs_test

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

// The round trip over a real gRPC connection: the generated handlers, the
// registration, and both stream directions. The other tests drive the service
// directly, which is faster and lets them hold a stream open; this one proves
// the wiring those tests bypass.
func TestOverGRPC_WriteThenReadRoundTrip(t *testing.T) {
	root := tempRoot(t)
	svc := newConfined(t, root)
	client := serveOverGRPC(t, svc)
	ctx := context.Background()

	path := filepath.Join(root, "round", "trip.txt")
	content := []byte(strings.Repeat("streamed over the wire\r\n", 4000))

	writer, err := client.WriteFile(ctx)
	require.NoError(t, err)
	require.NoError(t, writer.Send(&sandboxdv1.WriteFileRequest{
		Event: &sandboxdv1.WriteFileRequest_Header{Header: &sandboxdv1.WriteFileHeader{
			Path: path, CreateParents: true,
		}},
	}))
	for off := 0; off < len(content); off += 8192 {
		end := min(off+8192, len(content))
		require.NoError(t, writer.Send(&sandboxdv1.WriteFileRequest{
			Event: &sandboxdv1.WriteFileRequest_Chunk{Chunk: content[off:end]},
		}))
	}
	writeResp, err := writer.CloseAndRecv()
	require.NoError(t, err)
	assert.Equal(t, uint64(len(content)), writeResp.GetBytesWritten())
	assert.True(t, writeResp.GetCreated())

	reader, err := client.ReadFile(ctx, &sandboxdv1.ReadFileRequest{Path: path, Raw: true, MaxBytes: 1 << 20})
	require.NoError(t, err)

	var (
		got    []byte
		md     *sandboxdv1.FileMetadata
		result *sandboxdv1.ReadResult
		chunks int
	)
	for {
		resp, err := reader.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		switch {
		case resp.GetMetadata() != nil:
			md = resp.GetMetadata()
		case resp.GetResult() != nil:
			result = resp.GetResult()
		default:
			got = append(got, resp.GetChunk()...)
			chunks++
		}
	}

	assert.Equal(t, content, got, "byte-identical, CRLF included")
	require.NotNil(t, md)
	assert.Equal(t, uint64(len(content)), md.GetSizeBytes())
	assert.NotNil(t, result)
	assert.Greater(t, chunks, 1, "a 96 KB file arrives as several chunks")
}

func TestOverGRPC_GrepStreamsThenSummarises(t *testing.T) {
	root := tempRoot(t)
	writeFile(t, filepath.Join(root, "a.txt"), "alpha\nneedle\nomega\n")
	writeFile(t, filepath.Join(root, "b.txt"), "needle\n")
	client := serveOverGRPC(t, newConfined(t, root))

	stream, err := client.Grep(context.Background(), &sandboxdv1.GrepRequest{Pattern: "needle", Root: root})
	require.NoError(t, err)

	var (
		matches []*sandboxdv1.GrepMatch
		summary *sandboxdv1.GrepSummary
	)
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		if m := resp.GetMatch(); m != nil {
			matches = append(matches, m)
			continue
		}
		summary = resp.GetSummary()
	}

	require.Len(t, matches, 2)
	assert.Equal(t, uint64(2), matches[0].GetLineNumber())
	require.NotNil(t, summary)
	assert.Equal(t, uint64(2), summary.GetFilesSearched())
	assert.Equal(t, uint64(2), summary.GetMatchesFound())
}

func TestOverGRPC_EditAndListAndStat(t *testing.T) {
	root := tempRoot(t)
	path := writeFile(t, filepath.Join(root, "code.txt"), "before\n")
	client := serveOverGRPC(t, newConfined(t, root))
	ctx := context.Background()

	edit, err := client.EditFile(ctx, &sandboxdv1.EditFileRequest{
		Path: path, OldString: "before", NewString: "after",
	})
	require.NoError(t, err)
	assert.Equal(t, uint32(1), edit.GetReplacements())
	assert.Contains(t, edit.GetDiff(), "+after")

	list, err := client.ListDirectory(ctx, &sandboxdv1.ListDirectoryRequest{Path: root})
	require.NoError(t, err)
	assert.Len(t, list.GetEntries(), 1)

	stat, err := client.StatPath(ctx, &sandboxdv1.StatPathRequest{Path: path})
	require.NoError(t, err)
	assert.True(t, stat.GetExists())
	assert.Equal(t, uint64(6), stat.GetMetadata().GetSizeBytes())

	globbed, err := client.Glob(ctx, &sandboxdv1.GlobRequest{Pattern: "*.txt", Root: root})
	require.NoError(t, err)
	assert.Equal(t, []string{path}, globbed.GetPaths())
}

// MakeDirectory, RemovePath and MovePath are in the proto but in none of #8,
// #9 or #10. They answer Unimplemented rather than a guess at a contract nobody
// has written down, so a caller reaching for them gets a clear answer instead of
// a surprise.
func TestOverGRPC_UnscopedRPCsReportUnimplemented(t *testing.T) {
	root := tempRoot(t)
	client := serveOverGRPC(t, newConfined(t, root))
	ctx := context.Background()

	_, err := client.MakeDirectory(ctx, &sandboxdv1.MakeDirectoryRequest{Path: filepath.Join(root, "d")})
	assert.Equal(t, codes.Unimplemented, status.Code(err))

	_, err = client.RemovePath(ctx, &sandboxdv1.RemovePathRequest{Path: filepath.Join(root, "d")})
	assert.Equal(t, codes.Unimplemented, status.Code(err))

	_, err = client.MovePath(ctx, &sandboxdv1.MovePathRequest{
		Source: filepath.Join(root, "a"), Destination: filepath.Join(root, "b")})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}
