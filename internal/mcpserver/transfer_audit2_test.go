package mcpserver_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver/tools"
)

// Round 2's findings. Each of these fails with its fix reverted.

// TestTransfer_APulledEntryCannotLeaveTheDestinationThroughASymlinkInsideTheWorkingDirectory.
//
// Round 1 closed two ways out of the destination: a name spelling a traversal,
// and a subdirectory of the destination that is a symlink pointing out of the
// *working directory*. This is the third, and it is the one the two checks
// between them did not cover: the name is checked against the destination root
// but only as written, and the resolved path is checked only against the
// working directory. A subdirectory of the destination that links to a sibling
// satisfies both — so the sandbox, which chooses these names, decides which
// directory of the working tree the file lands in, and the result reports it as
// delivered to a path it never reached.
//
// Sibling directories of a destination are ordinary: a repository whose
// `results/logs` is a link to a shared log directory is the shape here, and
// "pull the results" then writes wherever the link goes.
func TestTransfer_APulledEntryCannotLeaveTheDestinationThroughASymlinkInsideTheWorkingDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a symlink on Windows needs a privilege CI does not grant")
	}
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	remote := f.path("results")
	f.clients.filesOverride = &namingFiles{
		FileServiceClient: f.backend.files,
		root:              remote,
		names:             []string{"keep/real.txt", "logs/escaped.txt"},
	}

	destination := filepath.Join(local, "pulled")
	// A sibling of the destination, well inside the working directory, so the
	// local write confinement has nothing to object to.
	sibling := filepath.Join(local, "sibling")
	require.NoError(t, os.MkdirAll(destination, 0o750))
	require.NoError(t, os.MkdirAll(sibling, 0o750))
	require.NoError(t, os.Symlink(sibling, filepath.Join(destination, "logs")))

	out := structured[transferResult](t, f.ok("fleet_transfer", map[string]any{
		"direction": "pull", "source": remote, "destination": destination, "recursive": true,
	}))

	assert.Equal(t, 1, out.Files, "only the entry that stays inside the destination is transferred")
	assert.FileExists(t, filepath.Join(destination, "keep", "real.txt"))

	require.Equal(t, 1, out.SkippedCount, "and the one that does not is reported, not silently written elsewhere")
	assert.Equal(t, "logs/escaped.txt", out.Skipped[0].Path)
	assert.Contains(t, out.Skipped[0].Reason, "outside the destination directory")

	assert.NoFileExists(t, filepath.Join(sibling, "escaped.txt"),
		"a link out of the destination must not be written through, even when it stays inside the working directory")
}

// hugeStatFiles reports whatever size it is told to for any path, and serves a
// tiny file for it. It is a sandbox that describes its filesystem wrongly —
// which is every sandbox, from this side, since the whole point of one is
// running code nobody vetted.
type hugeStatFiles struct {
	sandboxdv1.FileServiceClient
	size uint64
}

func (h *hugeStatFiles) StatPath(_ context.Context, in *sandboxdv1.StatPathRequest, _ ...grpc.CallOption) (*sandboxdv1.StatPathResponse, error) {
	return &sandboxdv1.StatPathResponse{Exists: true, Metadata: &sandboxdv1.FileMetadata{
		Path: in.GetPath(), SizeBytes: h.size, Mode: 0o644, ModifiedAt: timestamppb.Now(),
	}}, nil
}

// TestTransfer_ASingleFilePullOverTheByteCapIsRefusedNamingIt.
//
// #25 asks for the size cap to be "refused up front naming the limit rather
// than a transfer that runs for ten minutes". Both tree walks check it as they
// accumulate; the single-file path had no walk and so no check at all, and a
// pull of a file over the cap instead streamed the whole 256 MiB the agent
// would give it before failing as "truncated".
//
// The size also feeds the per-file RPC deadline, which scales with it. Nothing
// but the hour-long ceiling stood between a size the sandbox made up and a tool
// call held open for that hour; the cap is what puts the ceiling out of reach.
func TestTransfer_ASingleFilePullOverTheByteCapIsRefusedNamingIt(t *testing.T) {
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})
	f.clients.filesOverride = &hugeStatFiles{FileServiceClient: f.backend.files, size: 4 << 30}

	destination := filepath.Join(local, "huge.bin")
	text := f.fails("fleet_transfer", map[string]any{
		"direction": "pull", "source": f.path("huge.bin"), "destination": destination,
	})

	assert.Contains(t, text, "256.0 MiB", "the refusal must name the limit")
	assert.Contains(t, text, "4.0 GiB", "and what it was asked to move")
	assert.NoFileExists(t, destination, "and nothing may be fetched before the check")
}

// TestTransfer_ASingleFilePushOverTheByteCapIsRefusedNamingIt, the same limit
// in the other direction. The file is sparse: its apparent size is what the cap
// is measured against, and materialising a quarter of a gigabyte to test a
// comparison is a quarter of a gigabyte of CI disk.
func TestTransfer_ASingleFilePushOverTheByteCapIsRefusedNamingIt(t *testing.T) {
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	source := filepath.Join(local, "huge.bin")
	handle, err := os.Create(source) //nolint:gosec // a path this test just built under its own working directory
	require.NoError(t, err)
	require.NoError(t, handle.Truncate(int64(tools.MaxTransferBytes)+1))
	require.NoError(t, handle.Close())

	destination := f.path("huge.bin")
	text := f.fails("fleet_transfer", map[string]any{
		"direction": "push", "source": source, "destination": destination,
	})

	assert.Contains(t, text, "256.0 MiB", "the refusal must name the limit")
	assert.NoFileExists(t, destination, "and nothing may be sent before the check")
}

// wrappingListFiles serves a listing whose declared sizes sum past 2^64.
type wrappingListFiles struct {
	sandboxdv1.FileServiceClient
	root string
}

func (w *wrappingListFiles) StatPath(_ context.Context, in *sandboxdv1.StatPathRequest, _ ...grpc.CallOption) (*sandboxdv1.StatPathResponse, error) {
	return &sandboxdv1.StatPathResponse{Exists: true, Metadata: &sandboxdv1.FileMetadata{
		Path: in.GetPath(), IsDir: true, ModifiedAt: timestamppb.Now(),
	}}, nil
}

func (w *wrappingListFiles) ListDirectory(_ context.Context, _ *sandboxdv1.ListDirectoryRequest, _ ...grpc.CallOption) (*sandboxdv1.ListDirectoryResponse, error) {
	resp := &sandboxdv1.ListDirectoryResponse{Path: w.root}
	// Two entries at half the range each, which sum to exactly 2^64 and so to
	// zero, and one small one after them. Wrapped, the plan's total is eight
	// bytes and the cap has nothing to object to.
	for i, size := range []uint64{1 << 63, 1 << 63, 8} {
		resp.Entries = append(resp.Entries, &sandboxdv1.FileMetadata{
			Path: fmt.Sprintf("%s/f%d.bin", w.root, i), SizeBytes: size, Mode: 0o644, ModifiedAt: timestamppb.Now(),
		})
	}
	return resp, nil
}

// TestTransfer_APulledTreeWhoseDeclaredSizesWrapIsStillRefused.
//
// Every size in a pull's plan is a number the sandbox chose, and enough of them
// add past 2^64 back round to nothing. The cap then passes on a tree whose
// declared size is larger than the machine, and each file is handed the largest
// RPC deadline the allowance permits on the way through.
func TestTransfer_APulledTreeWhoseDeclaredSizesWrapIsStillRefused(t *testing.T) {
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	remote := f.path("results")
	f.clients.filesOverride = &wrappingListFiles{FileServiceClient: f.backend.files, root: remote}

	destination := filepath.Join(local, "pulled")
	text := f.fails("fleet_transfer", map[string]any{
		"direction": "pull", "source": remote, "destination": destination, "recursive": true,
	})

	assert.Contains(t, text, "256.0 MiB", "the refusal must name the limit")
	assert.NoDirExists(t, destination, "and nothing may be fetched before the check")
}

// manySymlinksFiles serves a listing of nothing but symlinks, which a pull
// skips one by one.
type manySymlinksFiles struct {
	sandboxdv1.FileServiceClient
	root  string
	count int
}

func (m *manySymlinksFiles) StatPath(_ context.Context, in *sandboxdv1.StatPathRequest, _ ...grpc.CallOption) (*sandboxdv1.StatPathResponse, error) {
	return &sandboxdv1.StatPathResponse{Exists: true, Metadata: &sandboxdv1.FileMetadata{
		Path: in.GetPath(), IsDir: true, ModifiedAt: timestamppb.Now(),
	}}, nil
}

func (m *manySymlinksFiles) ListDirectory(_ context.Context, _ *sandboxdv1.ListDirectoryRequest, _ ...grpc.CallOption) (*sandboxdv1.ListDirectoryResponse, error) {
	resp := &sandboxdv1.ListDirectoryResponse{Path: m.root}
	for i := range m.count {
		resp.Entries = append(resp.Entries, &sandboxdv1.FileMetadata{
			Path: fmt.Sprintf("%s/link%03d", m.root, i), IsSymlink: true, SymlinkTarget: "/elsewhere",
			ModifiedAt: timestamppb.Now(),
		})
	}
	return resp, nil
}

// TestTransfer_TheSkipListIsBoundedWhileItsCountStaysExact.
//
// The result documents the split — "skipped_count is exact; it is the
// enumeration that is capped" — but the plan retained one record per skipped
// entry and threw all but twenty-five of them away at the end. A walk over a
// directory of device nodes, dangling links or an unreadable subtree grows that
// list with the tree rather than with what anyone reads.
func TestTransfer_TheSkipListIsBoundedWhileItsCountStaysExact(t *testing.T) {
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	const links = 120
	remote := f.path("results")
	f.clients.filesOverride = &manySymlinksFiles{FileServiceClient: f.backend.files, root: remote, count: links}

	out := structured[transferResult](t, f.ok("fleet_transfer", map[string]any{
		"direction": "pull", "source": remote, "destination": filepath.Join(local, "pulled"), "recursive": true,
	}))

	assert.Equal(t, links, out.SkippedCount, "the count stays exact")
	assert.LessOrEqual(t, len(out.Skipped), 25, "and only the reported few are retained")
	assert.NotEmpty(t, out.Skipped, "some of them, though: a count with no example is not actionable")
	assert.Contains(t, out.Note, fmt.Sprintf("%d entries were skipped", links))
}
