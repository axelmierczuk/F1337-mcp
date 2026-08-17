package fs_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	agentfs "github.com/axelmierczuk/sandboxd-mcp/internal/agent/fs"
	"github.com/axelmierczuk/sandboxd-mcp/internal/security/jail"
)

// tempRoot returns a temp directory with its symlinks resolved.
//
// macOS hands out /var/folders/..., where /var is a symlink to /private/var.
// The jail resolves its roots, so every path this service returns is the
// resolved form; a test comparing against the unresolved one fails on macOS and
// nowhere else.
func tempRoot(t *testing.T) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	return resolved
}

// newConfined builds a service confined to root — the configuration an agent
// runs in with exec disabled, and the only one where a path can be refused.
func newConfined(t *testing.T, root string) *agentfs.Service {
	t.Helper()
	confinement, err := jail.New(jail.Config{Roots: []string{root}})
	require.NoError(t, err)
	return agentfs.NewService(confinement, testLogger(), agentfs.Limits{})
}

// newUnconfined builds a service with no confinement — the default agent, where
// exec is enabled and the jail would stop nothing. Every test that asserts a
// refusal has an unconfined twin asserting there is no refusal to make.
func newUnconfined(t *testing.T, workingDir string) *agentfs.Service {
	t.Helper()
	// jail.Unconfined resolves relative paths against the process working
	// directory; the tests want them resolved against their own tree, so they
	// pass absolute paths and this only fixes the default search root.
	t.Chdir(workingDir)
	return agentfs.NewService(jail.Unconfined(), testLogger(), agentfs.Limits{})
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// mustJail builds a confined jail, for a test that needs to pass its own
// Limits alongside it.
func mustJail(t *testing.T, root string) *jail.Jail {
	t.Helper()
	confinement, err := jail.New(jail.Config{Roots: []string{root}})
	require.NoError(t, err)
	return confinement
}

// agentfsService builds a confined service with a custom edit ceiling.
func agentfsService(t *testing.T, root string, maxEditBytes int64) *agentfs.Service {
	t.Helper()
	return agentfs.NewService(mustJail(t, root), testLogger(), agentfs.Limits{MaxEditBytes: maxEditBytes})
}

// tempSiblings returns the atomic-write temp files left in a directory. There
// should never be any once a call has returned, committed or not.
func tempSiblings(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var out []string
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".sandboxd-") && strings.HasSuffix(entry.Name(), ".tmp") {
			out = append(out, entry.Name())
		}
	}
	return out
}

// writeFile writes a fixture file, creating parents.
func writeFile(t *testing.T, path, content string) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

// readBack reads a file with the standard library, which is the independent
// check that the service did what it claimed.
func readBack(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(data)
}

// requireSymlink creates a symlink, skipping the test where the platform will
// not allow one.
func requireSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks need SeCreateSymbolicLinkPrivilege or developer mode on Windows: %v", err)
		}
		t.Fatalf("symlink %s -> %s: %v", link, target, err)
	}
}

// fakeReadStream captures a ReadFile server stream.
//
// The handlers are exercised directly through it rather than over a connection,
// so a test can hold a stream open at a chosen point — which is how the
// streaming and memory assertions are made deterministic rather than timed.
type fakeReadStream struct {
	grpc.ServerStream
	ctx      context.Context
	metadata *sandboxdv1.FileMetadata
	content  []byte
	result   *sandboxdv1.ReadResult
	sends    int
	// discard drops chunk content instead of collecting it, so the memory
	// assertion measures the handler rather than the test's own buffer.
	discard bool
	// onChunk runs on every chunk, for a test that needs to observe the stream
	// while it is still going.
	onChunk func(chunk []byte) error
}

func newReadStream(ctx context.Context) *fakeReadStream {
	return &fakeReadStream{ctx: ctx}
}

func (s *fakeReadStream) Context() context.Context { return s.ctx }

func (s *fakeReadStream) Send(resp *sandboxdv1.ReadFileResponse) error {
	s.sends++
	switch {
	case resp.GetMetadata() != nil:
		s.metadata = resp.GetMetadata()
	case resp.GetResult() != nil:
		s.result = resp.GetResult()
	default:
		chunk := resp.GetChunk()
		if !s.discard {
			s.content = append(s.content, chunk...)
		}
		if s.onChunk != nil {
			return s.onChunk(chunk)
		}
	}
	return nil
}

// fakeWriteStream replays a prepared WriteFile client stream.
type fakeWriteStream struct {
	grpc.ServerStream
	ctx  context.Context
	msgs []*sandboxdv1.WriteFileRequest
	idx  int
	// failAfter, when positive, ends the stream with failErr after that many
	// messages, standing in for a client that died mid-transfer.
	failAfter int
	failErr   error
	resp      *sandboxdv1.WriteFileResponse
	// onRecv runs before each message is handed to the handler.
	onRecv func(i int)
}

func (s *fakeWriteStream) Context() context.Context { return s.ctx }

func (s *fakeWriteStream) Recv() (*sandboxdv1.WriteFileRequest, error) {
	if s.onRecv != nil {
		s.onRecv(s.idx)
	}
	if s.failAfter > 0 && s.idx >= s.failAfter {
		return nil, s.failErr
	}
	if s.idx >= len(s.msgs) {
		return nil, io.EOF
	}
	msg := s.msgs[s.idx]
	s.idx++
	return msg, nil
}

func (s *fakeWriteStream) SendAndClose(resp *sandboxdv1.WriteFileResponse) error {
	s.resp = resp
	return nil
}

// writeStreamFor builds a client stream carrying a header and content.
func writeStreamFor(ctx context.Context, header *sandboxdv1.WriteFileHeader, content []byte, chunkSize int) *fakeWriteStream {
	msgs := []*sandboxdv1.WriteFileRequest{
		{Event: &sandboxdv1.WriteFileRequest_Header{Header: header}},
	}
	for off := 0; off < len(content); off += chunkSize {
		end := min(off+chunkSize, len(content))
		chunk := append([]byte(nil), content[off:end]...)
		msgs = append(msgs, &sandboxdv1.WriteFileRequest{
			Event: &sandboxdv1.WriteFileRequest_Chunk{Chunk: chunk},
		})
	}
	return &fakeWriteStream{ctx: ctx, msgs: msgs}
}

// generatedWriteStream produces chunks on demand instead of holding them.
//
// A 100 MB transfer built as a slice of messages would put 100 MB on the test's
// own heap, which is exactly the thing the memory assertion is trying to
// measure in the handler.
type generatedWriteStream struct {
	grpc.ServerStream
	ctx       context.Context
	header    *sandboxdv1.WriteFileHeader
	total     int
	chunkSize int
	fill      byte

	sent     int
	sentHead bool
	resp     *sandboxdv1.WriteFileResponse
	// onChunk runs after each chunk is handed over, with the bytes sent so far.
	onChunk func(sent int)
}

func (s *generatedWriteStream) Context() context.Context { return s.ctx }

func (s *generatedWriteStream) Recv() (*sandboxdv1.WriteFileRequest, error) {
	if !s.sentHead {
		s.sentHead = true
		return &sandboxdv1.WriteFileRequest{
			Event: &sandboxdv1.WriteFileRequest_Header{Header: s.header},
		}, nil
	}
	if s.sent >= s.total {
		return nil, io.EOF
	}
	n := min(s.chunkSize, s.total-s.sent)
	chunk := make([]byte, n)
	for i := range chunk {
		chunk[i] = s.fill
	}
	s.sent += n
	if s.onChunk != nil {
		s.onChunk(s.sent)
	}
	return &sandboxdv1.WriteFileRequest{
		Event: &sandboxdv1.WriteFileRequest_Chunk{Chunk: chunk},
	}, nil
}

func (s *generatedWriteStream) SendAndClose(resp *sandboxdv1.WriteFileResponse) error {
	s.resp = resp
	return nil
}

// fakeGrepStream captures a Grep server stream.
type fakeGrepStream struct {
	grpc.ServerStream
	ctx     context.Context
	matches []*sandboxdv1.GrepMatch
	summary *sandboxdv1.GrepSummary
	// onMatch runs on every match before it is recorded, so a test can block
	// the walk at a known point.
	onMatch func(m *sandboxdv1.GrepMatch) error
}

func newGrepStream(ctx context.Context) *fakeGrepStream {
	return &fakeGrepStream{ctx: ctx}
}

func (s *fakeGrepStream) Context() context.Context { return s.ctx }

func (s *fakeGrepStream) Send(resp *sandboxdv1.GrepResponse) error {
	if summary := resp.GetSummary(); summary != nil {
		s.summary = summary
		return nil
	}
	m := resp.GetMatch()
	if s.onMatch != nil {
		if err := s.onMatch(m); err != nil {
			return err
		}
	}
	s.matches = append(s.matches, m)
	return nil
}

// paths returns the matched paths, for an assertion that does not care about
// line content.
func (s *fakeGrepStream) paths() []string {
	out := make([]string, 0, len(s.matches))
	for _, m := range s.matches {
		out = append(out, m.GetPath())
	}
	return out
}

// serveOverGRPC registers the service on a real gRPC server over bufconn and
// returns a client.
//
// Most tests drive the handlers directly, which is faster and lets them hold a
// stream open. This exists so that at least one test of each streaming RPC goes
// through the generated code and a real connection — the wiring the daemon
// actually uses, including Register.
func serveOverGRPC(t *testing.T, svc *agentfs.Service) sandboxdv1.FileServiceClient {
	t.Helper()

	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	svc.Register(server)
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return sandboxdv1.NewFileServiceClient(conn)
}
