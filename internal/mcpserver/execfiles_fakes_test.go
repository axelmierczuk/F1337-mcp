package mcpserver_test

import (
	"context"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
)

// The canned Exec and File clients below exist for one job: making the
// fleet-wide walks in selection_test.go — the echo fixtures and the synthesised
// calls — able to *call* the exec, file and transfer tools. They answer with
// the smallest plausible response and assert nothing.
//
// What those tools actually do is tested against the real internal/agent/exec
// and internal/agent/fs services over bufconn; see agentbackend_test.go. A
// tool whose behaviour was only ever tested against a fake like this would
// prove that the glue matches the fake, which is not the same as proving it
// matches the agent.

// recvStream replays a fixed sequence of messages as a server stream.
type recvStream[T any] struct {
	grpc.ClientStream
	messages []*T
	next     int
}

func (s *recvStream[T]) Recv() (*T, error) {
	if s.next >= len(s.messages) {
		return nil, io.EOF
	}
	msg := s.messages[s.next]
	s.next++
	return msg, nil
}

// sendStream collects what was sent and answers with a fixed response.
type sendStream[Req any, Res any] struct {
	grpc.ClientStream
	sent     []*Req
	response *Res
}

func (s *sendStream[Req, Res]) Send(msg *Req) error { s.sent = append(s.sent, msg); return nil }

func (s *sendStream[Req, Res]) CloseAndRecv() (*Res, error) { return s.response, nil }

// fakeExec is a canned ExecServiceClient: one line on each stream, exit 0.
type fakeExec struct{}

func (fakeExec) Exec(_ context.Context, _ *sandboxdv1.ExecRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[sandboxdv1.ExecResponse], error) {
	return &recvStream[sandboxdv1.ExecResponse]{messages: []*sandboxdv1.ExecResponse{
		{Event: &sandboxdv1.ExecResponse_Output{Output: &sandboxdv1.OutputChunk{
			Stream: sandboxdv1.Stream_STREAM_STDOUT, Data: []byte("ok\n"),
		}}},
		{Event: &sandboxdv1.ExecResponse_Result{Result: &sandboxdv1.ExecResult{
			ExitCode: 0, Duration: durationpb.New(0),
		}}},
	}}, nil
}

// fakeFiles is a canned FileServiceClient.
type fakeFiles struct{}

func (fakeFiles) ReadFile(_ context.Context, in *sandboxdv1.ReadFileRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[sandboxdv1.ReadFileResponse], error) {
	return &recvStream[sandboxdv1.ReadFileResponse]{messages: []*sandboxdv1.ReadFileResponse{
		{Event: &sandboxdv1.ReadFileResponse_Metadata{Metadata: &sandboxdv1.FileMetadata{
			Path: in.GetPath(), SizeBytes: 6, ModifiedAt: timestamppb.Now(),
		}}},
		{Event: &sandboxdv1.ReadFileResponse_Chunk{Chunk: []byte("hello\n")}},
		{Event: &sandboxdv1.ReadFileResponse_Result{Result: &sandboxdv1.ReadResult{
			LinesReturned: 1, TotalLines: 1, TotalLinesExact: true,
		}}},
	}}, nil
}

func (fakeFiles) WriteFile(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[sandboxdv1.WriteFileRequest, sandboxdv1.WriteFileResponse], error) {
	return &sendStream[sandboxdv1.WriteFileRequest, sandboxdv1.WriteFileResponse]{
		response: &sandboxdv1.WriteFileResponse{Path: "/remote/file", BytesWritten: 6, Created: true},
	}, nil
}

func (fakeFiles) EditFile(_ context.Context, in *sandboxdv1.EditFileRequest, _ ...grpc.CallOption) (*sandboxdv1.EditFileResponse, error) {
	return &sandboxdv1.EditFileResponse{Path: in.GetPath(), Replacements: 1, Diff: "@@ -1 +1 @@\n-old\n+new\n"}, nil
}

func (fakeFiles) ListDirectory(_ context.Context, in *sandboxdv1.ListDirectoryRequest, _ ...grpc.CallOption) (*sandboxdv1.ListDirectoryResponse, error) {
	return &sandboxdv1.ListDirectoryResponse{Path: in.GetPath(), Entries: []*sandboxdv1.FileMetadata{
		{Path: in.GetPath() + "/main.go", SizeBytes: 120, ModifiedAt: timestamppb.Now()},
	}}, nil
}

func (fakeFiles) StatPath(_ context.Context, _ *sandboxdv1.StatPathRequest, _ ...grpc.CallOption) (*sandboxdv1.StatPathResponse, error) {
	return &sandboxdv1.StatPathResponse{Exists: false}, nil
}

func (fakeFiles) Glob(_ context.Context, _ *sandboxdv1.GlobRequest, _ ...grpc.CallOption) (*sandboxdv1.GlobResponse, error) {
	return &sandboxdv1.GlobResponse{Paths: []string{"/srv/app/main.go"}}, nil
}

func (fakeFiles) Grep(_ context.Context, _ *sandboxdv1.GrepRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[sandboxdv1.GrepResponse], error) {
	return &recvStream[sandboxdv1.GrepResponse]{messages: []*sandboxdv1.GrepResponse{
		{Event: &sandboxdv1.GrepResponse_Match{Match: &sandboxdv1.GrepMatch{
			Path: "/srv/app/main.go", LineNumber: 7, Line: "func main() {",
		}}},
		{Event: &sandboxdv1.GrepResponse_Summary{Summary: &sandboxdv1.GrepSummary{
			FilesSearched: 1, MatchesFound: 1,
		}}},
	}}, nil
}

func (fakeFiles) MakeDirectory(_ context.Context, in *sandboxdv1.MakeDirectoryRequest, _ ...grpc.CallOption) (*sandboxdv1.MakeDirectoryResponse, error) {
	return &sandboxdv1.MakeDirectoryResponse{Path: in.GetPath(), Created: true}, nil
}

func (fakeFiles) RemovePath(_ context.Context, in *sandboxdv1.RemovePathRequest, _ ...grpc.CallOption) (*sandboxdv1.RemovePathResponse, error) {
	return &sandboxdv1.RemovePathResponse{Path: in.GetPath(), EntriesRemoved: 1}, nil
}

func (fakeFiles) MovePath(_ context.Context, in *sandboxdv1.MovePathRequest, _ ...grpc.CallOption) (*sandboxdv1.MovePathResponse, error) {
	return &sandboxdv1.MovePathResponse{Source: in.GetSource(), Destination: in.GetDestination()}, nil
}
