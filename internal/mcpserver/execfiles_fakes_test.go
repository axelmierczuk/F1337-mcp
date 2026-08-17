package mcpserver_test

import (
	"context"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

// The canned Exec client below exists for one job: making the fleet-wide walks
// in selection_test.go — the echo fixtures and the synthesised calls — able to
// *call* the exec tool. It answers with the smallest plausible response and
// asserts nothing.
//
// What the tool actually does is tested against the real internal/agent/exec
// service over bufconn; see agentbackend_test.go. A tool whose behaviour was
// only ever tested against a fake like this would prove that the glue matches
// the fake, which is not the same as proving it matches the agent.

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
