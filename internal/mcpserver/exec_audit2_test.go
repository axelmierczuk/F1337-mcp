package mcpserver_test

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

// Round 1 enumerated the streams that could end early and reported a cut one as
// clean: the pull's read, grep's search, the write's send. sandbox_exec's own
// stream is the fourth, and its two guards — an output stream that ends without
// a result, and the two status codes that arrive *after* the command has run —
// were correct and untested. A guard with no test is one nobody will notice
// removing.

// resultlessExec streams output and then ends cleanly, with no terminal result.
type resultlessExec struct{}

func (resultlessExec) Exec(context.Context, *sandboxdv1.ExecRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[sandboxdv1.ExecResponse], error) {
	return &recvStream[sandboxdv1.ExecResponse]{messages: []*sandboxdv1.ExecResponse{
		{Event: &sandboxdv1.ExecResponse_Output{Output: &sandboxdv1.OutputChunk{
			Stream: sandboxdv1.Stream_STREAM_STDOUT, Data: []byte("started work\n"),
		}}},
	}}, nil
}

// TestExec_AStreamThatEndedWithoutAResultIsNotReportedAsAnExit.
//
// The stream is zero or more output chunks then exactly one result. Without it
// there is no exit code, and the nil-safe getters render that absence as exit
// zero — a command whose fate is unknown reported as one that succeeded, with
// its partial output attached to make the story convincing.
func TestExec_AStreamThatEndedWithoutAResultIsNotReportedAsAnExit(t *testing.T) {
	f := newAgentFixture(t, backendOptions{})
	f.clients.execOverride = resultlessExec{}

	text := f.fails("sandbox_exec", map[string]any{"argv": []any{"make", "install"}})

	assert.Contains(t, text, "without reporting a result")
	assert.Contains(t, text, "may well have run",
		"a command whose fate is unknown must not read as one that did not run")
	assert.NotContains(t, text, "rpc error: code =")
}

// codeExec fails the stream with a fixed status after the call is accepted.
type codeExec struct{ code codes.Code }

func (c codeExec) Exec(context.Context, *sandboxdv1.ExecRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[sandboxdv1.ExecResponse], error) {
	return &erroringExecStream{err: status.Error(c.code, "the agent gave up on the stream")}, nil
}

type erroringExecStream struct {
	grpc.ClientStream
	err  error
	sent bool
}

func (e *erroringExecStream) Recv() (*sandboxdv1.ExecResponse, error) {
	if !e.sent {
		e.sent = true
		return &sandboxdv1.ExecResponse{Event: &sandboxdv1.ExecResponse_Output{
			Output: &sandboxdv1.OutputChunk{Stream: sandboxdv1.Stream_STREAM_STDOUT, Data: []byte("half a log\n")},
		}}, nil
	}
	if e.err != nil {
		err := e.err
		e.err = nil
		return nil, err
	}
	return nil, io.EOF
}

// TestExec_TheTwoCodesThatArriveAfterTheCommandRanSaySoWhileOthersDoNot.
//
// Aborted is the agent giving up on delivering to a caller that stopped
// reading, and Internal is a required audit record that could not be written.
// Both are returned *after* the command has done its work, so a blanket "the
// request was rejected" sends the model to retry something that already ran —
// which for an install, a migration or a deploy is the expensive mistake. Every
// other code keeps the ordinary phrasing: saying "this may have run" about a
// call the agent refused would be the same error mirrored.
func TestExec_TheTwoCodesThatArriveAfterTheCommandRanSaySoWhileOthersDoNot(t *testing.T) {
	for _, tc := range []struct {
		code  codes.Code
		warns bool
	}{
		{codes.Aborted, true},
		{codes.Internal, true},
		{codes.InvalidArgument, false},
		{codes.PermissionDenied, false},
	} {
		t.Run(tc.code.String(), func(t *testing.T) {
			f := newAgentFixture(t, backendOptions{})
			f.clients.execOverride = codeExec{code: tc.code}

			text := f.fails("sandbox_exec", map[string]any{"argv": []any{"make", "install"}})

			assert.Contains(t, text, "build-box", "every failure names the sandbox")
			assert.NotContains(t, text, "rpc error: code =")
			if tc.warns {
				assert.Contains(t, text, "may well have run")
			} else {
				assert.NotContains(t, text, "may well have run",
					"a request the agent refused outright did not run, and must not be described as though it might have")
			}
		})
	}
}
