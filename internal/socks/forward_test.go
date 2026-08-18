package socks

import (
	"context"
	"io"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
)

// The wire between the two halves of this feature, which is the one place
// neither half's tests could see.
//
// The agent's tests build a ForwardOpen by hand and assert what its policy does
// with `socks`; this package's tests use a connector that never speaks gRPC at
// all. So the field that joins them — set here, in [ForwardConnector], and
// nowhere else — was asserted by nothing: clearing it left every test in this
// repository green, and it is what decides all three of these:
//
//   - which policy the agent applies. An agent with forward.socks_enabled false
//     and an allow list refuses a proxy and forwards to the listed hosts; a
//     connection that does not declare itself gets the second answer, so the
//     capability gate stops existing. The workstation-side preflight would not
//     catch it, because that is a guardrail this PR documents as one — the
//     boundary is the agent's, applied per connection.
//   - whether the unrestricted posture works at all. On an agent with
//     socks_enabled true and no allow list, a connection that does not declare
//     itself is judged as a forward and refused for reaching off-box.
//   - whether the connection is audited. Every proxied connection is recorded
//     wherever it went, including to loopback, and that turns on this field.

// recordingForward is an agent-side stream that answers the open and keeps what
// it was asked for.
type recordingForward struct {
	grpc.ClientStream

	answered bool

	mu   sync.Mutex
	open *sandboxdv1.ForwardOpen
}

func (s *recordingForward) Send(req *sandboxdv1.ForwardRequest) error {
	if open := req.GetOpen(); open != nil {
		s.mu.Lock()
		s.open = open
		s.mu.Unlock()
	}
	return nil
}

func (s *recordingForward) CloseSend() error { return nil }

func (s *recordingForward) Recv() (*sandboxdv1.ForwardResponse, error) {
	if !s.answered {
		s.answered = true
		return &sandboxdv1.ForwardResponse{
			Event: &sandboxdv1.ForwardResponse_Opened{Opened: &sandboxdv1.ForwardOpened{Success: true}},
		}, nil
	}
	// Nothing more to carry: the assertion is about the opening message.
	return nil, io.EOF
}

func (s *recordingForward) opened() *sandboxdv1.ForwardOpen {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.open
}

type recordingClient struct{ stream *recordingForward }

func (c *recordingClient) Forward(context.Context, ...grpc.CallOption) (grpc.BidiStreamingClient[sandboxdv1.ForwardRequest, sandboxdv1.ForwardResponse], error) {
	return c.stream, nil
}

// A proxied connection says so on the wire, and says where it is going in the
// words the client used.
func TestForwardConnector_DeclaresTheConnectionAsProxied(t *testing.T) {
	stream := &recordingForward{}
	server := startProxy(t, Options{Connect: ForwardConnector(&recordingClient{stream: stream})})

	c := dialProxy(t, server.Addr())
	require.Equal(t, byte(authNone), c.greet(t, authNone))
	require.Equal(t, byte(replySuccess), c.request(t, cmdConnect, addrDomain, []byte("db.internal"), 5432))

	open := stream.opened()
	require.NotNil(t, open, "the connector opened no stream")
	assert.True(t, open.GetSocks(),
		"a proxied connection has to declare itself, or the agent applies its forwarding rules to it: the capability gate stops applying, the unrestricted posture stops working, and the connection is recorded only if it happened to be off-box")
	assert.Equal(t, "db.internal", open.GetRemoteHost(),
		"the destination crosses as the name the client sent, for the agent to resolve")
	assert.Equal(t, uint32(5432), open.GetRemotePort())
}
