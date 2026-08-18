package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
)

// The half-close contract, asserted on the pump rather than through a live
// forward or proxy.
//
// TestForward_ClientCanStillSendAfterTheRemoteHalfCloses in the mcpserver suite
// asserts the same property end to end, but it cannot fail reliably: the bug it
// is named for is a race between this pump ending and the other one's last
// Send being consumed, so on an unloaded machine the wrong implementation wins
// the race and the test passes. These drive streamToLocal directly, through the
// narrowed [Receiver] this package already defines, so the invariant is pinned
// by something that fails every time.
//
// They live here rather than beside fleet_forward because the pump does: every
// caller of [Carry] — fleet_forward, fleet_socks, `fleetctl socks` — depends on
// this behaviour, and a test in one caller's package reads as being about that
// caller.

// scriptedForward replays a fixed sequence of responses and then blocks until
// released, standing in for an agent handler that has not returned yet.
type scriptedForward struct {
	events   []*sandboxdv1.ForwardResponse
	next     int
	released chan struct{}
}

func (s *scriptedForward) Recv() (*sandboxdv1.ForwardResponse, error) {
	if s.next < len(s.events) {
		event := s.events[s.next]
		s.next++
		return event, nil
	}
	if s.released != nil {
		<-s.released
	}
	return nil, io.EOF
}

func forwardData(b string) *sandboxdv1.ForwardResponse {
	return &sandboxdv1.ForwardResponse{Event: &sandboxdv1.ForwardResponse_Data{Data: []byte(b)}}
}

func forwardCloseEvent() *sandboxdv1.ForwardResponse {
	return &sandboxdv1.ForwardResponse{
		Event: &sandboxdv1.ForwardResponse_Close{Close: &sandboxdv1.ForwardClose{Reason: "the sandbox-side connection closed"}},
	}
}

// tcpPair returns two ends of a real loopback connection. A net.Pipe would not
// do: CloseLocalWrite half-closes a *net.TCPConn and closes anything else
// outright, and the difference is the whole subject here.
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = lis.Close() }()

	type accepted struct {
		conn net.Conn
		err  error
	}
	done := make(chan accepted, 1)
	go func() {
		conn, err := lis.Accept()
		done <- accepted{conn: conn, err: err}
	}()

	client, err = net.DialTimeout("tcp", lis.Addr().String(), 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	got := <-done
	require.NoError(t, got.err)
	t.Cleanup(func() { _ = got.conn.Close() })
	return client, got.conn
}

// A ForwardClose is a half-close, and the pump that receives it must keep
// receiving.
//
// Ending here ends Carry, which cancels the gRPC stream — and CloseSend does
// not wait for the agent to have consumed what the other pump already sent, so
// the client's last bytes are dropped and the request is silently truncated.
func TestStreamToLocal_KeepsReceivingAfterARemoteHalfClose(t *testing.T) {
	client, server := tcpPair(t)

	released := make(chan struct{})
	stream := &scriptedForward{
		events:   []*sandboxdv1.ForwardResponse{forwardData("greeting"), forwardCloseEvent()},
		released: released,
	}

	done := make(chan error, 1)
	go func() { done <- streamToLocal(stream, server) }()

	// Reading to EOF proves both that the data arrived and that the close was
	// processed: the write half of the local socket is shut and no more can
	// come. Anything the pump does after this it has already had the chance to
	// do.
	require.NoError(t, client.SetReadDeadline(time.Now().Add(20*time.Second)))
	got, err := io.ReadAll(client)
	require.NoError(t, err)
	require.Equal(t, "greeting", string(got), "the local client must see a clean EOF, not a reset")

	select {
	case err := <-done:
		t.Fatalf("streamToLocal returned at the sandbox-side half-close (%v); doing that cancels the stream and drops whatever the client sent after it", err)
	case <-time.After(250 * time.Millisecond):
	}

	// The agent's handler returns, which is the point at which there is
	// genuinely nothing left in flight.
	close(released)
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(20 * time.Second):
		t.Fatal("streamToLocal did not return once the stream ended")
	}
}

// And the end of the stream is what ends the pump, cleanly.
func TestStreamToLocal_EndsOnStreamEOF(t *testing.T) {
	client, server := tcpPair(t)

	stream := &scriptedForward{events: []*sandboxdv1.ForwardResponse{forwardData("body")}}

	done := make(chan error, 1)
	go func() { done <- streamToLocal(stream, server) }()

	require.NoError(t, client.SetReadDeadline(time.Now().Add(20*time.Second)))
	got, err := io.ReadAll(client)
	require.NoError(t, err)
	assert.Equal(t, "body", string(got))

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(20 * time.Second):
		t.Fatal("streamToLocal did not return at the end of the stream")
	}
}

// ------------------------------------------------------ failure classification

// A caller that has to answer in a protocol of its own needs to know which kind
// of failure it is reporting. A SOCKS client shown "connection refused" for a
// destination its operator never permitted goes looking at the destination.
func TestOpenError_ClassifiesWhatTheAgentSaid(t *testing.T) {
	for _, tc := range []struct {
		name    string
		message string
		want    FailureKind
	}{
		{"a name the agent could not resolve", `remote_host "db.internal" could not be resolved on the sandbox: no such host`, FailureUnreachable},
		{"a name with no addresses", `remote_host "db.internal" resolved to no addresses on the sandbox`, FailureUnreachable},
		{"a network with no route", "could not connect to db.internal:5432 on the sandbox: network is unreachable", FailureUnreachable},
		{"a port nothing is serving", "could not connect to 10.0.4.7:5432 on the sandbox: connection refused", FailureRefused},
		{"a target that timed out", "could not connect to 10.0.4.7:5432 on the sandbox: i/o timeout", FailureRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, classifyDialFailure(tc.message))
		})
	}
}

// A refusal by configuration is not a fact about the network, and reporting it
// as one sends an operator to look in the wrong place.
func TestOpenFailure_ReportsAPolicyRefusalAsDenied(t *testing.T) {
	denied := openFailure(
		status.Error(codes.PermissionDenied, "this agent does not serve SOCKS proxying (forward.socks_enabled is false)"),
		"connecting to db.internal:5432")

	var openErr *OpenError
	require.ErrorAs(t, denied, &openErr)
	assert.True(t, openErr.Denied(), "a PermissionDenied from the agent is a policy refusal")
	assert.Contains(t, openErr.Error(), "forward.socks_enabled",
		"the agent's own sentence is what names the setting, so it has to survive")

	unreachable := openFailure(status.Error(codes.Unavailable, "connection refused"), "connecting to db.internal:5432")
	require.ErrorAs(t, unreachable, &openErr)
	assert.Equal(t, FailureTransport, openErr.Kind, "an agent that did not answer is not the target refusing")
}

// A name that went nowhere is the same event whichever of the agent's two paths
// reported it.
//
// Which path a name takes is decided by the agent's allow list, which is not
// something a client can see: a listed name is dialed by name and its failure
// arrives in ForwardOpened.error, and an unlisted one is resolved first and its
// failure arrives as an InvalidArgument status. Classified differently, the
// same `curl` gets "host unreachable" on one agent and "general server failure"
// on the next, for the same typo.
func TestOpenFailure_ReportsANameThatWentNowhereAsUnreachable(t *testing.T) {
	var openErr *OpenError

	unresolvable := openFailure(
		status.Error(codes.InvalidArgument, `remote_host "db.internal" could not be resolved on the sandbox: lookup db.internal: no such host`),
		"connecting to db.internal:5432")
	require.ErrorAs(t, unresolvable, &openErr)
	assert.Equal(t, FailureUnreachable, openErr.Kind,
		"a name the agent could not resolve is unreachable however the agent reported it")

	// And the other things InvalidArgument covers are not reachability at all,
	// so they keep the code that says nothing about the network. Reporting a
	// rejected port as "host unreachable" would be the same mistake pointed the
	// other way.
	rejected := openFailure(
		status.Error(codes.InvalidArgument, "remote_port 0 is out of range; expected 1-65535"),
		"connecting to db.internal:0")
	require.ErrorAs(t, rejected, &openErr)
	assert.Equal(t, FailureUnknown, openErr.Kind)
}

// Target.Label names the loopback default rather than leaving a blank host in
// an error message.
func TestTargetLabel(t *testing.T) {
	assert.Equal(t, "localhost:3000", Target{Port: 3000}.Label())
	assert.Equal(t, "db.internal:5432", Target{Host: "db.internal", Port: 5432}.Label())
}

// ------------------------------------------------------- the onOpen seam

// openedStream answers the open and then ends, standing in for a stream that
// came up and had nothing more to say.
//
// It counts the data messages it was sent, which is what the assertion below
// turns on: what must not happen is bytes moving after the caller's own
// handshake failed.
type openedStream struct {
	grpc.ClientStream
	opened bool

	mu   sync.Mutex
	data int
}

func (s *openedStream) Send(req *sandboxdv1.ForwardRequest) error {
	if len(req.GetData()) > 0 {
		s.mu.Lock()
		s.data++
		s.mu.Unlock()
	}
	return nil
}

func (s *openedStream) CloseSend() error { return nil }

func (s *openedStream) Recv() (*sandboxdv1.ForwardResponse, error) {
	if !s.opened {
		s.opened = true
		return &sandboxdv1.ForwardResponse{
			Event: &sandboxdv1.ForwardResponse_Opened{Opened: &sandboxdv1.ForwardOpened{Success: true}},
		}, nil
	}
	return nil, io.EOF
}

func (s *openedStream) dataMessages() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data
}

type openingClient struct{ stream *openedStream }

func (c *openingClient) Forward(context.Context, ...grpc.CallOption) (grpc.BidiStreamingClient[sandboxdv1.ForwardRequest, sandboxdv1.ForwardResponse], error) {
	return c.stream, nil
}

// A handshake reply that could not be written ends the connection, carrying
// nothing.
//
// onOpen is where a protocol with a handshake of its own answers its client:
// for the SOCKS proxy it writes the ten bytes that say the destination is
// connected, and [Carry] documents an error from it as ending the connection
// without carrying anything. It has to — a client that never received those ten
// bytes is still waiting for them, so a response body pumped at it arrives
// where a handshake reply should be, on exactly the transfers a proxy exists to
// carry.
//
// Deterministic rather than statistical, which is what made this contract look
// untestable and left it unpinned: the failure it guards is a socket write that
// fails, which is hard to force on a live connection and trivial to state to
// the seam itself. Ignoring onOpen's error left every test in this repository
// green.
func TestCarry_CarriesNothingWhenTheHandshakeReplyFailed(t *testing.T) {
	client, server := tcpPair(t)

	// Queued before Carry runs, so a build that started the pumps anyway has
	// something to forward and is caught here rather than by a timeout.
	_, err := client.Write([]byte("a request the far side must never see"))
	require.NoError(t, err)

	stream := &openedStream{}
	unanswerable := errors.New("answering the SOCKS request: broken pipe")

	err = Carry(t.Context(), &openingClient{stream: stream}, server,
		Target{Host: "db.internal", Port: 5432}, func() error { return unanswerable })

	require.ErrorIs(t, err, unanswerable,
		"the caller's own handshake failure is what ended this connection, and is what it has to be told")
	assert.Zero(t, stream.dataMessages(),
		"nothing may be carried once the client's handshake could not be answered")
}
