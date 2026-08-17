package tunnel

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// Target.Label names the loopback default rather than leaving a blank host in
// an error message.
func TestTargetLabel(t *testing.T) {
	assert.Equal(t, "localhost:3000", Target{Port: 3000}.Label())
	assert.Equal(t, "db.internal:5432", Target{Host: "db.internal", Port: 5432}.Label())
}
