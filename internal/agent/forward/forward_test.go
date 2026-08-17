package forward

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/agent"
)

// These drive ForwardService directly over a gRPC connection, which is the
// only way to exercise the half-close in each direction: the whole contract is
// about what happens to one side of a bidirectional stream when the other side
// ends, and a hand-rolled stream would be asserting on the fake.

func newService(t *testing.T, cfg agent.ForwardConfig) *Service {
	t.Helper()
	enabled := cfg.Enabled
	if enabled == nil {
		on := true
		enabled = &on
	}
	cfg.Enabled = enabled
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = agent.Duration(3 * time.Second)
	}

	svc, err := New(agent.Deps{
		Config:  &agent.Config{Forward: cfg},
		Log:     slog.New(slog.DiscardHandler),
		Status:  agent.NewStatus(),
		Version: "test",
	})
	require.NoError(t, err)
	return svc.(*Service)
}

// serve puts the service behind a real gRPC connection.
func serve(t *testing.T, svc *Service) sandboxdv1.ForwardServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	svc.Register(srv)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = srv.Serve(lis)
	}()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
		wg.Wait()
	})
	return sandboxdv1.NewForwardServiceClient(conn)
}

// echoServer runs a TCP echo server on loopback and returns its port.
func echoServer(t *testing.T) int {
	t.Helper()
	return tcpServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		_, _ = io.Copy(conn, conn)
	})
}

func tcpServer(t *testing.T, handle func(net.Conn)) int {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				handle(conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = lis.Close()
		wg.Wait()
	})
	return lis.Addr().(*net.TCPAddr).Port
}

// open starts a stream and consumes the ForwardOpened.
func open(ctx context.Context, t *testing.T, client sandboxdv1.ForwardServiceClient, port int, host string) (grpc.BidiStreamingClient[sandboxdv1.ForwardRequest, sandboxdv1.ForwardResponse], *sandboxdv1.ForwardOpened, error) {
	t.Helper()
	stream, err := client.Forward(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&sandboxdv1.ForwardRequest{
		Event: &sandboxdv1.ForwardRequest_Open{Open: &sandboxdv1.ForwardOpen{
			RemotePort: uint32(port), RemoteHost: host,
		}},
	}))
	resp, err := stream.Recv()
	if err != nil {
		return stream, nil, err
	}
	return stream, resp.GetOpened(), nil
}

// ------------------------------------------------------------ round trip

func TestForward_CarriesBytesInBothDirections(t *testing.T) {
	client := serve(t, newService(t, agent.ForwardConfig{}))
	port := echoServer(t)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	stream, opened, err := open(ctx, t, client, port, "")
	require.NoError(t, err)
	require.NotNil(t, opened)
	require.True(t, opened.GetSuccess(), opened.GetError())
	assert.NotEmpty(t, opened.GetLocalAddress())

	require.NoError(t, stream.Send(&sandboxdv1.ForwardRequest{
		Event: &sandboxdv1.ForwardRequest_Data{Data: []byte("ping")},
	}))
	resp, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, []byte("ping"), resp.GetData())
}

// The half-close: the request stream ending must shut down only the write half
// of the sandbox-side socket, so a server that answers at EOF still answers.
func TestForward_HalfCloseLetsTheResponseComeBack(t *testing.T) {
	client := serve(t, newService(t, agent.ForwardConfig{}))
	port := tcpServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		body, _ := io.ReadAll(conn) // returns only once the write side is closed
		_, _ = conn.Write(append([]byte("answered: "), body...))
	})

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	stream, opened, err := open(ctx, t, client, port, "")
	require.NoError(t, err)
	require.True(t, opened.GetSuccess())

	require.NoError(t, stream.Send(&sandboxdv1.ForwardRequest{
		Event: &sandboxdv1.ForwardRequest_Data{Data: []byte("a request")},
	}))
	require.NoError(t, stream.Send(&sandboxdv1.ForwardRequest{
		Event: &sandboxdv1.ForwardRequest_Close{Close: &sandboxdv1.ForwardClose{Reason: "done sending"}},
	}))
	require.NoError(t, stream.CloseSend())

	var got []byte
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		if resp.GetClose() != nil {
			continue
		}
		got = append(got, resp.GetData()...)
	}
	assert.Equal(t, "answered: a request", string(got),
		"closing the request stream must not close the response direction")
}

// The other half: a sandbox-side server that closes first is reported as a
// close event, not as a stream failure.
func TestForward_RemoteCloseArrivesAsACloseEvent(t *testing.T) {
	client := serve(t, newService(t, agent.ForwardConfig{}))
	port := tcpServer(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("bye"))
		_ = conn.Close()
	})

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	stream, opened, err := open(ctx, t, client, port, "")
	require.NoError(t, err)
	require.True(t, opened.GetSuccess())

	var (
		data     []byte
		sawClose bool
	)
	for !sawClose {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		if resp.GetClose() != nil {
			sawClose = true
			continue
		}
		data = append(data, resp.GetData()...)
	}
	assert.Equal(t, "bye", string(data))
	assert.True(t, sawClose, "the sandbox-side close must be reported, not inferred from EOF")

	// The stream is deliberately still open here: the sandbox-side server has
	// closed its write half, and a client that has not closed its own may
	// still be sending. Ending the request stream is what finishes the call —
	// which is the other half of the same half-close contract.
	require.NoError(t, stream.CloseSend())
	for {
		if _, err := stream.Recv(); err != nil {
			assert.ErrorIs(t, err, io.EOF)
			break
		}
	}
}

// -------------------------------------------------------------- failures

// A port nothing is listening on is reported on the stream, not as an RPC
// failure. Reporting it as an RPC failure would have the MCP server phrase it
// as "the sandbox is unreachable", which is the opposite of what happened.
func TestForward_ADeadPortIsReportedAsAFailedOpen(t *testing.T) {
	client := serve(t, newService(t, agent.ForwardConfig{}))

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	dead := lis.Addr().(*net.TCPAddr).Port
	require.NoError(t, lis.Close())

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	_, opened, err := open(ctx, t, client, dead, "")
	require.NoError(t, err)
	require.NotNil(t, opened)
	assert.False(t, opened.GetSuccess())
	assert.Contains(t, opened.GetError(), strconv.Itoa(dead))
	assert.Contains(t, opened.GetError(), "sandbox_process_list",
		"the message should say how to check what is listening")
}

func TestForward_TheFirstMessageMustBeAnOpen(t *testing.T) {
	client := serve(t, newService(t, agent.ForwardConfig{}))

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	stream, err := client.Forward(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&sandboxdv1.ForwardRequest{
		Event: &sandboxdv1.ForwardRequest_Data{Data: []byte("bytes before an open")},
	}))
	_, err = stream.Recv()
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestForward_RejectsAnOutOfRangePort(t *testing.T) {
	client := serve(t, newService(t, agent.ForwardConfig{}))

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	_, _, err := open(ctx, t, client, 0, "")
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestForward_DisabledServiceRefuses(t *testing.T) {
	off := false
	client := serve(t, newService(t, agent.ForwardConfig{Enabled: &off}))

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	_, _, err := open(ctx, t, client, echoServer(t), "")
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "forward.enabled")
}

func TestForward_BoundsConcurrentConnections(t *testing.T) {
	svc := newService(t, agent.ForwardConfig{MaxConnections: 1})
	client := serve(t, svc)
	port := echoServer(t)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	first, opened, err := open(ctx, t, client, port, "")
	require.NoError(t, err)
	require.True(t, opened.GetSuccess())
	defer func() { _ = first.CloseSend() }()

	_, _, err = open(ctx, t, client, port, "")
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "forward.max_connections")
}

// ------------------------------------------------------ the loopback rule

// The security property of the whole feature: without it, every agent is a
// general-purpose pivot into whatever network it sits in.
func TestForward_RefusesANonLoopbackAddress(t *testing.T) {
	client := serve(t, newService(t, agent.ForwardConfig{}))

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	// TEST-NET-1: reserved, routes nowhere, and refused before anything is
	// dialed — which is what makes this a policy rather than a timeout.
	_, _, err := open(ctx, t, client, 8080, "192.0.2.1")
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "forward.allowed_hosts")
}

// A name is not an address. Judging the string rather than what it resolves to
// is how "internal.corp" reaches a corporate network through an agent that
// believed it was only forwarding to localhost.
func TestForward_RefusesANameThatResolvesOffLoopback(t *testing.T) {
	svc := newService(t, agent.ForwardConfig{})
	svc.resolver = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.1.2.3")}}, nil
	}
	client := serve(t, svc)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	_, _, err := open(ctx, t, client, 8080, "looks-harmless.internal")
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// Every resolved address is checked, not the first one: a name answering with
// both a loopback and a routable address must not pass on the strength of
// whichever came back first.
func TestForward_RefusesANameThatResolvesToLoopbackAndElsewhere(t *testing.T) {
	svc := newService(t, agent.ForwardConfig{})
	svc.resolver = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{
			{IP: net.ParseIP("127.0.0.1")},
			{IP: net.ParseIP("203.0.113.9")},
		}, nil
	}
	client := serve(t, svc)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	_, _, err := open(ctx, t, client, 8080, "split-horizon.example")
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// And the operator's override works, by name, case-insensitively.
func TestForward_AllowsAConfiguredNonLoopbackHost(t *testing.T) {
	port := echoServer(t)
	svc := newService(t, agent.ForwardConfig{AllowedHosts: []string{"Build-Host.Internal"}})
	// The allow list is matched on the name, so the dial goes to the name —
	// which this test points back at loopback so it can assert the connection
	// is actually made rather than merely permitted.
	svc.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		assert.Equal(t, "build-host.internal", host)
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	}
	client := serve(t, svc)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	_, opened, err := open(ctx, t, client, 8080, "build-host.internal")
	require.NoError(t, err)
	require.NotNil(t, opened)
	assert.True(t, opened.GetSuccess(), opened.GetError())
}

// A loopback IP given explicitly is fine, and is not re-resolved.
func TestForward_AllowsAnExplicitLoopbackAddress(t *testing.T) {
	client := serve(t, newService(t, agent.ForwardConfig{}))
	port := echoServer(t)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	_, opened, err := open(ctx, t, client, port, "127.0.0.1")
	require.NoError(t, err)
	require.True(t, opened.GetSuccess(), opened.GetError())
}

// --------------------------------------------------------------- goleak

// One connection is two pump goroutines and a socket. The failure mode is an
// agent that slowly stops working on a host nobody is watching, so the count
// has to come back down rather than merely look plausible.
func TestForward_NoGoroutineLeakAcrossManyStreams(t *testing.T) {
	client := serve(t, newService(t, agent.ForwardConfig{}))
	port := echoServer(t)

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	// One first, so gRPC's own long-lived goroutines are in the baseline.
	roundTrip(ctx, t, client, port)
	baseline := goleak.IgnoreCurrent()

	for range 25 {
		roundTrip(ctx, t, client, port)
	}

	// And the case that actually leaks: a caller that hangs up mid-stream
	// while the sandbox-side server is idle and will never say anything.
	for range 25 {
		streamCtx, streamCancel := context.WithCancel(ctx)
		stream, opened, err := open(streamCtx, t, client, port, "")
		require.NoError(t, err)
		require.True(t, opened.GetSuccess())
		require.NoError(t, stream.Send(&sandboxdv1.ForwardRequest{
			Event: &sandboxdv1.ForwardRequest_Data{Data: []byte("x")},
		}))
		streamCancel()
	}

	goleak.VerifyNone(t, baseline)
}

// roundTrip opens a stream, echoes a payload, half-closes, and drains.
func roundTrip(ctx context.Context, t *testing.T, client sandboxdv1.ForwardServiceClient, port int) {
	t.Helper()
	stream, opened, err := open(ctx, t, client, port, "")
	require.NoError(t, err)
	require.True(t, opened.GetSuccess(), opened.GetError())

	require.NoError(t, stream.Send(&sandboxdv1.ForwardRequest{
		Event: &sandboxdv1.ForwardRequest_Data{Data: []byte("payload")},
	}))
	require.NoError(t, stream.Send(&sandboxdv1.ForwardRequest{
		Event: &sandboxdv1.ForwardRequest_Close{Close: &sandboxdv1.ForwardClose{Reason: "done"}},
	}))
	require.NoError(t, stream.CloseSend())

	var got []byte
	for {
		resp, err := stream.Recv()
		if err != nil {
			break
		}
		got = append(got, resp.GetData()...)
	}
	require.Equal(t, "payload", string(got))
}
