package forward

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	"github.com/axelmierczuk/sandboxd-mcp/internal/security/policy"
)

// These drive ForwardService directly over a gRPC connection, which is the
// only way to exercise the half-close in each direction: the whole contract is
// about what happens to one side of a bidirectional stream when the other side
// ends, and a hand-rolled stream would be asserting on the fake.

// newService builds the service with a real audit log in a temp directory, so
// every test can read back what was recorded — and so none of them can pass
// while recording nothing.
func newService(t *testing.T, cfg agent.ForwardConfig, tune ...func(*policy.AuditConfig)) *Service {
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

	auditCfg := policy.AuditConfig{
		Path:    filepath.Join(t.TempDir(), "audit.jsonl"),
		Sandbox: "test-box",
		Enabled: true,
	}
	for _, apply := range tune {
		apply(&auditCfg)
	}
	auditLog := policy.NewAudit(auditCfg)
	// Released before the temp directory goes: on Windows a directory holding
	// an open handle does not delete, which has broken this suite's neighbours
	// before.
	t.Cleanup(func() { _ = auditLog.Close() })

	built, err := New(agent.Deps{
		Config:  &agent.Config{Forward: cfg},
		Log:     slog.New(slog.DiscardHandler),
		Status:  agent.NewStatus(),
		Audit:   auditLog,
		Version: "test",
	})
	require.NoError(t, err)
	svc, ok := built.(*Service)
	require.True(t, ok)

	// Wait for the handlers before the log they write to is closed.
	//
	// Registered after the two cleanups above, so it runs before them: the
	// record is written on the way out of Forward, and several of these tests
	// deliberately walk away from a stream rather than draining it. A handler
	// still unwinding when Audit.Close lands reopens the file — Close
	// documents that further writes do — and recreates it inside a temp
	// directory RemoveAll is already walking, which surfaces as "directory not
	// empty" in whichever test the scheduler picked, not in the one that left
	// the stream open. active drops only after record returns, so an idle
	// service is one whose records are all on disk.
	t.Cleanup(func() {
		deadline := time.Now().Add(30 * time.Second)
		for svc.active.Load() > 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		assert.Zero(t, svc.active.Load(), "a forwarded connection outlived the test that opened it")
	})
	return svc
}

// records returns everything the service has written to its audit log.
func records(t *testing.T, svc *Service) []policy.Record {
	t.Helper()
	data, err := os.ReadFile(svc.audit.Path())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	require.NoError(t, err)

	var out []policy.Record
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec policy.Record
		require.NoErrorf(t, json.Unmarshal([]byte(line), &rec), "audit line is not JSON: %s", line)
		out = append(out, rec)
	}
	return out
}

// onlyRecord requires exactly one audit record and returns it. One connection
// is one record, and a test that accepted "at least one" would not notice a
// duplicate on every path out of the handler.
func onlyRecord(t *testing.T, svc *Service) policy.Record {
	t.Helper()
	got := records(t, svc)
	require.Lenf(t, got, 1, "expected exactly one audit record, got %d: %+v", len(got), got)
	return got[0]
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

// A sandbox-side socket that fails, rather than closing cleanly, has to be
// reported to the caller too.
//
// The two directions of this stream are joined before the handler returns, and
// the request direction is parked in stream.Recv waiting for a caller with no
// reason to speak — an idle keep-alive connection through a forward is exactly
// that. Saying nothing holds the connection, its socket, both its goroutines
// and its slot against forward.max_connections until the caller happens to send
// something, on a connection that can no longer carry anything. A server that
// crashes mid-request resets its socket, which is the ordinary way a forwarded
// connection dies rather than an exotic one.
func TestForward_AFailedSandboxSideSocketIsReportedToTheCaller(t *testing.T) {
	port := echoServer(t)

	// The failure is injected rather than provoked with a reset. A server that
	// crashes mid-request is what produces one in the field, but which of
	// ECONNRESET and a clean EOF the kernel hands back is the platform's
	// choice — and an EOF takes the clean-close path, so a test that provoked
	// it would pass against the old behaviour on whichever platform decided to
	// be tidy. Injecting the error asserts the branch itself, everywhere.
	svc := newService(t, agent.ForwardConfig{MaxConnections: 4})
	svc.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		conn, err := d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			return nil, err
		}
		return &deadReadConn{Conn: conn}, nil
	}
	client := serve(t, svc)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	stream, opened, err := open(ctx, t, client, port, "")
	require.NoError(t, err)
	require.True(t, opened.GetSuccess(), opened.GetError())

	// The caller sends nothing after the open. It learns the connection is over
	// because the agent tells it, not because it asked.
	resp, err := stream.Recv()
	require.NoError(t, err, "the caller must be told the sandbox-side connection failed, not left waiting on it")
	require.NotNil(t, resp.GetClose(), "the failure must arrive as a close event: %v", resp.GetEvent())
	assert.Contains(t, resp.GetClose().GetReason(), "failed")

	// And a caller that acts on it — the MCP server's local end shuts its write
	// half, the local client sees EOF and hangs up, and that becomes a
	// CloseSend — releases everything the connection held.
	require.NoError(t, stream.CloseSend())
	eventually(t, func() bool { return svc.active.Load() == 0 })
}

// deadReadConn is a connection whose read side has failed the way a peer that
// reset it does: not io.EOF, not net.ErrClosed, and not recoverable.
type deadReadConn struct{ net.Conn }

func (c *deadReadConn) Read([]byte) (int, error) {
	return 0, &net.OpError{Op: "read", Net: "tcp", Err: errors.New("connection reset by peer")}
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

// ----------------------------------------------------------- the record

// A loopback forward reaches a port on a host the caller already has full
// command execution on. Recording it would add volume without adding an
// answer, and volume is what makes the interesting lines hard to find.
func TestAudit_LoopbackForwardsAreNotRecorded(t *testing.T) {
	svc := newService(t, agent.ForwardConfig{})
	client := serve(t, svc)
	port := echoServer(t)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	for _, host := range []string{"", "127.0.0.1", "localhost"} {
		roundTripTo(ctx, t, client, port, host)
	}
	assert.Empty(t, records(t, svc),
		"a forward to the sandbox's own loopback is a convenience, not a pivot")
}

// The one this exists for: the agent connected to something else on the
// network, on a caller's behalf, and the record is what makes that answerable
// afterwards.
func TestAudit_PermittedNonLoopbackForwardIsRecorded(t *testing.T) {
	port := echoServer(t)
	svc := newService(t, agent.ForwardConfig{AllowedHosts: []string{"build-host.internal"}})
	// The allow list matches on the name, so the dial goes to the name. It is
	// pointed back at loopback here so the connection actually completes, the
	// byte counts are real, and the name and the address genuinely differ —
	// which is the whole point of recording both.
	svc.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	}
	client := serve(t, svc)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	const payload = "forwarded through the agent"
	stream, opened, err := open(ctx, t, client, 8080, "build-host.internal")
	require.NoError(t, err)
	require.True(t, opened.GetSuccess(), opened.GetError())
	require.NoError(t, stream.Send(&sandboxdv1.ForwardRequest{
		Event: &sandboxdv1.ForwardRequest_Data{Data: []byte(payload)},
	}))
	require.NoError(t, stream.Send(&sandboxdv1.ForwardRequest{
		Event: &sandboxdv1.ForwardRequest_Close{Close: &sandboxdv1.ForwardClose{Reason: "done"}},
	}))
	require.NoError(t, stream.CloseSend())
	var echoed []byte
	for {
		resp, err := stream.Recv()
		if err != nil {
			break
		}
		echoed = append(echoed, resp.GetData()...)
	}
	require.Equal(t, payload, string(echoed))

	rec := onlyRecord(t, svc)
	assert.Equal(t, forwardMethod, rec.RPC)
	assert.Equal(t, policy.OutcomeOK, rec.Outcome)
	assert.Equal(t, "test-box", rec.Sandbox, "a record shipped off-box must name the host it came from")
	assert.False(t, rec.Time.IsZero())

	// What was asked for, and what it became. Both, because they are different
	// facts and an investigation needs each — and "what it became" has to come
	// from the socket, not from the request. An allow-listed host is dialed by
	// name, so a resolved_address filled in from the target would restate
	// remote_host and never show a name that resolved somewhere unexpected,
	// which is the one case the field exists for.
	assert.Equal(t, "build-host.internal", rec.RemoteHost)
	assert.Equal(t, uint32(8080), rec.RemotePort)
	assert.Equal(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), rec.ResolvedAddress,
		"resolved_address must be where the packets went, not the name they were addressed to")
	assert.NotEqual(t, "build-host.internal:8080", rec.ResolvedAddress,
		"a resolved address that is the requested host and port again answers nothing")
	assert.NotEmpty(t, rec.LocalAddress, "the local socket is what joins this to the host's own network logs")

	// Volume, in both directions, and nothing else about it.
	assert.Equal(t, int64(len(payload)), rec.BytesToRemote)
	assert.Equal(t, int64(len(payload)), rec.BytesFromRemote)
	assert.GreaterOrEqual(t, rec.DurationMS, int64(0))
}

// A refusal is the event most worth having a record of: it is the one that
// says someone asked this agent to reach somewhere it was not configured to
// go.
func TestAudit_RefusedNonLoopbackForwardIsRecorded(t *testing.T) {
	svc := newService(t, agent.ForwardConfig{})
	client := serve(t, svc)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	_, _, err := open(ctx, t, client, 8080, "192.0.2.1")
	require.Error(t, err)
	require.Equal(t, codes.PermissionDenied, status.Code(err))

	rec := onlyRecord(t, svc)
	assert.Equal(t, policy.OutcomeDenied, rec.Outcome)
	assert.Equal(t, ruleAllowedHosts, rec.Rule, "the record must name the configuration that refused it")
	assert.Equal(t, "192.0.2.1", rec.RemoteHost)
	assert.Equal(t, uint32(8080), rec.RemotePort)
	assert.Empty(t, rec.ResolvedAddress, "nothing was dialed, and an empty address is how a reader knows")
	assert.Empty(t, rec.LocalAddress)
	assert.Zero(t, rec.BytesToRemote)
	assert.Zero(t, rec.BytesFromRemote)
	assert.Contains(t, rec.Error, "loopback")
}

// A name that resolves outward is refused after resolution, and recorded with
// the name the caller used — which is the string an operator will search for.
func TestAudit_RefusedNameIsRecordedAsRequested(t *testing.T) {
	svc := newService(t, agent.ForwardConfig{})
	svc.resolver = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.1.2.3")}}, nil
	}
	client := serve(t, svc)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	_, _, err := open(ctx, t, client, 5432, "db.internal")
	require.Error(t, err)

	rec := onlyRecord(t, svc)
	assert.Equal(t, policy.OutcomeDenied, rec.Outcome)
	assert.Equal(t, "db.internal", rec.RemoteHost,
		"the requested name is what appears in the caller's configuration and what an operator will look for")
	assert.Equal(t, uint32(5432), rec.RemotePort)
}

// A disabled service still records the attempt, for the same reason a refusal
// does: the question "did anyone try" has an answer either way.
func TestAudit_RefusalByDisabledServiceIsRecorded(t *testing.T) {
	off := false
	svc := newService(t, agent.ForwardConfig{Enabled: &off})
	client := serve(t, svc)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	_, _, err := open(ctx, t, client, 8080, "192.0.2.1")
	require.Error(t, err)

	rec := onlyRecord(t, svc)
	assert.Equal(t, policy.OutcomeDenied, rec.Outcome)
	assert.Equal(t, "forward.enabled: false", rec.Rule)

	// And a loopback attempt on the same disabled agent is still not a pivot.
	_, _, err = open(ctx, t, client, 8080, "")
	require.Error(t, err)
	assert.Len(t, records(t, svc), 1)
}

// The third rule that can refuse a connection. It is recorded as an error
// rather than a denial, the same way exec records its own concurrency cap —
// "denied" is the policy refusing a target, and this is the agent running out
// of room — but it names the setting either way, because an operator reading a
// refusal needs to know which knob produced it.
func TestAudit_RefusalByTheConnectionCapIsRecorded(t *testing.T) {
	port := echoServer(t)
	svc := newService(t, agent.ForwardConfig{
		AllowedHosts:   []string{"build-host.internal"},
		MaxConnections: 1,
	})
	svc.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	}
	client := serve(t, svc)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	// One connection holds the only slot.
	first, opened, err := open(ctx, t, client, 8080, "build-host.internal")
	require.NoError(t, err)
	require.True(t, opened.GetSuccess(), opened.GetError())

	_, _, err = open(ctx, t, client, 8080, "build-host.internal")
	require.Error(t, err)
	require.Equal(t, codes.ResourceExhausted, status.Code(err))

	rec := waitForRecord(t, svc)
	assert.Equal(t, "forward.max_connections", rec.Rule,
		"a refusal must name the configuration that decided it")
	assert.Equal(t, policy.OutcomeError, rec.Outcome)
	assert.Equal(t, "build-host.internal", rec.RemoteHost)
	assert.Empty(t, rec.ResolvedAddress, "nothing was dialed for the refused connection")
	assert.Zero(t, rec.BytesToRemote)

	// And the slot comes back, so the cap bounds what is in flight rather than
	// what has ever been carried.
	require.NoError(t, first.CloseSend())
	for {
		if _, err := first.Recv(); err != nil {
			break
		}
	}
	eventually(t, func() bool { return svc.active.Load() == 0 })
	_, opened, err = open(ctx, t, client, 8080, "build-host.internal")
	require.NoError(t, err)
	assert.True(t, opened.GetSuccess(), opened.GetError())
}

// eventually polls until cond holds or a generous deadline passes.
func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition never held")
}

// A permitted target that does not answer is still a connection attempt off
// this machine, and the record says so rather than omitting the attempt.
func TestAudit_FailedDialToAPermittedHostIsRecorded(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	dead := lis.Addr().(*net.TCPAddr).Port
	require.NoError(t, lis.Close())

	svc := newService(t, agent.ForwardConfig{AllowedHosts: []string{"build-host.internal"}})
	svc.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(dead)))
	}
	client := serve(t, svc)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	stream, opened, err := open(ctx, t, client, 8080, "build-host.internal")
	require.NoError(t, err)
	require.False(t, opened.GetSuccess())
	// Drained to the end of the stream, not merely to the failed open: the
	// record is written on the way out of the handler, and the stream ending
	// is what proves the handler got there. Reading the file any earlier is a
	// race, not an assertion.
	for {
		if _, err := stream.Recv(); err != nil {
			break
		}
	}

	rec := onlyRecord(t, svc)
	assert.Equal(t, policy.OutcomeError, rec.Outcome)
	assert.Equal(t, "build-host.internal", rec.RemoteHost)
	// Where it went, for a connection that did not answer either. The dialer
	// resolved the name and put the address it tried in the error it returned;
	// that is the only place it survives, and it is what an operator reading
	// "a permitted target did not answer" needs.
	assert.Equal(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(dead)), rec.ResolvedAddress,
		"a failed dial still knows where it went")
	assert.NotEmpty(t, rec.Error)
}

// The rule the whole design turns on: the record counts what went through and
// never holds it. A tunnelled connection carries whatever the caller sends —
// a database password, a bearer token, a key on its way to a deploy — and a
// log that captured it would be a credential store nobody meant to build.
func TestAudit_NeverRecordsForwardedPayload(t *testing.T) {
	port := echoServer(t)
	svc := newService(t, agent.ForwardConfig{AllowedHosts: []string{"build-host.internal"}})
	svc.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	}
	client := serve(t, svc)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	const secret = "PGPASSWORD=hunter2-should-never-be-written-down"
	stream, opened, err := open(ctx, t, client, 5432, "build-host.internal")
	require.NoError(t, err)
	require.True(t, opened.GetSuccess())
	require.NoError(t, stream.Send(&sandboxdv1.ForwardRequest{
		Event: &sandboxdv1.ForwardRequest_Data{Data: []byte(secret)},
	}))
	require.NoError(t, stream.CloseSend())
	for {
		if _, err := stream.Recv(); err != nil {
			break
		}
	}

	// Asserted against the raw file, not the decoded record: a field added
	// later that happened to carry payload would still be caught here.
	raw, err := os.ReadFile(svc.audit.Path())
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "hunter2")
	assert.NotContains(t, string(raw), secret)

	rec := onlyRecord(t, svc)
	assert.Equal(t, int64(len(secret)), rec.BytesToRemote, "the volume is recorded, and only the volume")
}

// With audit.required set, a pivot the agent could not record is a pivot the
// agent reports as failed. Without it, the connection stands and the failure
// is logged — the same choice the exec path offers, for the same reason.
func TestAudit_RequiredFailureFailsTheConnection(t *testing.T) {
	port := echoServer(t)

	newRefusing := func(t *testing.T, required bool) *Service {
		t.Helper()
		dir := t.TempDir()
		svc := newService(t, agent.ForwardConfig{AllowedHosts: []string{"build-host.internal"}},
			func(cfg *policy.AuditConfig) {
				// A directory where the log file should be: every write fails,
				// and no test has to race a permission bit to arrange it.
				require.NoError(t, os.MkdirAll(filepath.Join(dir, "audit.jsonl"), 0o755))
				cfg.Path = filepath.Join(dir, "audit.jsonl")
				cfg.Required = required
			})
		svc.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		}
		return svc
	}

	t.Run("required", func(t *testing.T) {
		client := serve(t, newRefusing(t, true))
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()

		stream, opened, err := open(ctx, t, client, 8080, "build-host.internal")
		require.NoError(t, err)
		require.True(t, opened.GetSuccess())
		require.NoError(t, stream.CloseSend())

		var recvErr error
		for recvErr == nil {
			_, recvErr = stream.Recv()
		}
		require.NotErrorIs(t, recvErr, io.EOF,
			"a connection whose record could not be written must not end cleanly")
		assert.Contains(t, status.Convert(recvErr).Message(), "audit.required")
	})

	t.Run("not required", func(t *testing.T) {
		client := serve(t, newRefusing(t, false))
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()

		stream, opened, err := open(ctx, t, client, 8080, "build-host.internal")
		require.NoError(t, err)
		require.True(t, opened.GetSuccess())
		require.NoError(t, stream.CloseSend())

		var recvErr error
		for recvErr == nil {
			_, recvErr = stream.Recv()
		}
		assert.ErrorIs(t, recvErr, io.EOF,
			"an unwritable log must not take the fleet down with it")
	})
}

// A caller that goes away mid-transfer is recorded as cancelled, not as a
// clean close and not as an error. "How it ended" is one of the questions the
// record answers, and a connection someone abandoned halfway is a different
// answer from one that finished.
func TestAudit_CancelledConnectionIsRecordedAsCancelled(t *testing.T) {
	// A server that accepts, says nothing, and reports what it received, so the
	// caller can walk away at a point where the agent has provably already
	// forwarded and counted the request. Cancelling without waiting would make
	// the byte count a race: bytes still in flight when the caller goes are
	// bytes that may or may not have reached the socket.
	received := make(chan int, 8)
	port := tcpServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 256)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				received <- n
			}
			if err != nil {
				return
			}
		}
	})
	svc := newService(t, agent.ForwardConfig{AllowedHosts: []string{"build-host.internal"}})
	svc.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	}
	client := serve(t, svc)

	ctx, cancel := context.WithCancel(t.Context())
	stream, opened, err := open(ctx, t, client, 8080, "build-host.internal")
	require.NoError(t, err)
	require.True(t, opened.GetSuccess())
	const sent = "half a request"
	require.NoError(t, stream.Send(&sandboxdv1.ForwardRequest{
		Event: &sandboxdv1.ForwardRequest_Data{Data: []byte(sent)},
	}))
	select {
	case n := <-received:
		require.Equal(t, len(sent), n)
	case <-time.After(20 * time.Second):
		t.Fatal("the request never reached the server")
	}
	cancel()

	rec := waitForRecord(t, svc)
	assert.Equal(t, policy.OutcomeCancelled, rec.Outcome)
	assert.Equal(t, "build-host.internal", rec.RemoteHost)
	// Recorded even though the caller never came back for it: what went
	// through before the caller left is exactly what an investigation wants.
	assert.Equal(t, int64(len(sent)), rec.BytesToRemote)
}

// waitForRecord polls for exactly one record. The handler writes it on its way
// out, and a caller that cancelled has no stream left to synchronise on.
func waitForRecord(t *testing.T, svc *Service) policy.Record {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if got := records(t, svc); len(got) == 1 {
			return got[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no audit record was written within 20s; got %+v", records(t, svc))
	return policy.Record{}
}

// A disabled audit log records nothing and refuses nothing.
func TestAudit_DisabledLogStillForwards(t *testing.T) {
	port := echoServer(t)
	svc := newService(t, agent.ForwardConfig{AllowedHosts: []string{"build-host.internal"}},
		func(cfg *policy.AuditConfig) { cfg.Enabled = false })
	svc.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	}
	client := serve(t, svc)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	_, opened, err := open(ctx, t, client, 8080, "build-host.internal")
	require.NoError(t, err)
	assert.True(t, opened.GetSuccess())
	assert.Empty(t, records(t, svc))
}

// The service will not build without an audit log at all. An agent that can be
// asked to reach another host must not be constructible with nowhere to record
// that it did.
func TestAudit_ServiceRefusesToBuildWithoutALog(t *testing.T) {
	_, err := New(agent.Deps{
		Config: &agent.Config{},
		Log:    slog.New(slog.DiscardHandler),
		Status: agent.NewStatus(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Audit")
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

// roundTrip opens a stream to loopback, echoes a payload, half-closes, and
// drains.
func roundTrip(ctx context.Context, t *testing.T, client sandboxdv1.ForwardServiceClient, port int) {
	t.Helper()
	roundTripTo(ctx, t, client, port, "")
}

// roundTripTo is roundTrip against a named host.
func roundTripTo(ctx context.Context, t *testing.T, client sandboxdv1.ForwardServiceClient, port int, host string) {
	t.Helper()
	stream, opened, err := open(ctx, t, client, port, host)
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
