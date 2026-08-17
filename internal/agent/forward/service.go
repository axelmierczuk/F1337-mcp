package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/agent"
)

// init registers ForwardService with every sandboxd-agent daemon that links
// this package. See internal/cli/sandboxdagent/services.go for the import that
// does.
func init() {
	agent.Register("forward", New)
}

// copyBufferSize is the pump buffer. It is a compromise: large enough that a
// bulk transfer is not one gRPC message per 4 KiB, small enough that sixty-four
// concurrent connections do not cost megabytes of buffer on a small host.
const copyBufferSize = 32 * 1024

// defaultDialTimeout bounds the sandbox-side connection when the config names
// none. A connection to a port nothing is listening on must fail quickly and
// say so: the alternative is a local connection that hangs, which is the one
// outcome a caller cannot diagnose.
const defaultDialTimeout = 10 * time.Second

// Service implements sandboxd.v1.ForwardService.
type Service struct {
	sandboxdv1.UnimplementedForwardServiceServer

	cfg agent.ForwardConfig
	log *slog.Logger

	// resolver is swapped by tests. It is the only way to exercise a host that
	// resolves outward without depending on what the test machine's DNS says.
	resolver func(ctx context.Context, host string) ([]net.IPAddr, error)
	// dial is swapped by tests.
	dial func(ctx context.Context, network, address string) (net.Conn, error)

	// active counts the connections currently carried, for the concurrency
	// bound. A forward left open for hours is exactly where these accumulate.
	active atomic.Int64
}

// New builds the forward service. It satisfies agent.Factory.
func New(deps agent.Deps) (agent.Service, error) {
	cfg := deps.Config.Forward
	log := deps.Log.With("service", "forward")
	if len(cfg.AllowedHosts) > 0 {
		// Worth a line at every start. It is the setting that turns this agent
		// from "reaches its own loopback" into "reaches part of its network",
		// and an operator should be able to see it in the log rather than only
		// in a file.
		log.Info("forwarding to non-loopback hosts is permitted",
			"allowed_hosts", strings.Join(cfg.AllowedHosts, ","))
	}
	return &Service{
		cfg: cfg,
		log: log,
		resolver: func(ctx context.Context, host string) ([]net.IPAddr, error) {
			return net.DefaultResolver.LookupIPAddr(ctx, host)
		},
		dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, address)
		},
	}, nil
}

// Register attaches ForwardService to the daemon's gRPC server.
func (s *Service) Register(r grpc.ServiceRegistrar) {
	sandboxdv1.RegisterForwardServiceServer(r, s)
}

// Forward carries one TCP connection.
//
// The shape is fixed by the protocol: an open, then bytes, then a close, in
// each direction independently. The first message must be the open, because
// there is nowhere to send bytes until it has arrived.
func (s *Service) Forward(stream grpc.BidiStreamingServer[sandboxdv1.ForwardRequest, sandboxdv1.ForwardResponse]) error {
	if !s.cfg.IsEnabled() {
		return status.Error(codes.FailedPrecondition,
			"port forwarding is disabled on this agent (forward.enabled is false in its configuration)")
	}

	ctx := stream.Context()
	first, err := stream.Recv()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return status.Error(codes.InvalidArgument, "the stream closed before sending a ForwardOpen")
		}
		return err
	}
	open := first.GetOpen()
	if open == nil {
		return status.Error(codes.InvalidArgument, "the first message on a Forward stream must be a ForwardOpen")
	}
	port := open.GetRemotePort()
	if port == 0 || port > 65535 {
		return status.Errorf(codes.InvalidArgument, "remote_port %d is out of range; expected 1-65535", port)
	}

	// Resolve and authorise before anything is dialed, and dial the addresses
	// that passed rather than the name that was asked for.
	addresses, host, err := s.resolveTarget(ctx, open.GetRemoteHost(), port)
	if err != nil {
		return err
	}

	if n := s.active.Add(1); s.cfg.MaxConnections > 0 && n > int64(s.cfg.MaxConnections) {
		s.active.Add(-1)
		return status.Errorf(codes.ResourceExhausted,
			"this agent is already carrying %d forwarded connections, its configured maximum (forward.max_connections)", s.cfg.MaxConnections)
	}
	defer s.active.Add(-1)

	conn, err := s.connect(ctx, addresses)
	if err != nil {
		// Not an RPC error. The stream worked; the sandbox-side port did not
		// answer, and the caller needs to be told which of the two failed.
		// Reporting it as an RPC failure would have the MCP server phrase it as
		// "the sandbox is unreachable", which is the opposite of true.
		s.log.Debug("forward dial failed", "addresses", strings.Join(addresses, ","), "error", err)
		sendErr := stream.Send(&sandboxdv1.ForwardResponse{
			Event: &sandboxdv1.ForwardResponse_Opened{Opened: &sandboxdv1.ForwardOpened{
				Success: false,
				Error: fmt.Sprintf("could not connect to %s on the sandbox: %s. Check something is listening there — sandbox_process_list reports the ports each supervised process holds",
					net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)), dialMessage(err)),
			}},
		})
		return sendErr
	}
	defer func() { _ = conn.Close() }()

	// The RPC ending has to close the socket, not merely cancel the context. A
	// pump parked in conn.Read is not waiting on a context, so a caller that
	// hangs up while the sandbox-side server is idle would leave this handler
	// joining a goroutine that never returns — one leaked goroutine and one
	// leaked socket per connection, on exactly the long-lived forward where
	// they accumulate unnoticed.
	stopOnCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopOnCancel()

	if err := stream.Send(&sandboxdv1.ForwardResponse{
		Event: &sandboxdv1.ForwardResponse_Opened{Opened: &sandboxdv1.ForwardOpened{
			Success:      true,
			LocalAddress: conn.LocalAddr().String(),
		}},
	}); err != nil {
		return err
	}

	s.log.Debug("forwarding", "address", conn.RemoteAddr().String(), "local", conn.LocalAddr().String())
	return s.pump(stream, conn)
}

// pump runs both directions and joins them.
//
// Both goroutines are started and both are waited for. Returning while one is
// still running would leak it — and would leak it per connection, on a
// long-lived forward, which is precisely the accumulation this has to avoid.
func (s *Service) pump(stream grpc.BidiStreamingServer[sandboxdv1.ForwardRequest, sandboxdv1.ForwardResponse], conn net.Conn) error {
	var (
		wg             sync.WaitGroup
		toSandboxErr   error
		fromSandboxErr error
	)

	// Stream to socket. Ends when the caller half-closes (a ForwardClose, or
	// the end of the request stream), at which point only the write half of
	// the socket is shut down: the response still has to come back.
	wg.Add(1)
	go func() {
		defer wg.Done()
		toSandboxErr = streamToSocket(stream, conn)
	}()

	// Socket to stream. Ends when the sandbox-side server closes, which is
	// reported as a ForwardClose so the far end can shut down its own write
	// half and no further.
	//
	// It deliberately does not stop the other direction. The sandbox-side
	// server closing its write half does not mean it has stopped reading, and
	// a caller that is still sending must still be delivered. This direction
	// ending is not the end of the connection — the caller's own half-close
	// is, and cancelling the RPC closes the socket underneath both pumps, so
	// nothing here waits forever on a peer that has gone quiet.
	wg.Add(1)
	go func() {
		defer wg.Done()
		fromSandboxErr = socketToStream(stream, conn)
	}()

	wg.Wait()

	if fromSandboxErr != nil {
		return fromSandboxErr
	}
	return toSandboxErr
}

// streamToSocket copies request messages onto the socket.
func streamToSocket(stream grpc.BidiStreamingServer[sandboxdv1.ForwardRequest, sandboxdv1.ForwardResponse], conn net.Conn) error {
	for {
		req, err := stream.Recv()
		switch {
		case errors.Is(err, io.EOF):
			// The caller closed its request stream without a ForwardClose.
			// Same meaning, and the same handling.
			return closeWrite(conn)
		case err != nil:
			return err
		}

		if req.GetClose() != nil {
			// Half-close, not close: the caller is finished sending and is
			// still waiting to receive. Shutting the whole socket here is the
			// bug that makes `curl` with a closed write side hang.
			return closeWrite(conn)
		}
		data := req.GetData()
		if len(data) == 0 {
			continue
		}
		if _, err := conn.Write(data); err != nil {
			return nil //nolint:nilerr // the socket is gone; the other pump reports why, and this one has nothing to add
		}
	}
}

// socketToStream copies socket bytes back onto the stream.
func socketToStream(stream grpc.BidiStreamingServer[sandboxdv1.ForwardRequest, sandboxdv1.ForwardResponse], conn net.Conn) error {
	buf := make([]byte, copyBufferSize)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			// The slice is reused, and gRPC marshals on Send, so the copy the
			// wire sees is taken before the next Read overwrites it.
			if sendErr := stream.Send(&sandboxdv1.ForwardResponse{
				Event: &sandboxdv1.ForwardResponse_Data{Data: buf[:n]},
			}); sendErr != nil {
				return sendErr
			}
		}
		if err != nil {
			if isExpectedClose(err) {
				return stream.Send(&sandboxdv1.ForwardResponse{
					Event: &sandboxdv1.ForwardResponse_Close{Close: &sandboxdv1.ForwardClose{
						Reason: "the sandbox-side connection closed",
					}},
				})
			}
			return status.Errorf(codes.Unavailable, "reading from the sandbox-side connection: %v", err)
		}
	}
}

// closeWrite shuts down only the write half where the platform offers it.
func closeWrite(conn net.Conn) error {
	if tcp, ok := conn.(*net.TCPConn); ok {
		if err := tcp.CloseWrite(); err != nil && !isExpectedClose(err) {
			return nil //nolint:nilerr // a socket already gone is not this direction's failure to report
		}
		return nil
	}
	// Anything that is not a TCP connection (a test's pipe) has no half-close;
	// closing it entirely is the closest available meaning.
	_ = conn.Close()
	return nil
}

// isExpectedClose reports whether err is an ordinary end of a connection
// rather than a failure worth naming.
func isExpectedClose(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, context.Canceled)
}

// connect dials the sandbox-side port under the configured timeout, trying
// each authorised address in turn.
//
// There is more than one whenever a name resolves to both loopback families,
// which "localhost" does on most hosts. Taking only the first would refuse to
// forward an IPv4-only server on any machine whose resolver answers with ::1
// first — the standard dialer falls back for exactly this reason, and it
// cannot be used here because it would re-resolve the name and undo the check.
func (s *Service) connect(ctx context.Context, addresses []string) (net.Conn, error) {
	timeout := s.cfg.DialTimeout.Duration()
	if timeout <= 0 {
		timeout = defaultDialTimeout
	}

	// The first failure is the one reported. The addresses are ordered IPv4
	// first by resolveTarget, so on a host with no IPv6 the message the caller
	// gets is "connection refused" — an answer about whether anything is
	// listening — rather than "network unreachable", which is a fact about the
	// stack and not the question that was asked.
	var firstErr error
	for _, address := range addresses {
		dialCtx, cancel := context.WithTimeout(ctx, timeout)
		conn, err := s.dial(dialCtx, "tcp", address)
		cancel()
		if err == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = err
		}
		if ctx.Err() != nil {
			break
		}
	}
	if firstErr == nil {
		firstErr = errors.New("no address to connect to")
	}
	return nil, firstErr
}

// dialMessage strips the layers a net.OpError wraps a refusal in, so the
// caller is told "connection refused" rather than "dial tcp 127.0.0.1:9: …".
func dialMessage(err error) string {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		return opErr.Err.Error()
	}
	return err.Error()
}

// resolveTarget applies the loopback policy and returns the addresses to dial.
//
// The addresses it returns are the ones that passed the check. Returning the
// host name and letting the dialer re-resolve it would leave a window in which
// the name resolves to something else — which for a name the caller chose is
// not a theoretical window.
func (s *Service) resolveTarget(ctx context.Context, host string, port uint32) (addresses []string, reported string, err error) {
	host = strings.TrimSpace(host)
	portStr := strconv.FormatUint(uint64(port), 10)

	if host == "" {
		// The documented default, and the only one that needs no policy: this
		// reaches nothing but the sandbox's own machine. Both families,
		// because a server bound to one of them is not reachable on the other.
		return []string{
			net.JoinHostPort("127.0.0.1", portStr),
			net.JoinHostPort("::1", portStr),
		}, "localhost", nil
	}

	// An explicitly allowed host is dialed by name, because that is what the
	// operator listed and the name may be the only thing that routes. There is
	// no window to close here: the operator has already accepted wherever this
	// name points.
	if s.cfg.HostAllowed(host) {
		return []string{net.JoinHostPort(host, portStr)}, host, nil
	}

	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsLoopback() {
			return nil, "", s.refuse(host)
		}
		return []string{net.JoinHostPort(ip.String(), portStr)}, host, nil
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := s.resolver(lookupCtx, host)
	if err != nil {
		return nil, "", status.Errorf(codes.InvalidArgument, "remote_host %q could not be resolved on the sandbox: %v", host, err)
	}
	if len(addrs) == 0 {
		return nil, "", status.Errorf(codes.InvalidArgument, "remote_host %q resolved to no addresses on the sandbox", host)
	}
	// Every address, not the first one. A name resolving to both a loopback
	// and a routable address must not pass on the strength of whichever came
	// back first.
	// IPv4 first. "localhost" resolves to both families on most hosts, in
	// whichever order the resolver feels like, and a server bound to
	// 127.0.0.1 is not reachable on ::1 — so an order that is not chosen here
	// is a forward that works on one machine and fails on the next.
	var v4, v6 []string
	for _, addr := range addrs {
		if !addr.IP.IsLoopback() {
			return nil, "", s.refuse(host)
		}
		address := net.JoinHostPort(addr.IP.String(), portStr)
		if addr.IP.To4() != nil {
			v4 = append(v4, address)
		} else {
			v6 = append(v6, address)
		}
	}
	return append(v4, v6...), host, nil
}

// refuse is the one message a denied non-loopback target gets. It names the
// setting that would permit it, because an operator who genuinely wants this
// should not have to find the knob by reading source.
func (s *Service) refuse(host string) error {
	return status.Errorf(codes.PermissionDenied,
		"this agent only forwards to its own loopback interface, and %q is not on it. Forwarding elsewhere would let any caller reach this machine's whole network through the agent, so it is off unless an operator lists the host in forward.allowed_hosts in the agent configuration",
		host)
}
