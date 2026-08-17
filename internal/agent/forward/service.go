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

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	"github.com/axelmierczuk/fleet-mcp/internal/security/policy"
)

// init registers ForwardService with every fleet-agent daemon that links
// this package. See internal/cli/fleetagent/services.go for the import that
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

// forwardMethod is the RPC name written into every audit record.
const forwardMethod = "sandboxd.v1.ForwardService/Forward"

// Service implements sandboxd.v1.ForwardService.
type Service struct {
	sandboxdv1.UnimplementedForwardServiceServer

	cfg   agent.ForwardConfig
	log   *slog.Logger
	audit *policy.Audit

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
	// The daemon's log, never one built here. Two Audit instances over one
	// file rotate it out from under each other, and the loser appends to a
	// segment nothing reads again — a defect this repository already found
	// once on the exec path.
	if deps.Audit == nil {
		return nil, errors.New("forward: agent.Deps.Audit is required")
	}

	cfg := deps.Config.Forward
	log := deps.Log.With("service", "forward")
	logPosture(log, cfg, deps.Audit.Enabled())
	return &Service{
		cfg:   cfg,
		log:   log,
		audit: deps.Audit,
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

// logPosture says at every start what this agent will connect to on a caller's
// behalf.
//
// Every line here is about a setting whose effect is invisible in ordinary use:
// forwarding a dev server works identically whether or not the agent is also a
// route into a private subnet, so an operator who turned something on months
// ago, or inherited a config, has nothing to notice. The log is where they can
// see it without reading the file.
func logPosture(log *slog.Logger, cfg agent.ForwardConfig, audited bool) {
	if bad := cfg.MalformedAllowedHosts(); len(bad) > 0 {
		// Neither an address nor a block, so it is being treated as a hostname
		// that nothing will ever match. The list reads as permitting something
		// and permits nothing, which is a safe failure and a confusing one.
		log.Warn("forward.allowed_hosts has entries that are not a valid address or CIDR block",
			"entries", strings.Join(bad, ","),
			"consequence", "each is matched as a hostname, so it permits nothing unless a caller asks for that exact name")
	}

	switch {
	case cfg.SocksAllowsAnyHost():
		// The loudest thing this agent has to say about itself. An unrestricted
		// proxy reaches every host its network reaches, for anyone who can call
		// it, and unlike every other capability here that is not bounded by
		// what is installed on this machine.
		log.Warn("THIS AGENT WILL PROXY TO ANY HOST IT CAN REACH",
			"reason", "forward.socks_enabled is true and forward.allowed_hosts is empty",
			"consequence", "any caller can reach anything this machine's network reaches, through this agent",
			"remedy", "list the hosts, addresses or CIDR blocks it should reach in forward.allowed_hosts",
			"audited", audited)
	case cfg.SocksEnabled:
		log.Info("SOCKS proxying is permitted, narrowed by the allow list",
			"allowed_hosts", strings.Join(cfg.AllowedHosts, ","),
			"audited", audited)
	}

	if len(cfg.AllowedHosts) > 0 {
		// Worth a line at every start. It is the setting that turns this agent
		// from "reaches its own loopback" into "reaches part of its network",
		// and an operator should be able to see it in the log rather than only
		// in a file.
		log.Info("forwarding to non-loopback hosts is permitted",
			"allowed_hosts", strings.Join(cfg.AllowedHosts, ","),
			"socks_enabled", cfg.SocksEnabled,
			"audited", audited)
	}

	if !audited && (len(cfg.AllowedHosts) > 0 || cfg.SocksEnabled) {
		// The two settings are only dangerous together. Reaching the network on
		// request is a decision an operator may reasonably make; making it with
		// no record of what was reached is one they should have to have made on
		// purpose.
		log.Warn("THIS AGENT WILL CONNECT OFF THIS MACHINE WITH NO AUDIT LOG",
			"reason", "forward.allowed_hosts or forward.socks_enabled is set, and audit.enabled is false",
			"consequence", "this agent will connect to other hosts on a caller's behalf and record nothing about it")
	}
}

// Forward carries one TCP connection.
//
// The shape is fixed by the protocol: an open, then bytes, then a close, in
// each direction independently. The first message must be the open, because
// there is nowhere to send bytes until it has arrived.
func (s *Service) Forward(stream grpc.BidiStreamingServer[sandboxdv1.ForwardRequest, sandboxdv1.ForwardResponse]) error {
	ctx := stream.Context()
	principal, _ := agent.PrincipalFromContext(ctx)
	call := &call{
		started:   time.Now(),
		principal: principal,
	}

	first, err := stream.Recv()
	if err != nil {
		// Nothing was asked for, so there is nothing to record: a stream that
		// closed before naming a target reached nothing.
		if errors.Is(err, io.EOF) {
			return status.Error(codes.InvalidArgument, "the stream closed before sending a ForwardOpen")
		}
		return err
	}
	open := first.GetOpen()
	if open == nil {
		return status.Error(codes.InvalidArgument, "the first message on a Forward stream must be a ForwardOpen")
	}
	call.requested, call.port = strings.TrimSpace(open.GetRemoteHost()), open.GetRemotePort()
	call.socks = open.GetSocks()
	// Until the host is resolved, the only thing known about the target is how
	// it was spelled. That is enough to decide whether a refusal below is a
	// refusal to reach off this machine, which is the class of event the
	// record exists for.
	call.offBox = !looksLoopback(call.requested)

	if !s.cfg.IsEnabled() {
		return s.deny(call, "forward.enabled: false", status.Error(codes.FailedPrecondition,
			"port forwarding is disabled on this agent (forward.enabled is false in its configuration)"))
	}
	// Before the target is examined, because this refusal is about the
	// capability rather than about where this particular connection was going:
	// an agent that does not proxy refuses a proxied connection to its own
	// loopback too, and the answer a caller needs is the setting, not the
	// destination. Recorded as a denial with the target it named, which is what
	// makes "somebody pointed a proxy at this agent" a line an operator can
	// find.
	if call.socks && !s.cfg.SocksEnabled {
		return s.deny(call, ruleSocksEnabled, status.Error(codes.PermissionDenied,
			"this agent does not serve SOCKS proxying (forward.socks_enabled is false in its configuration). "+
				"A proxy would let any caller reach every host this machine's network reaches, so it is off unless "+
				"an operator turns it on — and an operator turning it on should also list the hosts, addresses or "+
				"CIDR blocks it may reach in forward.allowed_hosts"))
	}
	if call.port == 0 || call.port > 65535 {
		return s.errored(call, status.Errorf(codes.InvalidArgument,
			"remote_port %d is out of range; expected 1-65535", call.port))
	}

	// Resolve and authorise before anything is dialed, and dial the addresses
	// that passed rather than the name that was asked for.
	addresses, err := s.resolveTarget(ctx, call)
	if err != nil {
		if call.rule != "" {
			return s.deny(call, call.rule, err)
		}
		return s.errored(call, err)
	}

	if n := s.active.Add(1); s.cfg.MaxConnections > 0 && n > int64(s.cfg.MaxConnections) {
		s.active.Add(-1)
		call.rule = "forward.max_connections"
		return s.errored(call, status.Errorf(codes.ResourceExhausted,
			"this agent is already carrying %d forwarded connections, its configured maximum (forward.max_connections)", s.cfg.MaxConnections))
	}
	defer s.active.Add(-1)

	conn, dialed, err := s.connect(ctx, addresses)
	call.resolved = dialed
	if err != nil {
		// Not an RPC error. The stream worked; the sandbox-side port did not
		// answer, and the caller needs to be told which of the two failed.
		// Reporting it as an RPC failure would have the MCP server phrase it as
		// "the sandbox is unreachable", which is the opposite of true.
		s.log.Debug("forward dial failed", "addresses", strings.Join(addresses, ","), "error", err)
		call.err = dialMessage(err)
		sendErr := stream.Send(&sandboxdv1.ForwardResponse{
			Event: &sandboxdv1.ForwardResponse_Opened{Opened: &sandboxdv1.ForwardOpened{
				Success: false,
				Error: fmt.Sprintf("could not connect to %s on the sandbox: %s. Check something is listening there — fleet_process_list reports the ports each supervised process holds",
					net.JoinHostPort(call.reportedHost(), strconv.FormatUint(uint64(call.port), 10)), dialMessage(err)),
			}},
		})
		return s.record(call, policy.OutcomeError, sendErr)
	}
	defer func() { _ = conn.Close() }()

	call.local = conn.LocalAddr().String()

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
			LocalAddress: call.local,
		}},
	}); err != nil {
		call.err = err.Error()
		return s.record(call, policy.OutcomeError, err)
	}

	s.log.Debug("forwarding", "address", conn.RemoteAddr().String(), "local", call.local)

	pumpErr := s.pump(stream, conn, call)

	// A clean close is "ok" whatever the context says by the time this runs.
	// The caller cancels the stream the moment its own two pumps finish, which
	// is often before this handler has written its record — so reading
	// ctx.Err() first would report a completed connection as cancelled, and
	// every ordinary forward in the log would look aborted. The context is
	// consulted only to explain a pump that actually failed.
	outcome := policy.OutcomeOK
	switch {
	case pumpErr == nil:
	case ctx.Err() != nil:
		outcome = policy.OutcomeCancelled
	default:
		outcome = policy.OutcomeError
		call.err = status.Convert(pumpErr).Message()
	}
	return s.record(call, outcome, pumpErr)
}

// call is one connection's worth of audit material, filled in as the handler
// learns it.
//
// It exists so the record can be written from any of the six places this RPC
// can end, without each of them assembling a Record by hand and one of them
// forgetting a field.
type call struct {
	started   time.Time
	principal string

	// requested is the host as the caller spelled it, empty for the loopback
	// default. resolved is the address actually dialed, empty when nothing was.
	requested string
	port      uint32
	resolved  string
	local     string

	// socks reports that the caller declared this connection as one a SOCKS
	// proxy asked for. See the field's contract in forward.proto: it selects
	// which policy applies and can only ever make it stricter.
	socks bool
	// offBox reports that the target is not this machine's own loopback, which
	// is the whole test for whether this connection is recorded. See
	// [Service.record].
	offBox bool
	// rule names the configuration that refused the connection, when one did.
	rule string
	// err is the failure, as the agent phrased it. Never anything the
	// connection carried.
	err string

	toRemote   atomic.Int64
	fromRemote atomic.Int64
}

// reportedHost is the host to name back to the caller: what it asked for, or
// "localhost" when it asked for the default.
func (c *call) reportedHost() string {
	if c.requested == "" {
		return "localhost"
	}
	return c.requested
}

// deny records a refusal by configuration and returns the caller's error.
func (s *Service) deny(c *call, rule string, err error) error {
	c.rule = rule
	c.err = status.Convert(err).Message()
	return s.record(c, policy.OutcomeDenied, err)
}

// errored records a request that failed before any bytes moved.
func (s *Service) errored(c *call, err error) error {
	c.err = status.Convert(err).Message()
	return s.record(c, policy.OutcomeError, err)
}

// record writes the connection's audit record and returns the error this RPC
// ends with.
//
// Only a connection whose target is off this machine is recorded. A forward to
// the sandbox's own loopback reaches a port on a host the caller already has
// full command execution on, so recording it would add volume without adding
// an answer — and volume is not free: it is what makes the interesting lines
// hard to find. A forward to anywhere else is the agent acting as a pivot into
// the network it sits in, and that is the event this log exists for.
//
// audit.required is honoured on the same terms as the exec path: with it set, a
// record that could not be written fails the call. Here that means a connection
// which has already happened ends in an error rather than a clean close, which
// is the honest report — the agent could not record what it did.
func (s *Service) record(c *call, outcome policy.Outcome, rpcErr error) error {
	if !c.offBox || !s.audit.Enabled() {
		return rpcErr
	}

	writeErr := s.audit.Write(policy.Record{
		Time:      c.started.UTC(),
		Principal: c.principal,
		RPC:       forwardMethod,
		Outcome:   outcome,
		Rule:      c.rule,
		Error:     c.err,

		RemoteHost:      c.requested,
		RemotePort:      c.port,
		ResolvedAddress: c.resolved,
		LocalAddress:    c.local,
		BytesToRemote:   c.toRemote.Load(),
		BytesFromRemote: c.fromRemote.Load(),
		DurationMS:      time.Since(c.started).Milliseconds(),
	})
	if writeErr == nil {
		return rpcErr
	}

	s.log.Error("audit record was not written",
		"path", s.audit.Path(),
		"required", s.audit.Required(),
		"rpc", forwardMethod,
		"outcome", outcome,
		"principal", c.principal,
		"remote_host", c.requested,
		"remote_port", c.port,
		"error", writeErr)

	if !s.audit.Required() {
		return rpcErr
	}
	if rpcErr != nil {
		return status.Errorf(codes.Internal,
			"audit.required is set and this connection's record could not be written (%v); the call had already failed: %s",
			writeErr, status.Convert(rpcErr).Message())
	}
	return status.Errorf(codes.Internal,
		"audit.required is set and this connection's record could not be written, so the forward is reported as failed: %v", writeErr)
}

// looksLoopback reports whether a requested host is loopback on its face,
// without asking a resolver.
//
// It is used only to decide whether a refusal that happens *before* resolution
// is worth recording. It is deliberately not a security check — nothing is
// permitted on the strength of it — so treating the name "localhost" as
// loopback here cannot be turned into a way past the policy in
// [Service.resolveTarget], which resolves before it decides.
func looksLoopback(host string) bool {
	if host == "" {
		return true
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// pump runs both directions and joins them.
//
// Both goroutines are started and both are waited for. Returning while one is
// still running would leak it — and would leak it per connection, on a
// long-lived forward, which is precisely the accumulation this has to avoid.
func (s *Service) pump(stream grpc.BidiStreamingServer[sandboxdv1.ForwardRequest, sandboxdv1.ForwardResponse], conn net.Conn, c *call) error {
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
		toSandboxErr = streamToSocket(stream, conn, c)
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
		fromSandboxErr = socketToStream(stream, conn, c)
	}()

	wg.Wait()

	if fromSandboxErr != nil {
		return fromSandboxErr
	}
	return toSandboxErr
}

// streamToSocket copies request messages onto the socket, counting them.
//
// It counts how much went through, never what it was. See policy.Record.
func streamToSocket(stream grpc.BidiStreamingServer[sandboxdv1.ForwardRequest, sandboxdv1.ForwardResponse], conn net.Conn, c *call) error {
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
		n, err := conn.Write(data)
		c.toRemote.Add(int64(n))
		if err != nil {
			return nil //nolint:nilerr // the socket is gone; the other pump reports why, and this one has nothing to add
		}
	}
}

// socketToStream copies socket bytes back onto the stream, counting them.
func socketToStream(stream grpc.BidiStreamingServer[sandboxdv1.ForwardRequest, sandboxdv1.ForwardResponse], conn net.Conn, c *call) error {
	buf := make([]byte, copyBufferSize)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			c.fromRemote.Add(int64(n))
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
			// A failure is told to the caller too, and for a stronger reason
			// than a clean close is. The other pump is parked in stream.Recv
			// waiting for a caller that has no reason to speak — an idle
			// keep-alive connection through the forward is exactly that — and
			// this handler joins both before it returns. Saying nothing here
			// leaves the connection, its socket, its two goroutines and its
			// slot against forward.max_connections held until the caller
			// happens to send something, on a connection that can no longer
			// carry anything. A server that crashes mid-request resets its
			// socket, so this is the ordinary way a forwarded connection dies.
			//
			// The event is the same shape as a clean close because the
			// protocol has no third one, and the difference is carried in the
			// reason. The RPC still ends in an error, so the audit record
			// still says the connection failed.
			_ = stream.Send(&sandboxdv1.ForwardResponse{
				Event: &sandboxdv1.ForwardResponse_Close{Close: &sandboxdv1.ForwardClose{
					Reason: "the sandbox-side connection failed: " + err.Error(),
				}},
			})
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
// It also reports the address it dialed, successfully or not, for the audit
// record: an operator asking where a connection went needs the address rather
// than the list it was chosen from.
func (s *Service) connect(ctx context.Context, addresses []string) (net.Conn, string, error) {
	timeout := s.cfg.DialTimeout.Duration()
	if timeout <= 0 {
		timeout = defaultDialTimeout
	}

	// The first failure is the one reported. The addresses are ordered IPv4
	// first by resolveTarget, so on a host with no IPv6 the message the caller
	// gets is "connection refused" — an answer about whether anything is
	// listening — rather than "network unreachable", which is a fact about the
	// stack and not the question that was asked.
	var (
		firstErr     error
		firstAddress string
	)
	for _, address := range addresses {
		dialCtx, cancel := context.WithTimeout(ctx, timeout)
		conn, err := s.dial(dialCtx, "tcp", address)
		cancel()
		if err == nil {
			return conn, peerAddress(conn, address), nil
		}
		if firstErr == nil {
			firstErr, firstAddress = err, dialedAddress(err, address)
		}
		if ctx.Err() != nil {
			break
		}
	}
	if firstErr == nil {
		firstErr = errors.New("no address to connect to")
	}
	return nil, firstAddress, firstErr
}

// peerAddress is where the connection actually went, which is not always where
// it was pointed.
//
// An allow-listed host is dialed by *name* — see [Service.resolveTarget] — and
// that name is the only thing about the target the caller already told us. The
// record's resolved_address exists to answer the other question: a name that
// resolved somewhere unexpected is the case worth seeing, and a field that
// echoed the name back could never show it. The socket knows, so ask the
// socket.
func peerAddress(conn net.Conn, dialed string) string {
	if addr := conn.RemoteAddr(); addr != nil {
		return addr.String()
	}
	return dialed
}

// dialedAddress is the same answer for a dial that failed. The dialer resolved
// the name itself and put the address it tried in the net.OpError it returns,
// which is the only place that survives the failure — and "a permitted target
// that did not answer" is a line an operator reads for where it went, not for
// what it was called.
func dialedAddress(err error, attempted string) string {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Addr != nil {
		return opErr.Addr.String()
	}
	return attempted
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
// It refines c.offBox from the syntactic guess made before resolution to the
// answer resolution gives, and names the rule in c.rule on a refusal, so the
// caller can record the right kind of event without repeating the decision.
func (s *Service) resolveTarget(ctx context.Context, c *call) (addresses []string, err error) {
	host := c.requested
	portStr := strconv.FormatUint(uint64(c.port), 10)

	if host == "" {
		// The documented default, and the only one that needs no policy: this
		// reaches nothing but the sandbox's own machine. Both families,
		// because a server bound to one of them is not reachable on the other.
		c.offBox = false
		return []string{
			net.JoinHostPort("127.0.0.1", portStr),
			net.JoinHostPort("::1", portStr),
		}, nil
	}

	// A proxy on an agent that has narrowed nothing reaches whatever this
	// machine can. There is no check to make: the operator's choice was "any
	// host", it is warned about at every start, and every connection made under
	// it is recorded. Dialed by name for the same reason an allow-listed host
	// is — and because resolving on the agent is the entire point of a proxy,
	// which is asked for names the client's own resolver has never heard of.
	if c.socks && s.cfg.SocksAllowsAnyHost() {
		c.offBox = true
		return []string{net.JoinHostPort(host, portStr)}, nil
	}

	// An explicitly allowed host is dialed by name, because that is what the
	// operator listed and the name may be the only thing that routes. There is
	// no window to close here: the operator has already accepted wherever this
	// name points.
	if s.cfg.HostAllowed(host) {
		// Recorded whatever it resolves to. The operator listed it precisely
		// because it is meant to reach something, and a listed host that turns
		// out to be loopback is a configuration worth seeing in the log too.
		c.offBox = true
		return []string{net.JoinHostPort(host, portStr)}, nil
	}

	if ip := net.ParseIP(host); ip != nil {
		// An address the operator listed, or one inside a block they listed.
		// Checked before the loopback test so that a listed address is recorded
		// as the off-box connection it is even in the odd case of an operator
		// listing a loopback block.
		if s.cfg.AddressAllowed(ip) {
			c.offBox = true
			return []string{net.JoinHostPort(ip.String(), portStr)}, nil
		}
		if !ip.IsLoopback() {
			c.rule = ruleAllowedHosts
			return nil, s.refuse(c, host)
		}
		c.offBox = false
		return []string{net.JoinHostPort(ip.String(), portStr)}, nil
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := s.resolver(lookupCtx, host)
	if err != nil {
		// Recorded as an attempt to reach off this machine, because that is
		// what it was: a name that did not resolve is a name whose target is
		// unknown, and an unknown target is not a loopback one.
		return nil, status.Errorf(codes.InvalidArgument, "remote_host %q could not be resolved on the sandbox: %v", host, err)
	}
	if len(addrs) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "remote_host %q resolved to no addresses on the sandbox", host)
	}
	// Every address, not the first one. A name resolving to both a permitted
	// and an unpermitted address must not pass on the strength of whichever
	// came back first.
	// IPv4 first. "localhost" resolves to both families on most hosts, in
	// whichever order the resolver feels like, and a server bound to
	// 127.0.0.1 is not reachable on ::1 — so an order that is not chosen here
	// is a forward that works on one machine and fails on the next.
	var (
		v4, v6 []string
		offBox bool
	)
	for _, addr := range addrs {
		switch {
		case s.cfg.AddressAllowed(addr.IP):
			// A name resolving into a listed block. Recorded as off-box even if
			// some other address it answers to is loopback: the connection may
			// go to the listed one, and that is the fact a record is for.
			offBox = true
		case addr.IP.IsLoopback():
		default:
			c.rule = ruleAllowedHosts
			return nil, s.refuse(c, host)
		}
		address := net.JoinHostPort(addr.IP.String(), portStr)
		if addr.IP.To4() != nil {
			v4 = append(v4, address)
		} else {
			v6 = append(v6, address)
		}
	}
	c.offBox = offBox
	return append(v4, v6...), nil
}

// The configuration a refusal is recorded against.
const (
	// ruleAllowedHosts is a target the allow list does not cover.
	ruleAllowedHosts = "forward.allowed_hosts"
	// ruleSocksEnabled is a proxy on an agent that does not serve one.
	ruleSocksEnabled = "forward.socks_enabled"
)

// refuse is the message a denied non-loopback target gets. It names the setting
// that would permit it, because an operator who genuinely wants this should not
// have to find the knob by reading source — and it names the setting that
// applies to the connection in front of it, which for a proxied one is not
// quite the same sentence.
func (s *Service) refuse(c *call, host string) error {
	if c.socks {
		return status.Errorf(codes.PermissionDenied,
			"this agent will not proxy to %q: it is not covered by forward.allowed_hosts in the agent configuration, which lists %s. An operator decides once which network this agent may reach, and a proxy works inside that",
			host, describeAllowed(s.cfg.AllowedHosts))
	}
	return status.Errorf(codes.PermissionDenied,
		"this agent only forwards to its own loopback interface, and %q is not on it. Forwarding elsewhere would let any caller reach this machine's whole network through the agent, so it is off unless an operator lists the host in forward.allowed_hosts in the agent configuration",
		host)
}

// describeAllowed renders the allow list for a refusal.
//
// The refusal says what *is* permitted rather than only what is not, because
// the caller of a proxy is choosing destinations one connection at a time and
// "not that one" without "these ones" costs a round trip per guess.
func describeAllowed(hosts []string) string {
	if len(hosts) == 0 {
		return "nothing"
	}
	return strings.Join(hosts, ", ")
}
