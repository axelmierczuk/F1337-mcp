package tools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/mcpserver/selection"
)

// sandbox_forward is `ssh -L`, and saying so is worth more than a paragraph
// explaining it.
//
//	sandbox_forward(remote_port=3000, local_port=3000)
//
// is
//
//	ssh -L 3000:localhost:3000 sandbox
//
// Every model and every user already holds that mental model, so the tool
// description names it. It also names what is *not* implemented, because the
// same mental model comes with `-R` and `-D` attached: there is no reverse
// forward and no dynamic SOCKS proxy here, and a caller who assumes otherwise
// builds on a capability that does not exist. Both are deliberately out of
// scope for #26.
const forwardDescription = "Forward a port on the selected sandbox to this workstation, so a server running there is reachable over localhost. This is the `ssh -L` equivalent: sandbox_forward(remote_port=3000, local_port=3000) is `ssh -L 3000:localhost:3000 sandbox`. " +
	"The forward is owned by this MCP server, not by this call: it stays open across unrelated tool calls until you pass stop=true or the MCP server exits. Every call lists the forwards that are currently open. " +
	"The local listener binds loopback only, and remote_host defaults to the sandbox's loopback. Reverse forwarding (`ssh -R`) and dynamic SOCKS proxying (`ssh -D`) are not implemented."

// Bounds on the forward group.
const (
	// maxForwards caps how many local listeners one MCP server holds. It is a
	// bound on file descriptors and on the size of the listing every forward
	// call returns, not a policy.
	maxForwards = 32
	// forwardPreflightTimeout bounds the one-shot connection that checks the
	// sandbox-side port answers before a listener is opened.
	forwardPreflightTimeout = 10 * time.Second
	// forwardCopyBuffer is the local-to-sandbox pump buffer.
	forwardCopyBuffer = 32 * 1024
)

// registerForward adds sandbox_forward and gives the Registrar the manager
// that owns the listeners.
func registerForward(r *Registrar) {
	r.forwards = newForwardManager(r.deps.logger())
	AddTargeted(r, &mcp.Tool{
		Name:        "sandbox_forward",
		Title:       "Forward a sandbox port",
		Description: forwardDescription,
	}, r.sandboxForward)
}

// Close releases everything the tools own outside a single call: every open
// port forward and its local listener.
//
// The MCP server calls this on the way out. A local listener that survived the
// process would hold its port against the next server, and the user would see
// "address already in use" from a process that no longer exists.
func (r *Registrar) Close() error {
	if r.forwards == nil {
		return nil
	}
	return r.forwards.Close()
}

// ------------------------------------------------------------- manager

// forwardKey identifies a forward. A forward is "this sandbox's port", so two
// calls naming the same sandbox and remote port are the same forward — which
// is what makes a repeated call idempotent rather than a second listener on a
// second local port.
type forwardKey struct {
	sandbox    string
	remoteHost string
	remotePort int
}

func (k forwardKey) remoteLabel() string {
	host := k.remoteHost
	if host == "" {
		host = "localhost"
	}
	return net.JoinHostPort(host, strconv.Itoa(k.remotePort))
}

// forwardManager owns every open forward for the life of the MCP server.
type forwardManager struct {
	log *slog.Logger

	mu       sync.Mutex
	closed   bool
	forwards map[forwardKey]*activeForward
}

func newForwardManager(log *slog.Logger) *forwardManager {
	return &forwardManager{log: log, forwards: map[forwardKey]*activeForward{}}
}

// activeForward is one local listener and the connections running through it.
type activeForward struct {
	key       forwardKey
	localAddr string
	localPort int
	createdAt time.Time

	listener net.Listener
	cancel   context.CancelFunc
	// wg covers the accept loop and every per-connection goroutine, so Close
	// returns only once nothing is still running. Two pumps and a stream per
	// connection is exactly where a long-lived forward leaks goroutines, and
	// joining them here is what makes the goleak assertion pass rather than
	// merely usually pass.
	wg sync.WaitGroup

	mu       sync.Mutex
	accepted uint64
	open     int
	lastErr  string
}

func (f *activeForward) note(err string) {
	f.mu.Lock()
	f.lastErr = err
	f.mu.Unlock()
}

func (f *activeForward) stats() (accepted uint64, open int, lastErr string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.accepted, f.open, f.lastErr
}

// close tears one forward down: the listener first, so nothing new is
// accepted, then the connections in flight, then a join.
func (f *activeForward) close() {
	_ = f.listener.Close()
	f.cancel()
	f.wg.Wait()
}

// list renders every open forward, newest last. It is returned by every
// forward call so the model can see what is already open without a second
// tool and without a tool that does nothing else.
func (m *forwardManager) list() []ForwardLine {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]ForwardLine, 0, len(m.forwards))
	now := time.Now()
	for _, f := range m.forwards {
		accepted, open, lastErr := f.stats()
		out = append(out, ForwardLine{
			Sandbox:      f.key.sandbox,
			LocalAddress: f.localAddr,
			LocalPort:    f.localPort,
			RemoteHost:   f.key.remoteHost,
			RemotePort:   f.key.remotePort,
			Age:          humanDuration(now.Sub(f.createdAt)),
			Connections:  accepted,
			OpenNow:      open,
			LastError:    lastErr,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Sandbox != out[j].Sandbox {
			return out[i].Sandbox < out[j].Sandbox
		}
		return out[i].RemotePort < out[j].RemotePort
	})
	return out
}

func (m *forwardManager) get(key forwardKey) (*activeForward, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.forwards[key]
	return f, ok
}

// stop tears down the forward for key, if there is one.
func (m *forwardManager) stop(key forwardKey) (*activeForward, bool) {
	m.mu.Lock()
	f, ok := m.forwards[key]
	if ok {
		delete(m.forwards, key)
	}
	m.mu.Unlock()
	if !ok {
		return nil, false
	}
	f.close()
	return f, true
}

// add registers a started forward, refusing once the manager is closed or
// full.
func (m *forwardManager) add(f *activeForward) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("the MCP server is shutting down, so no new forward was opened")
	}
	if _, exists := m.forwards[f.key]; exists {
		return fmt.Errorf("a forward for %s on sandbox %s already exists", f.key.remoteLabel(), f.key.sandbox)
	}
	if len(m.forwards) >= maxForwards {
		return fmt.Errorf("%d forwards are already open, which is this server's maximum; stop one with sandbox_forward(stop=true)", maxForwards)
	}
	m.forwards[f.key] = f
	return nil
}

// Close releases every listener. It is idempotent.
func (m *forwardManager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	forwards := make([]*activeForward, 0, len(m.forwards))
	for key, f := range m.forwards {
		forwards = append(forwards, f)
		delete(m.forwards, key)
	}
	m.mu.Unlock()

	// Outside the lock: closing joins per-connection goroutines, and holding
	// the manager lock across that would block a concurrent list behind a
	// transfer that is still draining.
	for _, f := range forwards {
		m.log.Debug("releasing port forward", "local", f.localAddr, "remote", f.key.remoteLabel())
		f.close()
	}
	return nil
}

// ---------------------------------------------------------------- tool

// ForwardArgs are the arguments to sandbox_forward.
type ForwardArgs struct {
	TargetArgs
	// RemotePort is the port on the sandbox.
	RemotePort int `json:"remote_port" jsonschema:"port on the sandbox to forward, e.g. 3000 for a dev server"`
	// LocalPort is the port on this workstation. Zero picks a free one.
	LocalPort int `json:"local_port,omitempty" jsonschema:"port to listen on locally; 0 (the default) picks a free port and reports it"`
	// RemoteHost is the host on the sandbox's network.
	RemoteHost string `json:"remote_host,omitempty" jsonschema:"host to connect to from the sandbox; defaults to the sandbox's own loopback, and anything else must be allowed in the agent's configuration"`
	// Stop tears the forward down.
	Stop bool `json:"stop,omitempty" jsonschema:"close the existing forward for this remote_port instead of opening one"`
}

// ForwardLine is one open forward.
type ForwardLine struct {
	// Sandbox is the sandbox the forward reaches.
	Sandbox string `json:"sandbox"`
	// LocalAddress is what to connect to on this workstation.
	LocalAddress string `json:"local_address"`
	// LocalPort is the local half of it.
	LocalPort int `json:"local_port"`
	// RemoteHost is the host on the sandbox side, empty for loopback.
	RemoteHost string `json:"remote_host,omitempty"`
	// RemotePort is the sandbox-side port.
	RemotePort int `json:"remote_port"`
	// Age is how long the forward has been open.
	Age string `json:"age,omitempty"`
	// Connections is how many have been accepted since it opened.
	Connections uint64 `json:"connections,omitempty"`
	// OpenNow is how many are in flight.
	OpenNow int `json:"open_now,omitempty"`
	// LastError is the most recent per-connection failure, if any. A forward
	// whose listener is fine but whose target stopped answering looks healthy
	// from the outside; this is where that shows.
	LastError string `json:"last_error,omitempty"`
}

// ForwardResult is the sandbox_forward result.
type ForwardResult struct {
	// Echo carries the sandbox the forward reaches.
	Echo
	// LocalAddress is what to connect to on this workstation, e.g.
	// 127.0.0.1:3000.
	LocalAddress string `json:"local_address,omitempty"`
	// LocalPort is the local half.
	LocalPort int `json:"local_port,omitempty"`
	// RemotePort is the sandbox-side half.
	RemotePort int `json:"remote_port,omitempty"`
	// RemoteHost is the sandbox-side host, empty for loopback.
	RemoteHost string `json:"remote_host,omitempty"`
	// Stopped reports that this call closed a forward.
	Stopped bool `json:"stopped,omitempty"`
	// Existing reports that the forward was already open and was reused.
	Existing bool `json:"existing,omitempty"`
	// Active is every forward this MCP server currently holds, across every
	// sandbox.
	Active []ForwardLine `json:"active_forwards"`
	// Note is what the caller should not have to infer.
	Note string `json:"note,omitempty"`
}

func (r *Registrar) sandboxForward(ctx context.Context, _ *mcp.CallToolRequest, target *selection.Target, in ForwardArgs) (ForwardResult, error) {
	if in.RemotePort < 1 || in.RemotePort > 65535 {
		return ForwardResult{}, fmt.Errorf("remote_port %d is out of range; expected 1-65535", in.RemotePort)
	}
	if in.LocalPort < 0 || in.LocalPort > 65535 {
		return ForwardResult{}, fmt.Errorf("local_port %d is out of range; expected 0-65535, where 0 picks a free port", in.LocalPort)
	}

	key := forwardKey{
		sandbox:    target.Name(),
		remoteHost: strings.TrimSpace(in.RemoteHost),
		remotePort: in.RemotePort,
	}

	if in.Stop {
		return r.stopForward(key)
	}
	return r.startForward(ctx, target, key, in.LocalPort)
}

func (r *Registrar) stopForward(key forwardKey) (ForwardResult, error) {
	f, ok := r.forwards.stop(key)
	if !ok {
		active := r.forwards.list()
		if len(active) == 0 {
			return ForwardResult{}, fmt.Errorf("no forward is open for %s on sandbox %s, and none are open at all",
				key.remoteLabel(), key.sandbox)
		}
		return ForwardResult{}, fmt.Errorf("no forward is open for %s on sandbox %s. Open forwards: %s",
			key.remoteLabel(), key.sandbox, describeForwards(active))
	}
	return ForwardResult{
		LocalAddress: f.localAddr,
		LocalPort:    f.localPort,
		RemotePort:   key.remotePort,
		RemoteHost:   key.remoteHost,
		Stopped:      true,
		Active:       r.forwards.list(),
		Note: fmt.Sprintf("Closed %s. The local listener is released and connections that were in flight through it were dropped.",
			f.localAddr),
	}, nil
}

func (r *Registrar) startForward(ctx context.Context, target *selection.Target, key forwardKey, localPort int) (ForwardResult, error) {
	// An already-open forward is returned rather than duplicated. A model that
	// forwards the same port twice has forgotten it did, not asked for a
	// second tunnel, and answering with the address it already has is what
	// lets it carry on.
	if existing, ok := r.forwards.get(key); ok {
		if localPort != 0 && localPort != existing.localPort {
			return ForwardResult{}, fmt.Errorf("%s on sandbox %s is already forwarded to %s. Stop that forward first with sandbox_forward(remote_port=%d, stop=true) if it should move to local port %d",
				key.remoteLabel(), key.sandbox, existing.localAddr, key.remotePort, localPort)
		}
		return ForwardResult{
			LocalAddress: existing.localAddr,
			LocalPort:    existing.localPort,
			RemotePort:   key.remotePort,
			RemoteHost:   key.remoteHost,
			Existing:     true,
			Active:       r.forwards.list(),
			Note:         "This forward was already open, so the existing one was reused.",
		}, nil
	}

	if r.deps.Clients == nil {
		return ForwardResult{}, fmt.Errorf("sandbox %s cannot be reached: no gRPC client is configured", target.Name())
	}
	client, err := r.deps.Clients.Forward(target.Name(), target.Address())
	if err != nil {
		return ForwardResult{}, target.Call().Map(err)
	}

	// Preflight before a listener exists. A forward whose target is not
	// listening is worse than no forward: the model connects to localhost,
	// gets a connection that opens and then dies, and has no way to tell that
	// from a broken response. One round trip here turns that into an error
	// naming the port.
	if err := preflight(ctx, client, key, target); err != nil {
		return ForwardResult{}, err
	}

	// Loopback only, and explicitly. Binding 0.0.0.0 would publish a tunnel
	// into the sandbox on every interface of the workstation, to anyone on the
	// same network — a coffee-shop LAN included.
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)))
	if err != nil {
		if localPort != 0 {
			return ForwardResult{}, fmt.Errorf("could not listen on 127.0.0.1:%d (something else is using that port; pass local_port=0 to have one picked): %w", localPort, err)
		}
		return ForwardResult{}, fmt.Errorf("could not open a local listener: %w", err)
	}

	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		_ = listener.Close()
		return ForwardResult{}, fmt.Errorf("local listener bound a %T rather than a TCP address", listener.Addr())
	}

	// The forward's context is the manager's, never the tool call's. A forward
	// tied to the call that opened it would close the moment that call
	// returned, which is the opposite of what it is for.
	forwardCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	f := &activeForward{
		key:       key,
		localAddr: addr.String(),
		localPort: addr.Port,
		createdAt: time.Now(),
		listener:  listener,
		cancel:    cancel,
	}
	if err := r.forwards.add(f); err != nil {
		cancel()
		_ = listener.Close()
		return ForwardResult{}, err
	}

	f.wg.Add(1)
	go r.acceptLoop(forwardCtx, f, client, target)

	r.deps.logger().Debug("port forward open",
		"sandbox", key.sandbox, "local", f.localAddr, "remote", key.remoteLabel())

	return ForwardResult{
		LocalAddress: f.localAddr,
		LocalPort:    f.localPort,
		RemotePort:   key.remotePort,
		RemoteHost:   key.remoteHost,
		Active:       r.forwards.list(),
		Note: fmt.Sprintf("%s on sandbox %s is now reachable at %s on this workstation — http://%s if it serves HTTP. Equivalent to `ssh -L %d:%s:%d %s`. It stays open until you call sandbox_forward(remote_port=%d, stop=true) or this MCP server exits. The listener is bound to loopback, so it is not reachable from another machine.",
			key.remoteLabel(), key.sandbox, f.localAddr, f.localAddr,
			f.localPort, hostOrLocalhost(key.remoteHost), key.remotePort, key.sandbox,
			key.remotePort),
	}, nil
}

func hostOrLocalhost(host string) string {
	if host == "" {
		return "localhost"
	}
	return host
}

// describeForwards renders the open forwards for an error message.
func describeForwards(lines []ForwardLine) string {
	parts := make([]string, 0, len(lines))
	for _, l := range lines {
		parts = append(parts, fmt.Sprintf("%s -> %s:%d on %s", l.LocalAddress, hostOrLocalhost(l.RemoteHost), l.RemotePort, l.Sandbox))
	}
	return strings.Join(parts, "; ")
}

// preflight opens one stream, checks the sandbox-side port answers, and closes
// it.
func preflight(ctx context.Context, client sandboxdv1.ForwardServiceClient, key forwardKey, target *selection.Target) error {
	probeCtx, cancel := context.WithTimeout(ctx, forwardPreflightTimeout)
	defer cancel()

	stream, err := client.Forward(probeCtx)
	if err != nil {
		c := target.Call()
		c.Subject = "forward to " + key.remoteLabel()
		return c.Map(err)
	}
	if err := stream.Send(&sandboxdv1.ForwardRequest{
		Event: &sandboxdv1.ForwardRequest_Open{Open: &sandboxdv1.ForwardOpen{
			RemotePort: uint32(key.remotePort), //nolint:gosec // range-checked by the caller
			RemoteHost: key.remoteHost,
		}},
	}); err != nil {
		c := target.Call()
		c.Subject = "forward to " + key.remoteLabel()
		return c.Map(err)
	}
	// Nothing more will be sent on this stream. Closing the send side first
	// means the agent tears its side down as soon as it has answered, rather
	// than holding a socket open until the deadline.
	_ = stream.CloseSend()

	resp, err := stream.Recv()
	if err != nil {
		c := target.Call()
		c.Subject = "forward to " + key.remoteLabel()
		c.Timeout, c.Limit = forwardPreflightTimeout, "the forward preflight deadline"
		return c.Map(err)
	}
	opened := resp.GetOpened()
	if opened == nil {
		return fmt.Errorf("sandbox %s answered a forward request with an unexpected message; the agent may be older than this MCP server", target.Name())
	}
	if !opened.GetSuccess() {
		return fmt.Errorf("sandbox %s could not reach %s: %s", target.Name(), key.remoteLabel(), opened.GetError())
	}
	// The question is answered, so the stream ends here — by the deferred
	// cancel, not by draining it. Draining would wait for the sandbox-side
	// server to close, and a server that holds an idle connection open would
	// then cost every forward the whole preflight deadline before it opened.
	return nil
}

// ------------------------------------------------------------- plumbing

// acceptLoop serves the local listener until the forward is closed.
func (r *Registrar) acceptLoop(ctx context.Context, f *activeForward, client sandboxdv1.ForwardServiceClient, target *selection.Target) {
	defer f.wg.Done()

	for {
		conn, err := f.listener.Accept()
		if err != nil {
			// A closed listener is how a forward ends; anything else on a
			// listener this process owns is worth a line but not a panic.
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				f.note("accepting a local connection: " + err.Error())
				r.deps.logger().Warn("forward accept failed", "local", f.localAddr, "error", err)
			}
			return
		}

		f.mu.Lock()
		f.accepted++
		f.open++
		f.mu.Unlock()

		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			defer func() {
				f.mu.Lock()
				f.open--
				f.mu.Unlock()
			}()
			if err := r.carry(ctx, f, client, conn); err != nil {
				f.note(err.Error())
				r.deps.logger().Debug("forwarded connection failed",
					"sandbox", target.Name(), "local", f.localAddr, "error", err)
			}
		}()
	}
}

// carry runs one accepted connection over one gRPC stream.
func (r *Registrar) carry(ctx context.Context, f *activeForward, client sandboxdv1.ForwardServiceClient, conn net.Conn) error {
	defer func() { _ = conn.Close() }()

	// Per-connection cancellation, so a stream whose pumps have finished
	// releases its gRPC resources immediately rather than at forward teardown.
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Cancelling the context has to close the socket, not merely the stream.
	// A pump parked in conn.Read is not waiting on a context, so without this
	// sandbox_forward(stop=true) would block forever joining a goroutine that
	// is blocked on a client which has no reason to say anything — and the
	// tool call that asked for the teardown would never return.
	stopOnCancel := context.AfterFunc(streamCtx, func() { _ = conn.Close() })
	defer stopOnCancel()

	stream, err := client.Forward(streamCtx)
	if err != nil {
		return fmt.Errorf("opening a forward stream: %w", err)
	}
	if err := stream.Send(&sandboxdv1.ForwardRequest{
		Event: &sandboxdv1.ForwardRequest_Open{Open: &sandboxdv1.ForwardOpen{
			RemotePort: uint32(f.key.remotePort), //nolint:gosec // range-checked when the forward was opened
			RemoteHost: f.key.remoteHost,
		}},
	}); err != nil {
		return fmt.Errorf("opening a forward to %s: %w", f.key.remoteLabel(), err)
	}

	first, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", f.key.remoteLabel(), err)
	}
	opened := first.GetOpened()
	if opened == nil {
		return fmt.Errorf("the agent answered a forward open with an unexpected message")
	}
	if !opened.GetSuccess() {
		// Close the local connection rather than leaving it hanging: a client
		// that gets an immediate reset retries or reports, and a client left
		// waiting on a socket that will never answer does neither.
		return errors.New(opened.GetError())
	}

	var (
		wg      sync.WaitGroup
		sendErr error
		recvErr error
	)

	// Local to sandbox. The local client closing its write side ends this
	// direction and only this direction: the response still has to come back.
	wg.Add(1)
	go func() {
		defer wg.Done()
		sendErr = localToStream(conn, stream)
	}()

	// Sandbox to local. It does not stop the other direction either: a server
	// that closed its write half has not necessarily stopped reading, and a
	// client still sending must still be delivered. Tearing the forward down
	// cancels the context, which closes this socket underneath both pumps, so
	// neither waits forever on a peer with nothing left to say.
	wg.Add(1)
	go func() {
		defer wg.Done()
		recvErr = streamToLocal(stream, conn)
	}()

	wg.Wait()
	if recvErr != nil {
		return recvErr
	}
	return sendErr
}

// forwardSender is the send half of the client stream, narrowed so a test can
// drive it.
type forwardSender interface {
	Send(*sandboxdv1.ForwardRequest) error
	CloseSend() error
}

// localToStream copies local bytes onto the stream and half-closes at EOF.
func localToStream(conn net.Conn, stream forwardSender) error {
	buf := make([]byte, forwardCopyBuffer)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if sendErr := stream.Send(&sandboxdv1.ForwardRequest{
				Event: &sandboxdv1.ForwardRequest_Data{Data: buf[:n]},
			}); sendErr != nil {
				// The stream is gone; the receiving pump reports why.
				return nil //nolint:nilerr // the other direction carries the real error
			}
		}
		if err != nil {
			// EOF here is the local client half-closing, which is an ordinary
			// and meaningful event: tell the far end, then stop sending.
			_ = stream.Send(&sandboxdv1.ForwardRequest{
				Event: &sandboxdv1.ForwardRequest_Close{Close: &sandboxdv1.ForwardClose{
					Reason: "the local client closed its write side",
				}},
			})
			_ = stream.CloseSend()
			if isLocalClose(err) {
				return nil
			}
			return fmt.Errorf("reading from the local connection: %w", err)
		}
	}
}

// forwardReceiver is the receive half of the client stream.
type forwardReceiver interface {
	Recv() (*sandboxdv1.ForwardResponse, error)
}

// streamToLocal copies sandbox bytes onto the local connection.
func streamToLocal(stream forwardReceiver, conn net.Conn) error {
	for {
		resp, err := stream.Recv()
		switch {
		case errors.Is(err, io.EOF):
			return closeLocalWrite(conn)
		case err != nil:
			// Half-closing rather than closing outright: a client that is
			// still reading gets a clean EOF instead of a reset that looks like
			// a truncated response.
			_ = closeLocalWrite(conn)
			return fmt.Errorf("the forward stream ended: %w", err)
		}

		if resp.GetClose() != nil {
			// The sandbox-side server closed its write side. The local client
			// may still be sending, so shut down only the write half here.
			return closeLocalWrite(conn)
		}
		data := resp.GetData()
		if len(data) == 0 {
			continue
		}
		if _, err := conn.Write(data); err != nil {
			return nil //nolint:nilerr // the local client hung up; nothing left to report to it
		}
	}
}

func closeLocalWrite(conn net.Conn) error {
	if tcp, ok := conn.(*net.TCPConn); ok {
		if err := tcp.CloseWrite(); err != nil && !isLocalClose(err) {
			return nil //nolint:nilerr // a connection already gone is not a failure of this direction
		}
		return nil
	}
	return conn.Close()
}

// isLocalClose reports whether err is an ordinary end of a local connection.
func isLocalClose(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)
}

// compile-time check that the generated client stream satisfies the narrowed
// interfaces above, so a regeneration that changes their shape fails here
// rather than at the first forwarded byte.
var (
	_ forwardSender   = (grpc.BidiStreamingClient[sandboxdv1.ForwardRequest, sandboxdv1.ForwardResponse])(nil)
	_ forwardReceiver = (grpc.BidiStreamingClient[sandboxdv1.ForwardRequest, sandboxdv1.ForwardResponse])(nil)
)
