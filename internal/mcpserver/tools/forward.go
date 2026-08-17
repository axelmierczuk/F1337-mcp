package tools

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver/selection"
	"github.com/axelmierczuk/fleet-mcp/internal/tunnel"
)

// fleet_forward is `ssh -L`, and saying so is worth more than a paragraph
// explaining it.
//
//	fleet_forward(remote_port=3000, local_port=3000)
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
const forwardDescription = "Forward a port on the selected sandbox to this workstation, so a server running there is reachable over localhost. This is the `ssh -L` equivalent: fleet_forward(remote_port=3000, local_port=3000) is `ssh -L 3000:localhost:3000 sandbox`. " +
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
)

// registerForward adds fleet_forward and gives the Registrar the manager
// that owns the listeners.
func registerForward(r *Registrar) {
	r.forwards = newForwardManager(r.deps.logger())
	AddTargeted(r, &mcp.Tool{
		Name:        "fleet_forward",
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

// stopCall renders the fleet_forward call that tears this forward down.
//
// remote_host is part of the key, so it has to be part of the call: a forward
// opened with one and torn down without it looks up the loopback forward of the
// same port, finds nothing, and fails. The instruction a result hands back has
// to be the instruction that works — a wrong one costs a turn and reads as the
// forward having closed itself.
func (k forwardKey) stopCall() string {
	if k.remoteHost == "" {
		return fmt.Sprintf("fleet_forward(remote_port=%d, stop=true)", k.remotePort)
	}
	return fmt.Sprintf("fleet_forward(remote_port=%d, remote_host=%q, stop=true)", k.remotePort, k.remoteHost)
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

// stopForSandbox tears down every forward reaching one sandbox and returns
// their local addresses.
//
// It exists for fleet_remove. A forward outlives the call that opened it, so
// deregistering the sandbox it points at would otherwise leave a local port
// that still accepts connections and drops every one of them — the pooled
// channel behind it is closed on removal — which is precisely the "accepts and
// then dies" failure the preflight exists to prevent, arrived at from the other
// end.
func (m *forwardManager) stopForSandbox(sandbox string) []string {
	m.mu.Lock()
	var stopping []*activeForward
	for key, f := range m.forwards {
		if key.sandbox == sandbox {
			stopping = append(stopping, f)
			delete(m.forwards, key)
		}
	}
	m.mu.Unlock()

	// Outside the lock: closing joins per-connection goroutines.
	addresses := make([]string, 0, len(stopping))
	for _, f := range stopping {
		f.close()
		addresses = append(addresses, f.localAddr)
	}
	sort.Strings(addresses)
	return addresses
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
		return fmt.Errorf("%d forwards are already open, which is this server's maximum; stop one with fleet_forward(stop=true)", maxForwards)
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

// ForwardArgs are the arguments to fleet_forward.
type ForwardArgs struct {
	TargetArgs
	// RemotePort is the port on the sandbox.
	RemotePort int `json:"remote_port" jsonschema:"port on the sandbox to forward, e.g. 3000 for a dev server"`
	// LocalPort is the port on this workstation. Zero picks a free one.
	LocalPort int `json:"local_port,omitempty" jsonschema:"port to listen on locally; 0 (the default) picks a free port and reports it"`
	// RemoteHost is the host on the sandbox's network.
	RemoteHost string `json:"remote_host,omitempty" jsonschema:"host to connect to from the sandbox; defaults to the sandbox's own loopback, and anything else must be allowed in the agent's configuration"`
	// Stop tears the forward down.
	Stop bool `json:"stop,omitempty" jsonschema:"close the existing forward for this remote_port instead of opening one; pass the same remote_host it was opened with, because a forward is identified by both"`
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

// ForwardResult is the fleet_forward result.
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
			return ForwardResult{}, fmt.Errorf("%s on sandbox %s is already forwarded to %s. Stop that forward first with %s if it should move to local port %d",
				key.remoteLabel(), key.sandbox, existing.localAddr, key.stopCall(), localPort)
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
		Note: fmt.Sprintf("%s on sandbox %s is now reachable at %s on this workstation — http://%s if it serves HTTP. Equivalent to `ssh -L %d:%s:%d %s`. It stays open until you call %s or this MCP server exits. The listener is bound to loopback, so it is not reachable from another machine.",
			key.remoteLabel(), key.sandbox, f.localAddr, f.localAddr,
			f.localPort, hostOrLocalhost(key.remoteHost), key.remotePort, key.sandbox,
			key.stopCall()),
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

	backoff := time.Duration(0)
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			// A closed listener, or a torn-down forward, is how this ends.
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			// Anything else is transient until proven otherwise, and giving up
			// on it would leave a forward that is still listed as open, still
			// holding its port, and permanently deaf. A workstation that hits
			// its descriptor limit for a second — which is what EMFILE is, and
			// the kernel hands it straight back here — must not silently cost
			// the model the tunnel it is working through. Backed off so a
			// listener that is genuinely broken costs one syscall a second
			// rather than a spin.
			backoff = nextAcceptBackoff(backoff)
			f.note("accepting a local connection: " + err.Error())
			r.deps.logger().Warn("forward accept failed, retrying",
				"local", f.localAddr, "retry_in", backoff, "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
				continue
			}
		}
		backoff = 0

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

// Bounds on how fast a failing listener is retried.
const (
	minAcceptBackoff = 5 * time.Millisecond
	maxAcceptBackoff = time.Second
)

// nextAcceptBackoff doubles a retry delay up to the cap.
func nextAcceptBackoff(current time.Duration) time.Duration {
	switch {
	case current <= 0:
		return minAcceptBackoff
	case current >= maxAcceptBackoff:
		return maxAcceptBackoff
	default:
		return min(current*2, maxAcceptBackoff)
	}
}

// carry runs one accepted connection over one gRPC stream.
//
// The pump itself is [tunnel.Carry], shared with the SOCKS proxy. This is the
// forward's half: which target, and nothing else. See the package comment on
// internal/tunnel for why there is only one copy of the rest.
func (r *Registrar) carry(ctx context.Context, f *activeForward, client sandboxdv1.ForwardServiceClient, conn net.Conn) error {
	// The accepted socket is this function's to release: tunnel.Carry leaves it
	// open so that a caller with a protocol of its own can answer on it, and a
	// forward has nothing to say.
	defer func() { _ = conn.Close() }()
	return tunnel.Carry(ctx, client, conn, tunnel.Target{
		Host: f.key.remoteHost,
		Port: f.key.remotePort,
	}, nil)
}
