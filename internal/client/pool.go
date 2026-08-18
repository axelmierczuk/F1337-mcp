package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
)

// entry is one pooled channel and its background health state.
type entry struct {
	target Target
	conn   *grpc.ClientConn

	healthMu sync.RWMutex
	health   HealthStatus

	cancel context.CancelFunc
}

// name is the pool key this entry was dialled under.
func (e *entry) name() string { return e.target.Name }

// Pool dials fleet-agent instances over gRPC — mutually authenticated unless
// the target says otherwise, see [Target.Insecure] — keeping one long-lived
// channel per sandbox name and a periodically refreshed health cache
// alongside it.
//
// gRPC channels connect lazily and reconnect with their own built-in
// exponential backoff and jitter, so Pool does not reimplement either: a
// sandbox that is powered off fails the first RPC issued against it once
// the caller's context expires, and never blocks a concurrent call routed
// to a different sandbox.
type Pool struct {
	cfg     Config
	tlsConf *tls.Config

	dialCount atomic.Int64

	mu      sync.Mutex
	entries map[string]*entry
	closed  bool
	wg      sync.WaitGroup
}

// NewPool validates cfg and returns a ready-to-use Pool. No connections are
// made until Conn (or a typed accessor) is first called for a sandbox.
//
// A pool with no mTLS material is a valid pool: it dials every sandbox the
// registry marks insecure and refuses the rest, naming what is missing. See
// [Config.CredentialErr].
func NewPool(cfg Config) (*Pool, error) {
	cfg = cfg.withDefaults()
	tlsConf, err := cfg.buildTLSConfig()
	if err != nil {
		return nil, err
	}
	return &Pool{
		cfg:     cfg,
		tlsConf: tlsConf,
		entries: map[string]*entry{},
	}, nil
}

// Conn returns the pooled channel for the target's sandbox, dialing lazily on
// first use. A second call with the same name, address and posture reuses the
// existing channel without dialing again; a call with either changed
// (re-enrollment, a new IP, an operator who turned mTLS off) replaces it.
func (p *Pool) Conn(t Target) (*grpc.ClientConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, fmt.Errorf("client: pool is closed")
	}

	// Checked before the cache, not after: a pool with no credentials would
	// otherwise report "pooled" for a target it can never dial, and the answer
	// to "why can this not reach my sandbox" would be a TLS error rather than
	// the missing file.
	if !t.Insecure && p.tlsConf == nil {
		return nil, p.noCredentialsErr(t)
	}

	if e, ok := p.entries[t.Name]; ok {
		if e.target == t {
			return e.conn, nil
		}
		p.removeLocked(t.Name)
	}

	e, err := p.dial(t)
	if err != nil {
		return nil, err
	}
	p.entries[t.Name] = e
	return e.conn, nil
}

// CredentialErr reports why this pool holds no mTLS material, or nil when it
// holds some.
//
// It exists so a caller can say once, above a listing, what it would otherwise
// have to repeat on every row that could not be dialled — and say it in the
// loader's own words, which name the file and the command that creates it.
func (p *Pool) CredentialErr() error {
	if p.tlsConf != nil {
		return nil
	}
	if p.cfg.CredentialErr != nil {
		return p.cfg.CredentialErr
	}
	return ErrNoCredentials
}

// noCredentialsErr explains a dial that needs a client certificate to a pool
// that holds none.
//
// The loader's own error is preferred when there is one, because it names the
// file and the command that creates it. The fallback is for a pool built with
// no credentials and no explanation, which is a programming error rather than
// an operator's.
func (p *Pool) noCredentialsErr(t Target) error {
	if p.cfg.CredentialErr != nil {
		return fmt.Errorf("%w: sandbox %s is reached over mTLS: %w", ErrNoCredentials, t.Name, p.cfg.CredentialErr)
	}
	return fmt.Errorf("%w: sandbox %s is reached over mTLS and this pool was built with none", ErrNoCredentials, t.Name)
}

// dial creates a new channel and starts its background health loop. Callers
// must hold p.mu.
func (p *Pool) dial(t Target) (*entry, error) {
	name, address := t.Name, t.Address

	// The server name is what the agent's leaf is verified against, so an
	// address we cannot parse a host out of is rejected here. Left to the
	// TLS stack it surfaces as "either ServerName or InsecureSkipVerify must
	// be specified in the config" on the first RPC, which names neither the
	// sandbox nor the malformed address that caused it.
	//
	// Checked for an insecure target too. There is no certificate to verify
	// against a name there, but a registry entry that is not host:port is a
	// broken entry either way, and one error for it beats two.
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("client: sandbox %s has address %q, which is not host:port: %w", name, address, err)
	}
	if host == "" {
		return nil, fmt.Errorf("client: sandbox %s has address %q, which names no host", name, address)
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(p.creds(t, host)),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(p.cfg.MaxRecvMsgSize),
			grpc.MaxCallSendMsgSize(p.cfg.MaxSendMsgSize),
		),
	}
	opts = append(opts, p.cfg.DialOptions...)

	p.dialCount.Add(1)
	// "passthrough:///" hands the address to the dialer literally instead
	// of through gRPC's default DNS resolver. There is exactly one address
	// per sandbox and Conn already redials on change, so gRPC's periodic
	// re-resolution buys nothing here — and it is what lets tests route an
	// address through an in-memory bufconn dialer.
	cc, err := grpc.NewClient("passthrough:///"+address, opts...)
	if err != nil {
		return nil, fmt.Errorf("client: dial %s (%s): %w", name, address, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	e := &entry{
		target: t,
		conn:   cc,
		cancel: cancel,
		health: HealthStatus{CheckedAt: time.Now()},
	}

	p.wg.Add(1)
	go p.healthLoop(ctx, e)

	return e, nil
}

// creds picks the transport credentials for one target, and says so out loud
// when they authenticate nobody.
//
// The announcement is here rather than at the call sites because this is the
// one place that knows a plaintext channel was opened, and #85 turns on it
// being said: an agent reached without mTLS is one whose caller this fleet
// never identified, and the whole failure mode of that posture is holding it
// without noticing. Once per dial, not per RPC — a channel is long-lived, and a
// line per call would be noise nobody reads.
func (p *Pool) creds(t Target, host string) credentials.TransportCredentials {
	if !t.Insecure {
		tlsConf := p.tlsConf.Clone()
		tlsConf.ServerName = host
		return credentials.NewTLS(tlsConf)
	}
	if p.cfg.Log != nil {
		p.cfg.Log.Warn("CONNECTING TO A SANDBOX THIS FLEET DOES NOT AUTHENTICATE",
			"sandbox", t.Name,
			"address", t.Address,
			"reason", "this sandbox is registered as insecure, so no client certificate is presented and the agent's certificate is not verified",
			"consequence", "whatever authenticates and encrypts this connection is the network; nothing here does")
	}
	return insecure.NewCredentials()
}

// removeLocked evicts and tears down an entry. Callers must hold p.mu.
func (p *Pool) removeLocked(name string) {
	e, ok := p.entries[name]
	if !ok {
		return
	}
	delete(p.entries, name)
	e.cancel()
	_ = e.conn.Close()
}

// Remove evicts a sandbox's pooled channel, if one exists, closing it and
// stopping its health loop.
func (p *Pool) Remove(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.removeLocked(name)
}

// DialCount returns how many times Pool has dialed a new channel. It exists
// for tests to assert that a second call for an already-pooled sandbox
// reuses the channel rather than dialing again.
func (p *Pool) DialCount() int64 {
	return p.dialCount.Load()
}

// HealthInterval is how often each pooled channel's background loop re-probes
// its sandbox, after Config's defaults have been applied.
//
// Like DialCount it exists for callers to assert with rather than to act on.
// A one-shot command sets this to longer than the process lives and a watching
// one sets it to what the operator asked for, and those are opposite
// requirements built from the same struct — so which one a command got is
// worth being able to check.
func (p *Pool) HealthInterval() time.Duration {
	return p.cfg.HealthInterval
}

// Close closes every pooled channel and stops every health loop, waiting
// for them to exit before returning.
func (p *Pool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	entries := make([]*entry, 0, len(p.entries))
	for _, e := range p.entries {
		entries = append(entries, e)
	}
	p.entries = map[string]*entry{}
	p.mu.Unlock()

	var firstErr error
	for _, e := range entries {
		e.cancel()
		if err := e.conn.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("client: close channel for %s: %w", e.name(), err)
		}
	}
	p.wg.Wait()
	return firstErr
}

// Host returns a HostServiceClient bound to the named sandbox's pooled
// channel.
func (p *Pool) Host(t Target) (sandboxdv1.HostServiceClient, error) {
	cc, err := p.Conn(t)
	if err != nil {
		return nil, err
	}
	return sandboxdv1.NewHostServiceClient(cc), nil
}

// Exec returns an ExecServiceClient bound to the named sandbox's pooled
// channel.
func (p *Pool) Exec(t Target) (sandboxdv1.ExecServiceClient, error) {
	cc, err := p.Conn(t)
	if err != nil {
		return nil, err
	}
	return sandboxdv1.NewExecServiceClient(cc), nil
}

// Files returns a FileServiceClient bound to the named sandbox's pooled
// channel.
func (p *Pool) Files(t Target) (sandboxdv1.FileServiceClient, error) {
	cc, err := p.Conn(t)
	if err != nil {
		return nil, err
	}
	return sandboxdv1.NewFileServiceClient(cc), nil
}

// Process returns a ProcessServiceClient bound to the named sandbox's
// pooled channel.
func (p *Pool) Process(t Target) (sandboxdv1.ProcessServiceClient, error) {
	cc, err := p.Conn(t)
	if err != nil {
		return nil, err
	}
	return sandboxdv1.NewProcessServiceClient(cc), nil
}

// Shell returns a ShellServiceClient bound to the named sandbox's pooled
// channel.
//
// It has no MCP caller and is not expected to grow one: a model does not need
// an interactive terminal, and streaming raw terminal bytes into a context
// window is a bad trade in every direction. This is here for `fleetctl shell`.
func (p *Pool) Shell(t Target) (sandboxdv1.ShellServiceClient, error) {
	cc, err := p.Conn(t)
	if err != nil {
		return nil, err
	}
	return sandboxdv1.NewShellServiceClient(cc), nil
}

// Forward returns a ForwardServiceClient bound to the named sandbox's
// pooled channel.
func (p *Pool) Forward(t Target) (sandboxdv1.ForwardServiceClient, error) {
	cc, err := p.Conn(t)
	if err != nil {
		return nil, err
	}
	return sandboxdv1.NewForwardServiceClient(cc), nil
}
