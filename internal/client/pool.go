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

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

// entry is one pooled channel and its background health state.
type entry struct {
	name    string
	address string
	conn    *grpc.ClientConn

	healthMu sync.RWMutex
	health   HealthStatus

	cancel context.CancelFunc
}

// Pool dials sandboxd-agent instances over mTLS gRPC, keeping one long-lived
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

// Conn returns the pooled channel for the named sandbox, dialing lazily on
// first use. A second call with the same name and address reuses the
// existing channel without dialing again; a call with a changed address
// (re-enrollment, a new IP) replaces it.
func (p *Pool) Conn(name, address string) (*grpc.ClientConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, fmt.Errorf("client: pool is closed")
	}

	if e, ok := p.entries[name]; ok {
		if e.address == address {
			return e.conn, nil
		}
		p.removeLocked(name)
	}

	e, err := p.dial(name, address)
	if err != nil {
		return nil, err
	}
	p.entries[name] = e
	return e.conn, nil
}

// dial creates a new channel and starts its background health loop. Callers
// must hold p.mu.
func (p *Pool) dial(name, address string) (*entry, error) {
	// The server name is what the agent's leaf is verified against, so an
	// address we cannot parse a host out of is rejected here. Left to the
	// TLS stack it surfaces as "either ServerName or InsecureSkipVerify must
	// be specified in the config" on the first RPC, which names neither the
	// sandbox nor the malformed address that caused it.
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("client: sandbox %s has address %q, which is not host:port: %w", name, address, err)
	}
	if host == "" {
		return nil, fmt.Errorf("client: sandbox %s has address %q, which names no host", name, address)
	}
	tlsConf := p.tlsConf.Clone()
	tlsConf.ServerName = host

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)),
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
		name:    name,
		address: address,
		conn:    cc,
		cancel:  cancel,
		health:  HealthStatus{CheckedAt: time.Now()},
	}

	p.wg.Add(1)
	go p.healthLoop(ctx, e)

	return e, nil
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
			firstErr = fmt.Errorf("client: close channel for %s: %w", e.name, err)
		}
	}
	p.wg.Wait()
	return firstErr
}

// Host returns a HostServiceClient bound to the named sandbox's pooled
// channel.
func (p *Pool) Host(name, address string) (sandboxdv1.HostServiceClient, error) {
	cc, err := p.Conn(name, address)
	if err != nil {
		return nil, err
	}
	return sandboxdv1.NewHostServiceClient(cc), nil
}

// Exec returns an ExecServiceClient bound to the named sandbox's pooled
// channel.
func (p *Pool) Exec(name, address string) (sandboxdv1.ExecServiceClient, error) {
	cc, err := p.Conn(name, address)
	if err != nil {
		return nil, err
	}
	return sandboxdv1.NewExecServiceClient(cc), nil
}

// Files returns a FileServiceClient bound to the named sandbox's pooled
// channel.
func (p *Pool) Files(name, address string) (sandboxdv1.FileServiceClient, error) {
	cc, err := p.Conn(name, address)
	if err != nil {
		return nil, err
	}
	return sandboxdv1.NewFileServiceClient(cc), nil
}

// Process returns a ProcessServiceClient bound to the named sandbox's
// pooled channel.
func (p *Pool) Process(name, address string) (sandboxdv1.ProcessServiceClient, error) {
	cc, err := p.Conn(name, address)
	if err != nil {
		return nil, err
	}
	return sandboxdv1.NewProcessServiceClient(cc), nil
}

// Forward returns a ForwardServiceClient bound to the named sandbox's
// pooled channel.
func (p *Pool) Forward(name, address string) (sandboxdv1.ForwardServiceClient, error) {
	cc, err := p.Conn(name, address)
	if err != nil {
		return nil, err
	}
	return sandboxdv1.NewForwardServiceClient(cc), nil
}
