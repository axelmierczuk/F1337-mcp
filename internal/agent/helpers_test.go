package agent_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	"github.com/axelmierczuk/fleet-mcp/internal/client"
	"github.com/axelmierczuk/fleet-mcp/internal/security/ca"
)

// testFleet is a real fleet CA plus the leaves an agent and a control plane
// would hold. Every TLS test here runs against genuinely signed certificates
// rather than a stub, because the property under test is exactly what the
// handshake does with them.
type testFleet struct {
	t  *testing.T
	ca *ca.CA
}

func newTestFleet(t *testing.T) *testFleet {
	t.Helper()
	authority, err := ca.Init(filepath.Join(t.TempDir(), "ca"), false)
	require.NoError(t, err)
	return &testFleet{t: t, ca: authority}
}

// agentConfig writes the agent's certificate, key, and CA bundle to a temp
// directory and returns a config pointing at them, with exec left at its
// default — which means the jail is off however many roots are passed.
func (f *testFleet) agentConfig(t *testing.T, roots ...string) *agent.Config {
	t.Helper()
	return f.config(t, true, roots...)
}

// jailedConfig is agentConfig with exec disabled, which is the one
// configuration where allowed_roots is enforced.
func (f *testFleet) jailedConfig(t *testing.T, roots ...string) *agent.Config {
	t.Helper()
	return f.config(t, false, roots...)
}

func (f *testFleet) config(t *testing.T, execEnabled bool, roots ...string) *agent.Config {
	t.Helper()
	dir := t.TempDir()
	certPEM, keyPEM := f.sign(ca.ProfileAgent, "test-agent", []string{"test-agent", "localhost"})

	certPath := filepath.Join(dir, "agent.crt")
	keyPath := filepath.Join(dir, "agent.key")
	caPath := filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))
	require.NoError(t, os.WriteFile(caPath, f.ca.CertPEM(), 0o600))

	cfg := &agent.Config{
		Name:   "test-agent",
		Listen: "127.0.0.1:0",
		TLS: agent.TLSConfig{
			Certificate:     certPath,
			PrivateKey:      keyPath,
			CABundle:        caPath,
			RequireClientOU: agent.DefaultClientOU,
		},
		AllowedRoots: roots,
		StateDir:     filepath.Join(dir, "state"),
		Exec:         agent.ExecConfig{Enabled: &execEnabled},
	}
	require.NoError(t, cfg.Validate(agent.ValidateOptions{AllowNoJail: len(roots) == 0}))
	return cfg
}

// controlLeaf issues the leaf sandboxd-mcp presents. The common name is
// fixed: it is the principal every test that checks authentication asserts on.
func (f *testFleet) controlLeaf() (certPEM, keyPEM []byte) {
	f.t.Helper()
	return f.sign(ca.ProfileControl, "sandboxd-mcp", nil)
}

func (f *testFleet) agentLeaf(cn string) (certPEM, keyPEM []byte) {
	f.t.Helper()
	return f.sign(ca.ProfileAgent, cn, []string{cn})
}

func (f *testFleet) sign(profile ca.Profile, cn string, dnsNames []string) (certPEM, keyPEM []byte) {
	f.t.Helper()
	return signLeafWith(f.t, f.ca, profile, cn, dnsNames)
}

func signLeafWith(t *testing.T, authority *ca.CA, profile ca.Profile, cn string, dnsNames []string) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: dnsNames,
	}, priv)
	require.NoError(t, err)
	_, certPEM, err = authority.SignCSR(csrDER, ca.SignOptions{Profile: profile, Subject: cn, DNSNames: dnsNames})
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// countingService is a Service that records every request that reached it.
//
// The count is the assertion that matters for the rejection tests. "The RPC
// returned an error" is satisfied by a typo in the address; "the handler never
// ran" is only satisfied by the connection actually being refused.
type countingService struct {
	sandboxdv1.UnimplementedHostServiceServer

	served    atomic.Int64
	principal atomic.Pointer[string]

	// block, when set, holds Health until the channel is closed, so a test can
	// have an RPC in flight across a shutdown.
	block   chan struct{}
	entered chan struct{}
	once    sync.Once
}

func newCountingService() *countingService {
	return &countingService{entered: make(chan struct{})}
}

func (s *countingService) Register(r grpc.ServiceRegistrar) {
	sandboxdv1.RegisterHostServiceServer(r, s)
}

func (s *countingService) Health(ctx context.Context, _ *sandboxdv1.HealthRequest) (*sandboxdv1.HealthResponse, error) {
	s.served.Add(1)
	if name, ok := agent.PrincipalFromContext(ctx); ok {
		s.principal.Store(&name)
	}
	if s.block != nil {
		s.once.Do(func() { close(s.entered) })
		<-s.block
	}
	return &sandboxdv1.HealthResponse{Status: sandboxdv1.HealthResponse_STATUS_SERVING}, nil
}

func (s *countingService) servedCount() int64 { return s.served.Load() }

func (s *countingService) seenPrincipal() string {
	if p := s.principal.Load(); p != nil {
		return *p
	}
	return ""
}

// discardLogger is the logger every test uses: the daemon's output is not what
// is under test, and a failing case is diagnosed from assertions rather than
// from log noise.
func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// syncBuffer is a log sink a test can read while the daemon is still writing
// to it. slog does not serialise a handler's writer against anything but
// itself, and the daemon logs from its own goroutines, so a bare bytes.Buffer
// here is a race the detector finds rather than a convenience.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// capturedLogger returns a logger writing to a buffer a test can read at any
// time, for the assertions about what the daemon announces at startup.
func capturedLogger() (*slog.Logger, *syncBuffer) {
	buf := &syncBuffer{}
	return slog.New(slog.NewTextHandler(buf, nil)), buf
}

// newBufconn returns an in-memory listener for a server that is built but
// never served.
func newBufconn(t *testing.T) *bufconn.Listener {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	t.Cleanup(func() { _ = lis.Close() })
	return lis
}

// syscallZero is signal 0: delivered to nothing, but an error iff the process
// is gone. It is spelled out here so the process-survival test reads as a
// liveness probe rather than as sending a signal to a supervised child.
const syscallZero = syscall.Signal(0)

// registration wraps an already-built service so a test can hand the server a
// specific instance rather than a factory.
func registration(name string, svc agent.Service) agent.Registration {
	return agent.Registration{Name: name, Factory: func(agent.Deps) (agent.Service, error) { return svc, nil }}
}

// harness is a running agent server on an in-memory listener, plus the dial
// option that reaches it.
type harness struct {
	server  *agent.Server
	dialOpt grpc.DialOption
	cancel  context.CancelFunc
	done    chan error
	status  *agent.Status

	// stopOnce makes waiting idempotent, so a test that collects Serve's
	// result and the cleanup that collects it again do not both try to read
	// the single value off done.
	stopOnce sync.Once
	stopErr  error
}

// start builds and runs a server over bufconn. bufconn is what lets the real
// TLS stack and the real gRPC server run without binding a port, which is what
// makes the handshake assertions genuine rather than mocked.
func start(t *testing.T, cfg *agent.Config, regs []agent.Registration, opts ...func(*agent.Options)) *harness {
	t.Helper()

	lis := bufconn.Listen(1024 * 1024)
	options := agent.Options{
		Config:   cfg,
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version:  "0.0.0-test",
		Services: regs,
		Listener: lis,
	}
	for _, opt := range opts {
		opt(&options)
	}

	srv, err := agent.New(options)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()

	h := &harness{
		server: srv,
		dialOpt: grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		cancel: cancel,
		done:   done,
		status: srv.Deps().Status,
	}
	t.Cleanup(func() { h.stop(t) })
	return h
}

// stop cancels the server and waits for it to finish draining.
func (h *harness) stop(t *testing.T) error {
	t.Helper()
	h.cancel()
	return h.wait(t)
}

// wait collects Serve's result. It memoizes, because Serve reports its result
// exactly once and both a test and the cleanup registered by start may ask
// for it.
func (h *harness) wait(t *testing.T) error {
	t.Helper()
	h.stopOnce.Do(func() {
		select {
		case h.stopErr = <-h.done:
		case <-time.After(30 * time.Second):
			t.Error("server did not shut down within 30s")
		}
	})
	return h.stopErr
}

// hostClient dials the harness with the given client identity.
func (h *harness) hostClient(t *testing.T, caPEM, certPEM, keyPEM []byte) sandboxdv1.HostServiceClient {
	t.Helper()
	pool, err := client.NewPool(client.Config{
		CACertPEM:   caPEM,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		DialOptions: []grpc.DialOption{h.dialOpt},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pool.Close() })

	hostClient, err := pool.Host("test-agent", "test-agent:8722")
	require.NoError(t, err)
	return hostClient
}

// rawTLSClient dials the harness with an arbitrary tls.Config, for the cases
// internal/client cannot express — no client certificate at all, most of all.
func (h *harness) rawConn(t *testing.T, creds credentials.TransportCredentials) *grpc.ClientConn {
	t.Helper()
	cc, err := grpc.NewClient("passthrough:///test-agent:8722",
		grpc.WithTransportCredentials(creds),
		h.dialOpt,
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}
