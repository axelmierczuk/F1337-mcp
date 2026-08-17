package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/security/ca"
)

// fakeAgent is a minimal HostService implementation standing in for
// fleet-agent (milestone M1, not yet built) so internal/client's mTLS,
// pooling, and health behaviour can be exercised end to end.
type fakeAgent struct {
	sandboxdv1.UnimplementedHostServiceServer

	mu      sync.Mutex
	status  sandboxdv1.HealthResponse_Status
	message string
	// served counts requests that reached the service, so a test can assert
	// that a rejected connection never got past the handshake.
	served int
}

func newFakeAgent() *fakeAgent {
	return &fakeAgent{status: sandboxdv1.HealthResponse_STATUS_SERVING}
}

func (f *fakeAgent) Health(context.Context, *sandboxdv1.HealthRequest) (*sandboxdv1.HealthResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.served++
	return &sandboxdv1.HealthResponse{
		Status:       f.status,
		Message:      f.message,
		AgentVersion: "0.1.0-test",
	}, nil
}

// servedCount reports how many requests reached the service.
func (f *fakeAgent) servedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.served
}

func (f *fakeAgent) GetHostInfo(context.Context, *sandboxdv1.GetHostInfoRequest) (*sandboxdv1.GetHostInfoResponse, error) {
	return &sandboxdv1.GetHostInfoResponse{AgentVersion: "0.1.0-test"}, nil
}

// testFleet bundles a fleet CA plus a signed control leaf (for the Pool
// under test) and helpers to stand up fake agents on bufconn listeners
// signed by that same CA.
type testFleet struct {
	t  *testing.T
	ca *ca.CA
}

func newTestFleet(t *testing.T) *testFleet {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ca")
	c, err := ca.Init(dir, false)
	require.NoError(t, err)
	return &testFleet{t: t, ca: c}
}

func (f *testFleet) controlCert() (certPEM, keyPEM []byte) {
	f.t.Helper()
	return signLeaf(f.t, f.ca, ca.ProfileControl, "fleet-mcp", nil)
}

func (f *testFleet) agentCert(name string) (certPEM, keyPEM []byte) {
	f.t.Helper()
	return signLeaf(f.t, f.ca, ca.ProfileAgent, name, []string{name})
}

// serveAgent starts a fake agent over bufconn, presenting an agent leaf
// issued by caObj (which need not be f.ca, so tests can simulate an
// imposter CA) and requiring mTLS from a client cert issued by caObj. It
// returns the listener's target address (matching what tests should pass to
// Pool.Conn), a dial option that routes connections to it (and blocks,
// simulating an unreachable host, for any other target), and the underlying
// *grpc.Server for tests that need to stop it mid-test.
func serveAgent(t *testing.T, caObj *ca.CA, name string, agent sandboxdv1.HostServiceServer) (address string, dialOpt grpc.DialOption, server *grpc.Server) {
	t.Helper()
	certPEM, keyPEM := signLeaf(t, caObj, ca.ProfileAgent, name, []string{name})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(caObj.Certificate())

	lis := bufconn.Listen(4 * 1024 * 1024)
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS12,
	})
	s := grpc.NewServer(grpc.Creds(creds))
	sandboxdv1.RegisterHostServiceServer(s, agent)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)

	return name + ":8722", grpc.WithContextDialer(dialerFor(name, lis)), s
}

// dialerFor returns a context dialer that routes any target containing name
// to lis, and otherwise blocks until the context is done — simulating a
// sandbox that is powered off rather than one that actively refuses the
// connection.
func dialerFor(name string, lis *bufconn.Listener) func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, target string) (net.Conn, error) {
		if strings.Contains(target, name) {
			return lis.DialContext(ctx)
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
}

func signLeaf(t *testing.T, caObj *ca.CA, profile ca.Profile, cn string, dnsNames []string) (certPEM, keyPEM []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: dnsNames,
	}, priv)
	require.NoError(t, err)

	_, certPEM, err = caObj.SignCSR(csrDER, ca.SignOptions{Profile: profile, Subject: cn, DNSNames: dnsNames})
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}
