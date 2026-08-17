package mcpserver_test

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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/client"
	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver"
	"github.com/axelmierczuk/fleet-mcp/internal/security/ca"
)

// agentServer is a HostService served over a real gRPC listener, as opposed
// to the fake client the other tests use. It exists so the tool path is
// exercised against real mTLS, real status codes and the real client pool at
// least once — the seam #22 to #26 build on is only worth what it is worth
// over an actual connection.
type agentServer struct {
	sandboxdv1.UnimplementedHostServiceServer
}

func (agentServer) Health(context.Context, *sandboxdv1.HealthRequest) (*sandboxdv1.HealthResponse, error) {
	return &sandboxdv1.HealthResponse{
		Status: sandboxdv1.HealthResponse_STATUS_SERVING, AgentVersion: "0.1.0-bufconn", RunningProcesses: 1,
	}, nil
}

func (agentServer) GetHostInfo(context.Context, *sandboxdv1.GetHostInfoRequest) (*sandboxdv1.GetHostInfoResponse, error) {
	return &sandboxdv1.GetHostInfoResponse{
		Platform:     &sandboxdv1.Platform{Os: "linux", Arch: "arm64", PathSeparator: "/"},
		AgentVersion: "0.1.0-bufconn",
		AllowedRoots: []string{"/srv/work"},
	}, nil
}

// TestEndToEnd_OverRealMTLS runs the fleet tools against a gRPC agent behind
// the actual client pool.
func TestEndToEnd_OverRealMTLS(t *testing.T) {
	dir := t.TempDir()
	authority, err := ca.Init(filepath.Join(dir, "ca"), false)
	require.NoError(t, err)

	stop, dialOpt := serveAgentOverBufconn(t, authority, "agent-a")

	controlCert, controlKey := signLeaf(t, authority, ca.ProfileControl, "fleet-mcp", nil)
	pool, err := client.NewPool(client.Config{
		CACertPEM:   authority.CertPEM(),
		CertPEM:     controlCert,
		KeyPEM:      controlKey,
		DialOptions: []grpc.DialOption{dialOpt},
		// Long enough that the pool's own background loop cannot race the
		// probe counts this test reasons about.
		HealthInterval: time.Hour,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pool.Close() })

	server, err := mcpserver.New(mcpserver.Options{
		ConfigDir:   dir,
		Clients:     pool,
		LogWriter:   &testWriter{t: t},
		CallTimeout: 5 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })

	session := connect(t, server)

	callTool(t, session, "fleet_add", map[string]any{"name": "agent-a", "address": "agent-a:8722"}, false)

	res := callTool(t, session, "fleet_select", map[string]any{"name": "agent-a"}, false)
	selected := structured[selectResult](t, res)
	assert.Equal(t, "agent-a", selected.Sandbox)
	assert.Equal(t, "linux/arm64", selected.Platform)
	assert.Equal(t, []string{"/srv/work"}, selected.AllowedRoots)

	res = callTool(t, session, "fleet_list", map[string]any{"refresh": true}, false)
	listed := structured[listResult](t, res)
	require.Len(t, listed.Sandboxes, 1)
	assert.Equal(t, "serving", listed.Sandboxes[0].Health)
	assert.Equal(t, "0.1.0-bufconn", listed.Sandboxes[0].Agent)

	// With the agent gone, the same call must produce a readable tool error
	// rather than a gRPC status the model cannot act on.
	stop()

	res = callTool(t, session, "fleet_info", map[string]any{}, true)
	text := resultText(res)
	assert.Contains(t, text, "agent-a", "the error must name the sandbox")
	assert.Contains(t, text, "agent-a:8722", "and the address that did not answer")
	assert.NotContains(t, text, "rpc error: code =")

	res = callTool(t, session, "fleet_list", map[string]any{"refresh": true}, false)
	listed = structured[listResult](t, res)
	require.Len(t, listed.Sandboxes, 1)
	assert.Equal(t, "unreachable", listed.Sandboxes[0].Health,
		"listing must report a dead agent, not fail")
}

// TestLazyPool_BuildsFromCredentialsOnDisk checks the production path that
// the other tests substitute a fake for: a server given no client pool reads
// the CA bundle and control leaf from the config directory and dials with
// them. A missing certificate is covered by TestServer_StartsWithoutCredentials;
// this is the case where they are present.
func TestLazyPool_BuildsFromCredentialsOnDisk(t *testing.T) {
	dir := t.TempDir()
	authority, err := ca.Init(filepath.Join(dir, "ca"), false)
	require.NoError(t, err)

	certPEM, keyPEM := signLeaf(t, authority, ca.ProfileControl, "fleet-mcp", nil)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "control.crt"), certPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "control.key"), keyPEM, 0o600))

	server, err := mcpserver.New(mcpserver.Options{
		ConfigDir:   dir,
		LogWriter:   &testWriter{t: t},
		CallTimeout: 2 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })

	session := connect(t, server)
	// 127.0.0.1:1 is closed, so this fails at the connection rather than at
	// the credentials — which is the point: the pool was built.
	callTool(t, session, "fleet_add", map[string]any{"name": "closed", "address": "127.0.0.1:1"}, false)

	text := resultText(callTool(t, session, "fleet_info", map[string]any{"sandbox": "closed"}, true))
	assert.NotContains(t, text, "control certificate", "the credentials on disk must have been used")
	assert.NotContains(t, text, "fleetctl ca sign")
	assert.Truef(t,
		strings.Contains(text, "unreachable") || strings.Contains(text, "timed out"),
		"expected a connection failure, got: %s", text)
}

// TestLazyPool_NoticesCredentialsAppearingMidSession. Certificates get issued
// while a server is already running — the user reads the error, goes and
// fixes it, and comes back. A session that has to be restarted to notice is a
// session the user will conclude is broken.
func TestLazyPool_NoticesCredentialsAppearingMidSession(t *testing.T) {
	dir := t.TempDir()
	server, err := mcpserver.New(mcpserver.Options{
		ConfigDir:   dir,
		LogWriter:   &testWriter{t: t},
		CallTimeout: 2 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })

	session := connect(t, server)
	callTool(t, session, "fleet_add", map[string]any{"name": "closed", "address": "127.0.0.1:1"}, false)

	text := resultText(callTool(t, session, "fleet_info", map[string]any{"sandbox": "closed"}, true))
	require.Contains(t, text, "fleetctl ca init", "the first failure must name the missing CA")

	// The operator goes and creates them, without restarting the server.
	authority, err := ca.Init(filepath.Join(dir, "ca"), false)
	require.NoError(t, err)
	certPEM, keyPEM := signLeaf(t, authority, ca.ProfileControl, "fleet-mcp", nil)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "control.crt"), certPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "control.key"), keyPEM, 0o600))

	text = resultText(callTool(t, session, "fleet_info", map[string]any{"sandbox": "closed"}, true))
	assert.NotContains(t, text, "fleetctl ca init",
		"the same session must pick up credentials that appeared after it started")
	assert.Truef(t,
		strings.Contains(text, "unreachable") || strings.Contains(text, "timed out"),
		"expected a connection failure once credentials existed, got: %s", text)
}

// TestLazyPool_DoesNotRebuildAfterClose. A handler can still be running when
// the session ends and Server.Close runs — the SDK cancels its context, it
// does not wait for it. A lazy pool that builds on demand would then build a
// *fresh* one on the way out: new channels, new background health goroutines,
// and nothing left to close them, because Server.Close has already dropped its
// closers. On a stdio server the process is exiting anyway; on the Connect
// path, which exists for embedding, it is a leak with no owner.
func TestLazyPool_DoesNotRebuildAfterClose(t *testing.T) {
	dir := t.TempDir()
	authority, err := ca.Init(filepath.Join(dir, "ca"), false)
	require.NoError(t, err)

	certPEM, keyPEM := signLeaf(t, authority, ca.ProfileControl, "fleet-mcp", nil)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "control.crt"), certPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "control.key"), keyPEM, 0o600))

	server, err := mcpserver.New(mcpserver.Options{
		ConfigDir:   dir,
		LogWriter:   &testWriter{t: t},
		CallTimeout: 2 * time.Second,
	})
	require.NoError(t, err)

	session := connect(t, server)
	callTool(t, session, "fleet_add", map[string]any{"name": "closed", "address": "127.0.0.1:1"}, false)

	// Shut the server down without ever having built the pool, so a rebuild
	// would be unmistakable.
	require.NoError(t, server.Close())

	text := resultText(callTool(t, session, "fleet_info", map[string]any{"sandbox": "closed"}, true))
	assert.Contains(t, text, "shutting down",
		"a call arriving after Close must be refused, not answered with a pool nothing will close")
	assert.Contains(t, text, "closed", "and the refusal still names the sandbox it was aimed at")

	// Registry-only tools keep working: they never needed a client.
	callTool(t, session, "fleet_list", map[string]any{}, false)
}

// ---------------------------------------------------------------- helpers

func connect(t *testing.T, server *mcpserver.Server) *mcp.ClientSession {
	t.Helper()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(t.Context(), serverTransport)
	require.NoError(t, err)
	t.Cleanup(func() { _ = serverSession.Close() })

	session, err := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0.0"}, nil).
		Connect(t.Context(), clientTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func callTool(t *testing.T, session *mcp.ClientSession, name string, args map[string]any, wantError bool) *mcp.CallToolResult {
	t.Helper()
	res, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	require.NoError(t, err)
	require.Equalf(t, wantError, res.IsError, "%s: %s", name, resultText(res))
	return res
}

// serveAgentOverBufconn starts an mTLS gRPC server on an in-memory listener
// and returns a stop function plus the dial option that routes to it.
func serveAgentOverBufconn(t *testing.T, authority *ca.CA, name string) (stop func(), dialOpt grpc.DialOption) {
	t.Helper()

	certPEM, keyPEM := signLeaf(t, authority, ca.ProfileAgent, name, []string{name})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(authority.Certificate())

	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS12,
	})))
	sandboxdv1.RegisterHostServiceServer(grpcServer, agentServer{})
	go func() { _ = grpcServer.Serve(lis) }()

	var once bool
	stop = func() {
		if once {
			return
		}
		once = true
		grpcServer.Stop()
		_ = lis.Close()
	}
	t.Cleanup(stop)

	dialOpt = grpc.WithContextDialer(func(ctx context.Context, target string) (net.Conn, error) {
		if strings.Contains(target, name) {
			return lis.DialContext(ctx)
		}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	return stop, dialOpt
}

func signLeaf(t *testing.T, authority *ca.CA, profile ca.Profile, subject string, dnsNames []string) (certPEM, keyPEM []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: subject},
		DNSNames: dnsNames,
	}, priv)
	require.NoError(t, err)

	_, certPEM, err = authority.SignCSR(csrDER, ca.SignOptions{
		Profile: profile, Subject: subject, DNSNames: dnsNames,
	})
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
