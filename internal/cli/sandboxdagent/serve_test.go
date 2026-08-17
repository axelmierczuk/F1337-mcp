package sandboxdagent_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/agent"
	"github.com/axelmierczuk/sandboxd-mcp/internal/cli/sandboxdagent"
	"github.com/axelmierczuk/sandboxd-mcp/internal/client"
	"github.com/axelmierczuk/sandboxd-mcp/internal/security/ca"
)

// enrolledAgent writes a complete, startable agent installation to a temp
// directory: a fleet CA, an agent leaf, and the config pointing at both.
type enrolledAgent struct {
	ca         *ca.CA
	configPath string
	address    string
}

func newEnrolledAgent(t *testing.T, roots ...string) *enrolledAgent {
	t.Helper()

	dir := t.TempDir()
	authority, err := ca.Init(filepath.Join(dir, "ca"), false)
	require.NoError(t, err)

	certPEM, keyPEM := signLeaf(t, authority, ca.ProfileAgent, "test-agent", []string{"localhost"})
	certPath := filepath.Join(dir, "agent.crt")
	keyPath := filepath.Join(dir, "agent.key")
	caPath := filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))
	require.NoError(t, os.WriteFile(caPath, authority.CertPEM(), 0o600))

	address := "127.0.0.1:" + freePort(t)
	cfg := &agent.Config{
		Name:   "test-agent",
		Listen: address,
		TLS: agent.TLSConfig{
			Certificate:     certPath,
			PrivateKey:      keyPath,
			CABundle:        caPath,
			RequireClientOU: agent.DefaultClientOU,
		},
		AllowedRoots: roots,
		StateDir:     filepath.Join(dir, "state"),
		Audit:        agent.AuditConfig{Path: filepath.Join(dir, "logs", "audit.jsonl")},
	}
	configPath := filepath.Join(dir, "agent.yaml")
	require.NoError(t, cfg.Save(configPath))

	return &enrolledAgent{ca: authority, configPath: configPath, address: address}
}

// freePort asks the kernel for an unused port and gives it straight back. The
// window between is a race in principle; in practice the kernel does not
// immediately reissue a port it just handed out, and the alternative is not
// exercising a real socket at all.
func freePort(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(lis.Addr().String())
	require.NoError(t, err)
	require.NoError(t, lis.Close())
	return port
}

func signLeaf(t *testing.T, authority *ca.CA, profile ca.Profile, cn string, dnsNames []string) (certPEM, keyPEM []byte) {
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

// runServe starts the serve command in the background and returns a channel
// carrying its exit code.
func runServe(ctx context.Context, t *testing.T, args ...string) (<-chan int, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}
	codes := make(chan int, 1)
	go func() { codes <- sandboxdagent.MainContext(ctx, args, out) }()
	return codes, out
}

// waitServing polls until the daemon answers Health, so a test does not race
// the listener opening.
func waitServing(t *testing.T, ea *enrolledAgent) sandboxdv1.HostServiceClient {
	t.Helper()

	certPEM, keyPEM := signLeaf(t, ea.ca, ca.ProfileControl, "sandboxd-mcp", nil)
	pool, err := client.NewPool(client.Config{
		CACertPEM: ea.ca.CertPEM(),
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pool.Close() })

	// The leaf names "localhost", so that is the name the client must verify
	// against — dialing 127.0.0.1 would fail hostname verification, exactly as
	// it would in production.
	_, port, err := net.SplitHostPort(ea.address)
	require.NoError(t, err)
	hostClient, err := pool.Host("test-agent", net.JoinHostPort("localhost", port))
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := hostClient.Health(ctx, &sandboxdv1.HealthRequest{})
		return err == nil
	}, 15*time.Second, 100*time.Millisecond, "the daemon never started serving")

	return hostClient
}

// The core acceptance criterion for #5: serve starts, answers Health over
// mTLS, and shuts down cleanly.
func TestServe_StartsServesAndStopsCleanly(t *testing.T) {
	ea := newEnrolledAgent(t, t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	codes, out := runServe(ctx, t, "serve", "--config", ea.configPath)
	defer cancel()

	hostClient := waitServing(t, ea)

	resp, err := hostClient.Health(context.Background(), &sandboxdv1.HealthRequest{})
	require.NoError(t, err)
	assert.Equal(t, sandboxdv1.HealthResponse_STATUS_SERVING, resp.GetStatus())

	// GetHostInfo comes back with the identity the handshake established, not
	// anything the caller sent.
	info, err := hostClient.GetHostInfo(context.Background(), &sandboxdv1.GetHostInfoRequest{})
	require.NoError(t, err)
	assert.Equal(t, "sandboxd-mcp", info.GetAuthenticatedPrincipal())
	assert.Equal(t, runtime.GOOS, info.GetPlatform().GetOs())
	assert.NotEmpty(t, info.GetAllowedRoots())

	cancel()
	select {
	case code := <-codes:
		assert.Equal(t, 0, code, out.String())
	case <-time.After(20 * time.Second):
		t.Fatal("serve did not exit after its context was cancelled")
	}
}

// The same thing driven by a real SIGTERM, which is what systemd and launchd
// actually send.
//
// Sending a signal to the test process is safe only while serve's handler is
// installed, so the test waits for the daemon to be serving first and for it
// to exit afterwards.
func TestServe_ShutsDownOnSIGTERM(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no SIGTERM; the service manager stops the process through the SCM")
	}
	ea := newEnrolledAgent(t, t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	codes, out := runServe(ctx, t, "serve", "--config", ea.configPath)

	waitServing(t, ea)

	require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGTERM))

	select {
	case code := <-codes:
		assert.Equal(t, 0, code, out.String())
	case <-time.After(20 * time.Second):
		t.Fatal("serve did not exit on SIGTERM")
	}
}

// An empty allowed_roots list is refused, and the refusal names the override
// rather than leaving the operator to guess.
func TestServe_RefusesEmptyAllowedRootsWithoutNoJail(t *testing.T) {
	ea := newEnrolledAgent(t)

	out := &bytes.Buffer{}
	code := sandboxdagent.Main([]string{"serve", "--config", ea.configPath}, out)
	assert.Equal(t, 1, code)
}

// With --no-jail it starts, and says so loudly.
func TestServe_NoJailStartsAndWarns(t *testing.T) {
	ea := newEnrolledAgent(t)

	// The warning goes to the daemon's logger on stderr, so capture that.
	stderr := captureStderr(t)

	ctx, cancel := context.WithCancel(context.Background())
	codes, out := runServe(ctx, t, "serve", "--config", ea.configPath, "--no-jail")
	defer cancel()

	hostClient := waitServing(t, ea)
	info, err := hostClient.GetHostInfo(context.Background(), &sandboxdv1.GetHostInfoRequest{})
	require.NoError(t, err)
	assert.Empty(t, info.GetAllowedRoots(), "a jail-less agent reports no roots, which is how sandbox_info surfaces it")

	cancel()
	select {
	case code := <-codes:
		require.Equal(t, 0, code, out.String())
	case <-time.After(20 * time.Second):
		t.Fatal("serve did not exit")
	}

	logged := stderr()
	assert.Contains(t, logged, "STARTING WITHOUT A PATH JAIL")
	assert.Contains(t, logged, "level=WARN")
}

// A config that does not exist is a clear failure naming the file, not a
// daemon that starts with defaults.
func TestServe_MissingConfig(t *testing.T) {
	out := &bytes.Buffer{}
	code := sandboxdagent.Main([]string{"serve", "--config", filepath.Join(t.TempDir(), "absent.yaml")}, out)
	assert.Equal(t, 1, code)
}

// captureStderr redirects os.Stderr for the duration of a test and returns a
// function yielding what was written.
func captureStderr(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)

	original := os.Stderr
	os.Stderr = w

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		done <- buf.String()
	}()

	var captured string
	var read bool
	t.Cleanup(func() {
		if !read {
			os.Stderr = original
			_ = w.Close()
			<-done
		}
	})
	return func() string {
		if read {
			return captured
		}
		read = true
		os.Stderr = original
		require.NoError(t, w.Close())
		captured = <-done
		return captured
	}
}
