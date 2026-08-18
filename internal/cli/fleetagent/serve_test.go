package fleetagent_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	"github.com/axelmierczuk/fleet-mcp/internal/cli/fleetagent"
	"github.com/axelmierczuk/fleet-mcp/internal/client"
	"github.com/axelmierczuk/fleet-mcp/internal/security/ca"
)

// enrolledAgent writes a complete, startable agent installation to a temp
// directory: a fleet CA, an agent leaf, and the config pointing at both.
type enrolledAgent struct {
	ca         *ca.CA
	configPath string
	address    string
	stateDir   string
}

// newEnrolledAgent writes an installation with exec left at its default, which
// is on — and therefore with no path jail, whatever roots are passed.
func newEnrolledAgent(t *testing.T, roots ...string) *enrolledAgent {
	t.Helper()
	return newAgentInstall(t, true, roots...)
}

// newJailedAgent writes one with exec disabled, which is the configuration
// where allowed_roots is enforced.
func newJailedAgent(t *testing.T, roots ...string) *enrolledAgent {
	t.Helper()
	return newAgentInstall(t, false, roots...)
}

func newAgentInstall(t *testing.T, execEnabled bool, roots ...string) *enrolledAgent {
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
		Exec:         agent.ExecConfig{Enabled: &execEnabled},
	}
	configPath := filepath.Join(dir, "agent.yaml")
	require.NoError(t, cfg.Save(configPath))

	return &enrolledAgent{ca: authority, configPath: configPath, address: address, stateDir: cfg.StateDir}
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
	go func() { codes <- fleetagent.MainContext(ctx, args, out) }()
	return codes, out
}

// waitServing polls until the daemon answers Health, so a test does not race
// the listener opening.
func waitServing(t *testing.T, ea *enrolledAgent) sandboxdv1.HostServiceClient {
	t.Helper()

	certPEM, keyPEM := signLeaf(t, ea.ca, ca.ProfileControl, "fleet-mcp", nil)
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
	assert.Equal(t, "fleet-mcp", info.GetAuthenticatedPrincipal())
	assert.Equal(t, runtime.GOOS, info.GetPlatform().GetOs())
	// Exec is on in this config, so there is no jail and the agent says so.
	// TestServe_ExecDisabledEnforcesAllowedRoots covers the other side.
	assert.Empty(t, info.GetAllowedRoots())

	cancel()
	select {
	case code := <-codes:
		assert.Equal(t, 0, code, out.String())
	case <-time.After(20 * time.Second):
		t.Fatal("serve did not exit after its context was cancelled")
	}
}

// The same thing driven by a real SIGTERM lives in serve_signal_unix_test.go:
// syscall.Kill does not exist on Windows, so it has to be excluded at build
// time rather than skipped at run time.

// An exec-disabled agent with an empty allowed_roots is refused, and the
// refusal names the override rather than leaving the operator to guess.
func TestServe_RefusesEmptyAllowedRootsWithoutNoJail(t *testing.T) {
	ja := newJailedAgent(t)

	out := &bytes.Buffer{}
	code := fleetagent.Main([]string{"serve", "--config", ja.configPath}, out)
	assert.Equal(t, 1, code)
}

// With --no-jail it starts, and says so loudly.
func TestServe_NoJailStartsAndWarns(t *testing.T) {
	ja := newJailedAgent(t)

	// The warning goes to the daemon's logger on stderr, so capture that.
	stderr := captureStderr(t)

	ctx, cancel := context.WithCancel(context.Background())
	codes, out := runServe(ctx, t, "serve", "--config", ja.configPath, "--no-jail")
	defer cancel()

	hostClient := waitServing(t, ja)
	info, err := hostClient.GetHostInfo(context.Background(), &sandboxdv1.GetHostInfoRequest{})
	require.NoError(t, err)
	assert.Empty(t, info.GetAllowedRoots(), "a jail-less agent reports no roots, which is how fleet_info surfaces it")

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

// End to end: exec on, roots configured. The daemon starts without demanding
// --no-jail, ignores the roots, says so at WARN, and tells the caller it is
// unconfined.
//
// The last part is the one that reaches the model: allowed_roots is what
// fleet_select returns to tell it where it may write.
func TestServe_ExecEnabledIgnoresAllowedRoots(t *testing.T) {
	ea := newEnrolledAgent(t, t.TempDir())

	stderr := captureStderr(t)

	ctx, cancel := context.WithCancel(context.Background())
	codes, out := runServe(ctx, t, "serve", "--config", ea.configPath)
	defer cancel()

	hostClient := waitServing(t, ea)
	info, err := hostClient.GetHostInfo(context.Background(), &sandboxdv1.GetHostInfoRequest{})
	require.NoError(t, err)
	assert.Empty(t, info.GetAllowedRoots(),
		"with exec enabled the roots confine nothing, and the wire must not claim otherwise")

	cancel()
	select {
	case code := <-codes:
		require.Equal(t, 0, code, out.String())
	case <-time.After(20 * time.Second):
		t.Fatal("serve did not exit")
	}

	logged := stderr()
	assert.Contains(t, logged, "ALLOWED_ROOTS ARE IGNORED")
	assert.Contains(t, logged, "level=WARN")
	assert.Contains(t, logged, "exec.enabled: false", "the warning must name the remedy")
}

// The other side: exec off, roots configured, roots enforced and reported.
func TestServe_ExecDisabledEnforcesAllowedRoots(t *testing.T) {
	root := t.TempDir()
	ja := newJailedAgent(t, root)

	ctx, cancel := context.WithCancel(context.Background())
	codes, out := runServe(ctx, t, "serve", "--config", ja.configPath)
	defer cancel()

	hostClient := waitServing(t, ja)
	info, err := hostClient.GetHostInfo(context.Background(), &sandboxdv1.GetHostInfoRequest{})
	require.NoError(t, err)

	resolvedRoot, err := filepath.EvalSymlinks(root)
	require.NoError(t, err)
	assert.Equal(t, []string{resolvedRoot}, info.GetAllowedRoots())

	cancel()
	select {
	case code := <-codes:
		require.Equal(t, 0, code, out.String())
	case <-time.After(20 * time.Second):
		t.Fatal("serve did not exit")
	}
}

// A config that does not exist is a clear failure naming the file, not a
// daemon that starts with defaults.
func TestServe_MissingConfig(t *testing.T) {
	out := &bytes.Buffer{}
	code := fleetagent.Main([]string{"serve", "--config", filepath.Join(t.TempDir(), "absent.yaml")}, out)
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

// `serve` records what the daemon can reach, where `service status` reads it.
//
// This is the one path that makes the report exist at all: every answer status
// gives about a confined agent — the account, the session, whether a per-user
// toolchain resolves — is read out of this file, and nothing else on the host
// writes it. The report is written before the listener opens, so a daemon that
// is answering Health has already written one; there is nothing here that
// depends on how long anything took.
func TestServe_RecordsWhatTheDaemonCanReach(t *testing.T) {
	ea := newEnrolledAgent(t, t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	codes, out := runServe(ctx, t, "serve", "--config", ea.configPath)
	defer cancel()
	waitServing(t, ea)

	data, err := os.ReadFile(filepath.Join(ea.stateDir, "runtime.json"))
	require.NoError(t, err, "the daemon has to record its own environment: %s", out.String())

	var report struct {
		PID     int    `json:"pid"`
		StartID string `json:"start_id"`
		Account string `json:"account"`
		Home    string `json:"home"`
		Profile struct {
			Visibility string `json:"visibility"`
		} `json:"profile"`
	}
	require.NoError(t, json.Unmarshal(data, &report))

	assert.Equal(t, os.Getpid(), report.PID, "serve runs in this process here")
	assert.NotEmpty(t, report.StartID,
		"without a start identity `service status` refuses the report, so an agent that recorded one would never be reported on")
	assert.NotEmpty(t, report.Account, "the account the platform says the daemon is running as")
	assert.NotEmpty(t, report.Home)
	assert.Contains(t, []string{"visible", "hidden", "unknown"}, report.Profile.Visibility)

	cancel()
	select {
	case <-codes:
	case <-time.After(20 * time.Second):
		t.Fatal("serve did not exit after its context was cancelled")
	}
}
