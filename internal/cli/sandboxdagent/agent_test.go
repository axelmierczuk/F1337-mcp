package sandboxdagent_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	"github.com/axelmierczuk/fleet-mcp/internal/cli/sandboxdagent"
	"github.com/axelmierczuk/fleet-mcp/internal/registry"
	"github.com/axelmierczuk/fleet-mcp/internal/security/ca"
	"github.com/axelmierczuk/fleet-mcp/internal/security/enroll"
)

// controlPlane stands up a real TCP enrollment listener, as `sandboxctl serve`
// does: a CA-signed serving leaf, no CA private key in the TLS path.
type controlPlane struct {
	ca       *ca.CA
	tokens   *enroll.TokenStore
	registry *registry.Registry
	address  string
}

func startControlPlane(t *testing.T, dir string) *controlPlane {
	t.Helper()

	authority, err := ca.Init(filepath.Join(dir, "ca"), false)
	require.NoError(t, err)
	tokens, err := enroll.OpenTokenStore(filepath.Join(dir, "enrollment-tokens.yaml"))
	require.NoError(t, err)
	fleet, err := registry.Open(filepath.Join(dir, "registry.yaml"))
	require.NoError(t, err)

	serverCert, err := authority.ServerCertificate([]string{"127.0.0.1"}, 0)
	require.NoError(t, err)

	svc := &enroll.Service{
		Tokens: tokens,
		CA:     authority,
		Names:  fleet,
		Fleet:  fleetRecorder{fleet},
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	})))
	sandboxdv1.RegisterEnrollmentServiceServer(server, svc)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)

	return &controlPlane{ca: authority, tokens: tokens, registry: fleet, address: lis.Addr().String()}
}

type fleetRecorder struct{ reg *registry.Registry }

func (f fleetRecorder) Record(sb enroll.EnrolledSandbox) error {
	return f.reg.Add(registry.Sandbox{
		Name:         sb.Name,
		Address:      sb.Address,
		Labels:       sb.Labels,
		Platform:     registry.Platform{OS: sb.OS, Arch: sb.Arch, Hostname: sb.Hostname},
		AgentVersion: sb.AgentVersion,
	})
}

// The M0 acceptance loop end to end: mint, enroll, and the agent holds a leaf
// that validates against the fleet CA.
func TestEnroll_FullLoop(t *testing.T) {
	dir := t.TempDir()
	cp := startControlPlane(t, dir)

	token, _, err := cp.tokens.Mint(enroll.MintOptions{
		Name:      "build-box",
		Labels:    map[string]string{"role": "build"},
		Addresses: []string{"127.0.0.1:8722"},
	})
	require.NoError(t, err)

	agentDir := filepath.Join(dir, "agent")
	var out bytes.Buffer
	code := sandboxdagent.Main([]string{"enroll",
		"--server", cp.address,
		"--token", token,
		"--ca-fingerprint", ca.FormatFingerprint(cp.ca.Fingerprint()),
		"--name", "build-box",
		"--address", "127.0.0.1:8722",
		"--dir", agentDir,
	}, &out)
	require.Equal(t, 0, code, out.String())
	assert.Contains(t, out.String(), "enrolled as \"build-box\"")

	// The agent holds a leaf that validates against the fleet CA for server
	// auth, which is the whole point of enrolling.
	certPEM, err := os.ReadFile(filepath.Join(agentDir, "agent.crt"))
	require.NoError(t, err)
	leaf, err := cp.ca.VerifyLeaf(certPEM, x509.ExtKeyUsageServerAuth)
	require.NoError(t, err)
	assert.Equal(t, "build-box", leaf.Subject.CommonName)

	// The certificate and its key form a usable pair.
	keyPEM, err := os.ReadFile(filepath.Join(agentDir, "agent.key"))
	require.NoError(t, err)
	_, err = tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	// The CA bundle it was handed is the fleet CA.
	caPEM, err := os.ReadFile(filepath.Join(agentDir, "ca.crt"))
	require.NoError(t, err)
	assert.Equal(t, cp.ca.CertPEM(), caPEM)

	// The config the daemon will read points at all three, and loads through
	// the same path the daemon loads it by.
	cfg, err := agent.Load(filepath.Join(agentDir, "agent.yaml"))
	require.NoError(t, err)
	assert.Equal(t, "build-box", cfg.Name)
	assert.FileExists(t, cfg.TLS.Certificate)
	assert.FileExists(t, cfg.TLS.PrivateKey)
	assert.FileExists(t, cfg.TLS.CABundle)
	// The OU the agent will demand of clients is the one the CA stamps on a
	// control leaf. If enroll wrote anything else, every control plane in the
	// fleet would be rejected at the handshake.
	assert.Equal(t, "sandboxd-control", cfg.TLS.RequireClientOU)

	// And the control plane recorded the host, including what it reported
	// about itself.
	sb, err := cp.registry.Get("build-box")
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:8722", sb.Address)
	assert.Equal(t, runtime.GOOS, sb.Platform.OS)
	assert.Equal(t, runtime.GOARCH, sb.Platform.Arch)
	assert.Equal(t, map[string]string{"role": "build"}, sb.Labels)
}

func TestEnroll_PrivateKeyStaysOnTheHost(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	cp := startControlPlane(t, dir)
	token, _, err := cp.tokens.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	agentDir := filepath.Join(dir, "agent")
	var out bytes.Buffer
	code := sandboxdagent.Main([]string{"enroll",
		"--server", cp.address,
		"--token", token,
		"--ca-fingerprint", ca.FormatFingerprint(cp.ca.Fingerprint()),
		"--name", "build-box",
		"--dir", agentDir,
	}, &out)
	require.Equal(t, 0, code, out.String())

	info, err := os.Stat(filepath.Join(agentDir, "agent.key"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

// Without the pin, anything that can answer on the network collects the
// token. Defaulting to unpinned would make that the easy path, so it is
// refused instead.
func TestEnroll_RequiresFingerprint(t *testing.T) {
	dir := t.TempDir()
	cp := startControlPlane(t, dir)
	token, _, err := cp.tokens.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	var out bytes.Buffer
	code := sandboxdagent.Main([]string{"enroll",
		"--server", cp.address,
		"--token", token,
		"--dir", filepath.Join(dir, "agent"),
	}, &out)
	assert.NotEqual(t, 0, code)

	// The token was never sent, so it is still redeemable.
	_, err = cp.tokens.Redeem(token)
	assert.NoError(t, err)
}

func TestEnroll_WrongFingerprintAbortsBeforeTokenIsSent(t *testing.T) {
	dir := t.TempDir()
	cp := startControlPlane(t, dir)
	token, _, err := cp.tokens.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	// A well-formed fingerprint that belongs to a different CA.
	otherCA, err := ca.Init(filepath.Join(t.TempDir(), "other-ca"), false)
	require.NoError(t, err)

	var out bytes.Buffer
	code := sandboxdagent.Main([]string{"enroll",
		"--server", cp.address,
		"--token", token,
		"--ca-fingerprint", ca.FormatFingerprint(otherCA.Fingerprint()),
		"--dir", filepath.Join(dir, "agent"),
	}, &out)
	assert.NotEqual(t, 0, code)

	_, err = cp.tokens.Redeem(token)
	assert.NoError(t, err, "the token must not have been transmitted to an unverified control plane")
}

// The name is the other half of the identity a token authorizes. A host that
// asks to be enrolled under a different one is asking for a CA-signed leaf
// naming another fleet member, so it is refused rather than quietly honoured.
func TestEnroll_CannotEnrollUnderAnotherName(t *testing.T) {
	dir := t.TempDir()
	cp := startControlPlane(t, dir)
	token, _, err := cp.tokens.Mint(enroll.MintOptions{
		Name:      "dev-box",
		Addresses: []string{"127.0.0.1:8722"},
	})
	require.NoError(t, err)

	var out bytes.Buffer
	code := sandboxdagent.Main([]string{"enroll",
		"--server", cp.address,
		"--token", token,
		"--ca-fingerprint", ca.FormatFingerprint(cp.ca.Fingerprint()),
		"--name", "prod-db.internal",
		"--dir", filepath.Join(dir, "agent"),
	}, &out)
	assert.NotEqual(t, 0, code, "a token reserving dev-box must not enroll a host as prod-db.internal")
	assert.NoFileExists(t, filepath.Join(dir, "agent", "agent.crt"))

	// And nothing was recorded under the name it tried to claim.
	_, err = cp.registry.Get("prod-db.internal")
	require.Error(t, err)
}

// Omitting --name is the normal path: the token already names the sandbox, and
// a host that substituted its own hostname there would be refused by the check
// above for no reason.
func TestEnroll_WithoutNameUsesTheTokensReservation(t *testing.T) {
	dir := t.TempDir()
	cp := startControlPlane(t, dir)
	token, _, err := cp.tokens.Mint(enroll.MintOptions{
		Name:      "build-box",
		Addresses: []string{"127.0.0.1:8722"},
	})
	require.NoError(t, err)

	var out bytes.Buffer
	code := sandboxdagent.Main([]string{"enroll",
		"--server", cp.address,
		"--token", token,
		"--ca-fingerprint", ca.FormatFingerprint(cp.ca.Fingerprint()),
		"--address", "127.0.0.1:8722",
		"--dir", filepath.Join(dir, "agent"),
	}, &out)
	require.Equal(t, 0, code, out.String())
	assert.Contains(t, out.String(), "enrolled as \"build-box\"")

	certPEM, err := os.ReadFile(filepath.Join(dir, "agent", "agent.crt"))
	require.NoError(t, err)
	leaf, err := cp.ca.VerifyLeaf(certPEM, x509.ExtKeyUsageServerAuth)
	require.NoError(t, err)
	assert.Equal(t, []string{"build-box"}, leaf.DNSNames)
	require.NoError(t, leaf.VerifyHostname("127.0.0.1"))
}

// A relative --dir must still produce a config the daemon can load.
//
// agent.yaml names the certificate, key, CA bundle, state directory and audit
// path, and Load resolves any relative one of those against the config file's
// own directory. Writing them relative therefore doubles the directory:
// "out/agent.crt" inside "out/agent.yaml" is read back as "out/out/agent.crt",
// and the daemon fails to start on a certificate it wrote itself.
func TestEnroll_RelativeDirWritesLoadablePaths(t *testing.T) {
	dir := t.TempDir()
	cp := startControlPlane(t, dir)
	token, _, err := cp.tokens.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	// --dir is interpreted against the working directory, so run from one the
	// test owns rather than from the package directory.
	wd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(wd) })

	// The expectation is built from the working directory as the process sees
	// it, which is the base filepath.Abs resolves --dir against. It is not
	// always the string t.TempDir returned: macOS reports /private/var where
	// TempDir said /var, and a Windows runner reports the 8.3 short form
	// (C:\Users\RUNNER~1) where TempDir said C:\Users\runneradmin. Both name
	// the same directory, so comparing against the wrong spelling tests the
	// platform's naming rather than this command's behaviour.
	cwd, err := os.Getwd()
	require.NoError(t, err)

	var out bytes.Buffer
	code := sandboxdagent.Main([]string{"enroll",
		"--server", cp.address,
		"--token", token,
		"--ca-fingerprint", ca.FormatFingerprint(cp.ca.Fingerprint()),
		"--dir", "enrollment",
	}, &out)
	require.Equal(t, 0, code, out.String())

	cfg, err := agent.Load(filepath.Join(dir, "enrollment", "agent.yaml"))
	require.NoError(t, err)
	for _, path := range []string{cfg.TLS.Certificate, cfg.TLS.PrivateKey, cfg.TLS.CABundle} {
		assert.FileExists(t, path, "the daemon must find the material enroll just wrote")
	}
	assert.Equal(t, filepath.Join(cwd, "enrollment", "state"), cfg.StateDir)
	assert.DirExists(t, filepath.Join(cwd, "enrollment"),
		"a relative --dir must not have written a second level of the same name")
	assert.NoDirExists(t, filepath.Join(cwd, "enrollment", "enrollment"),
		"the directory must not have been rebased through itself")
}

// The agent asks for what it was told to listen on; the control plane decides
// what it is certified for. Asking is not receiving.
func TestEnroll_AgentCannotWidenItsOwnCertificate(t *testing.T) {
	dir := t.TempDir()
	cp := startControlPlane(t, dir)
	token, _, err := cp.tokens.Mint(enroll.MintOptions{
		Name:      "build-box",
		Addresses: []string{"127.0.0.1:8722"},
	})
	require.NoError(t, err)

	var out bytes.Buffer
	code := sandboxdagent.Main([]string{"enroll",
		"--server", cp.address,
		"--token", token,
		"--ca-fingerprint", ca.FormatFingerprint(cp.ca.Fingerprint()),
		"--name", "build-box",
		"--address", "prod-db.internal:8722",
		"--dir", filepath.Join(dir, "agent"),
	}, &out)
	assert.NotEqual(t, 0, code, "an unauthorized address must not be certified")
	assert.NoFileExists(t, filepath.Join(dir, "agent", "agent.crt"))
}
