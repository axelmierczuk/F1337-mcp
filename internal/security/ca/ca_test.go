package ca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/security/ca"
)

func generateCSR(t *testing.T, priv any, cn string) []byte {
	t.Helper()
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	require.NoError(t, err)
	return der
}

func ecdsaCSR(t *testing.T, cn string) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return generateCSR(t, priv, cn)
}

func TestInit_ProducesUsableCA(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	c, err := ca.Init(dir, false)
	require.NoError(t, err)
	require.NotEmpty(t, c.CertPEM())
	assert.True(t, c.Certificate().IsCA)
	assert.Equal(t, 0, c.Certificate().MaxPathLen)
	assert.True(t, c.Certificate().MaxPathLenZero)

	reloaded, err := ca.Load(dir)
	require.NoError(t, err)
	assert.Equal(t, c.Certificate().Raw, reloaded.Certificate().Raw)
}

func TestInit_RefusesOverwriteWithoutForce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	_, err := ca.Init(dir, false)
	require.NoError(t, err)

	_, err = ca.Init(dir, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "force")
}

func TestInit_ForceOverwrites(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	first, err := ca.Init(dir, false)
	require.NoError(t, err)

	second, err := ca.Init(dir, true)
	require.NoError(t, err)

	assert.NotEqual(t, first.Certificate().Raw, second.Certificate().Raw)
}

// A certificate beside a key from a different CA is what a half-restored
// backup, or two `ca init` runs pointed at overlapping directories, leaves
// behind. Loading it succeeds, so `fleetctl serve` starts and `ca
// fingerprint` prints — and the operator distributes — the fingerprint of a CA
// this process cannot sign for. Every enrollment then fails at the last step,
// after its token has been spent.
func TestLoad_RejectsCertificateAndKeyFromDifferentCAs(t *testing.T) {
	dirA := filepath.Join(t.TempDir(), "a")
	dirB := filepath.Join(t.TempDir(), "b")
	_, err := ca.Init(dirA, false)
	require.NoError(t, err)
	_, err = ca.Init(dirB, false)
	require.NoError(t, err)

	keyB, err := os.ReadFile(filepath.Join(dirB, "ca.key"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dirA, "ca.key"), keyB, 0o600))

	_, err = ca.Load(dirA)
	require.Error(t, err, "a certificate and a key from different CAs are not a CA")
	assert.Contains(t, err.Error(), "different CAs")
}

func TestSignCSR_AgentProfile_ServerAuthValidates(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	c, err := ca.Init(dir, false)
	require.NoError(t, err)

	csrDER := ecdsaCSR(t, "build-box")
	_, certPEM, err := c.SignCSR(csrDER, ca.SignOptions{
		Profile:  ca.ProfileAgent,
		Subject:  "build-box",
		DNSNames: []string{"build-box"},
	})
	require.NoError(t, err)

	_, err = c.VerifyLeaf(certPEM, x509.ExtKeyUsageServerAuth)
	assert.NoError(t, err)
}

func TestSignCSR_ControlProfile_ClientAuthValidates(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	c, err := ca.Init(dir, false)
	require.NoError(t, err)

	csrDER := ecdsaCSR(t, "fleet-mcp")
	_, certPEM, err := c.SignCSR(csrDER, ca.SignOptions{
		Profile: ca.ProfileControl,
		Subject: "fleet-mcp",
	})
	require.NoError(t, err)

	_, err = c.VerifyLeaf(certPEM, x509.ExtKeyUsageClientAuth)
	assert.NoError(t, err)
}

// TestSignCSR_AgentLeafRejectedAsClientCert is the check that stops one
// compromised sandbox from driving the rest of the fleet: an agent leaf
// only carries the server-auth EKU, so presenting it where a client
// certificate is expected must fail chain verification.
func TestSignCSR_AgentLeafRejectedAsClientCert(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	c, err := ca.Init(dir, false)
	require.NoError(t, err)

	csrDER := ecdsaCSR(t, "build-box")
	_, certPEM, err := c.SignCSR(csrDER, ca.SignOptions{
		Profile:  ca.ProfileAgent,
		Subject:  "build-box",
		DNSNames: []string{"build-box"},
	})
	require.NoError(t, err)

	_, err = c.VerifyLeaf(certPEM, x509.ExtKeyUsageClientAuth)
	require.Error(t, err)

	var invalid x509.CertificateInvalidError
	if assert.ErrorAs(t, err, &invalid) {
		assert.Equal(t, x509.IncompatibleUsage, invalid.Reason)
	}
}

// TestSignCSR_ControlLeafRejectedAsServerCert is the symmetric case: a
// control leaf must not be usable as an agent's server identity.
func TestSignCSR_ControlLeafRejectedAsServerCert(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	c, err := ca.Init(dir, false)
	require.NoError(t, err)

	csrDER := ecdsaCSR(t, "fleet-mcp")
	_, certPEM, err := c.SignCSR(csrDER, ca.SignOptions{
		Profile: ca.ProfileControl,
		Subject: "fleet-mcp",
	})
	require.NoError(t, err)

	_, err = c.VerifyLeaf(certPEM, x509.ExtKeyUsageServerAuth)
	require.Error(t, err)
}

func TestFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	dir := filepath.Join(t.TempDir(), "ca")
	_, err := ca.Init(dir, false)
	require.NoError(t, err)

	dirInfo, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())

	keyInfo, err := os.Stat(filepath.Join(dir, "ca.key"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), keyInfo.Mode().Perm())
}

func TestFingerprint_MatchesOpenSSL(t *testing.T) {
	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available")
	}

	dir := filepath.Join(t.TempDir(), "ca")
	c, err := ca.Init(dir, false)
	require.NoError(t, err)

	out, err := exec.Command(opensslPath, "x509", "-in", filepath.Join(dir, "ca.crt"), "-noout", "-fingerprint", "-sha256").Output() //nolint:gosec
	require.NoError(t, err)

	// openssl prints "sha256 Fingerprint=AA:BB:...\n" (case of the label
	// varies by version); pull out the fingerprint value.
	line := strings.TrimSpace(string(out))
	idx := strings.LastIndex(line, "=")
	require.Greater(t, idx, -1, "unexpected openssl output: %s", line)
	want := line[idx+1:]

	got := ca.FormatFingerprint(c.Fingerprint())
	assert.Equal(t, want, got)
}

func TestParseFingerprint_RoundTrips(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	c, err := ca.Init(dir, false)
	require.NoError(t, err)

	sum := c.Fingerprint()
	formatted := ca.FormatFingerprint(sum)

	parsed, err := ca.ParseFingerprint(formatted)
	require.NoError(t, err)
	assert.Equal(t, sum, parsed)

	// Plain hex, lowercase, no separators, should parse the same way.
	plain, err := ca.ParseFingerprint(strings.ToLower(strings.ReplaceAll(formatted, ":", "")))
	require.NoError(t, err)
	assert.Equal(t, sum, plain)
}

func TestParseFingerprint_RejectsGarbage(t *testing.T) {
	_, err := ca.ParseFingerprint("not-a-fingerprint")
	require.Error(t, err)

	_, err = ca.ParseFingerprint("aa:bb")
	require.Error(t, err)
}

func TestLeafLifetime_Default(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	c, err := ca.Init(dir, false)
	require.NoError(t, err)

	csrDER := ecdsaCSR(t, "build-box")
	cert, _, err := c.SignCSR(csrDER, ca.SignOptions{Profile: ca.ProfileAgent, Subject: "build-box"})
	require.NoError(t, err)

	wantNotAfter := time.Now().Add(ca.DefaultLeafTTL)
	assert.WithinDuration(t, wantNotAfter, cert.NotAfter, time.Hour)
}

func TestLeafLifetime_Configurable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	c, err := ca.Init(dir, false)
	require.NoError(t, err)

	ttl := 2 * time.Hour
	csrDER := ecdsaCSR(t, "build-box")
	cert, _, err := c.SignCSR(csrDER, ca.SignOptions{Profile: ca.ProfileAgent, Subject: "build-box", TTL: ttl})
	require.NoError(t, err)

	wantNotAfter := time.Now().Add(ttl)
	assert.WithinDuration(t, wantNotAfter, cert.NotAfter, time.Minute)
}

func TestSignCSR_RejectsWeakRSAKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	c, err := ca.Init(dir, false)
	require.NoError(t, err)

	priv, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec
	require.NoError(t, err)
	csrDER := generateCSR(t, priv, "weak-rsa")

	_, _, err = c.SignCSR(csrDER, ca.SignOptions{Profile: ca.ProfileAgent, Subject: "weak-rsa"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "weak")
}

func TestSignCSR_RejectsWeakECDSAKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	c, err := ca.Init(dir, false)
	require.NoError(t, err)

	priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)
	csrDER := generateCSR(t, priv, "weak-ecdsa")

	_, _, err = c.SignCSR(csrDER, ca.SignOptions{Profile: ca.ProfileAgent, Subject: "weak-ecdsa"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "weak")
}

func TestSignCSR_RejectsInvalidSignature(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	c, err := ca.Init(dir, false)
	require.NoError(t, err)

	csrDER := ecdsaCSR(t, "build-box")
	// Corrupt a byte inside the trailing signature to invalidate it without
	// disturbing the ASN.1 structure enough to fail parsing outright.
	tampered := make([]byte, len(csrDER))
	copy(tampered, csrDER)
	tampered[len(tampered)-1] ^= 0xFF

	_, _, err = c.SignCSR(tampered, ca.SignOptions{Profile: ca.ProfileAgent, Subject: "build-box"})
	require.Error(t, err)
}

func TestSignCSR_RejectsUnknownProfile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	c, err := ca.Init(dir, false)
	require.NoError(t, err)

	csrDER := ecdsaCSR(t, "build-box")
	_, _, err = c.SignCSR(csrDER, ca.SignOptions{Profile: ca.Profile(99), Subject: "build-box"})
	require.Error(t, err)
}
