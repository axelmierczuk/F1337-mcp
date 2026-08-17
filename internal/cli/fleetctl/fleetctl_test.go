package fleetctl_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/cli/fleetctl"
	"github.com/axelmierczuk/fleet-mcp/internal/security/ca"
	"github.com/axelmierczuk/fleet-mcp/internal/security/enroll"
)

// run executes fleetctl with args against a config directory scoped to this
// test, and returns its output and exit code.
func run(t *testing.T, configDir string, args ...string) (string, int) {
	t.Helper()
	t.Setenv("FLEET_CONFIG_DIR", configDir)
	var out bytes.Buffer
	code := fleetctl.Main(args, &out)
	return out.String(), code
}

func TestCAInit_ProducesFingerprintAndRefusesReinit(t *testing.T) {
	dir := t.TempDir()

	out, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code, out)
	assert.Contains(t, out, "SHA256 Fingerprint=")

	// A second init without --force must fail: silently replacing a CA
	// orphans every certificate it ever issued.
	_, code = run(t, dir, "ca", "init")
	assert.NotEqual(t, 0, code)

	_, code = run(t, dir, "ca", "init", "--force")
	assert.Equal(t, 0, code)
}

// The fingerprint an operator hands to an enrolling host must be the one that
// pinning actually compares against.
func TestCAFingerprint_MatchesTheCACertificate(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)

	out, code := run(t, dir, "ca", "fingerprint")
	require.Equal(t, 0, code, out)

	authority, err := ca.Load(filepath.Join(dir, "ca"))
	require.NoError(t, err)
	sum := sha256.Sum256(authority.Certificate().Raw)
	assert.Contains(t, out, ca.FormatFingerprint(sum))
}

func TestEnrollMint_WritesARedeemableTokenToDisk(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)

	out, code := run(t, dir, "enroll", "mint", "--name", "build-box", "--address", "build-box.internal:9443")
	require.Equal(t, 0, code, out)

	token := tokenFrom(t, out)
	assert.True(t, strings.HasPrefix(token, enroll.TokenPrefix))
	assert.Contains(t, out, "ca-fingerprint:")

	// The serving process is a different process, so the token has to be
	// redeemable from a store opened fresh against the same path.
	store, err := enroll.OpenTokenStore(filepath.Join(dir, "enrollment-tokens.yaml"))
	require.NoError(t, err)
	rec, err := store.Redeem(token)
	require.NoError(t, err)
	assert.Equal(t, "build-box", rec.Name)
	assert.Equal(t, []string{"build-box.internal:9443"}, rec.Addresses)
}

// Minting without --address is allowed, but the operator is told what it costs
// before the agent fails a handshake over it.
func TestEnrollMint_WarnsWhenNoAddressAuthorized(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)

	out, code := run(t, dir, "enroll", "mint", "--name", "build-box")
	require.Equal(t, 0, code, out)
	assert.Contains(t, out, "--address")
}

func TestEnrollList_ShowsMintedTokens(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)
	_, code = run(t, dir, "enroll", "mint", "--name", "build-box")
	require.Equal(t, 0, code)

	out, code := run(t, dir, "enroll", "list")
	require.Equal(t, 0, code, out)
	assert.Contains(t, out, "build-box")
	assert.Contains(t, out, "pending")
	// The plaintext token is shown once, at mint time, and never again.
	assert.NotContains(t, out, enroll.TokenPrefix)
}

// Rotation: re-issuing a leaf before expiry must not require a fresh
// enrollment token. Tokens bootstrap an identity the fleet does not yet know
// about; renewing one it does know about is an operator action.
func TestCASign_RotatesALeafWithoutAToken(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)

	key, err := enroll.GenerateKey()
	require.NoError(t, err)
	csrDER, err := enroll.BuildCSR(key, "build-box", nil, nil)
	require.NoError(t, err)
	csrPath := filepath.Join(dir, "build-box.csr")
	require.NoError(t, os.WriteFile(csrPath, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrDER,
	}), 0o600))

	certPath := filepath.Join(dir, "build-box.crt")
	out, code := run(t, dir, "ca", "sign",
		"--csr", csrPath,
		"--subject", "build-box",
		"--address", "build-box.internal:9443",
		"--out", certPath)
	require.Equal(t, 0, code, out)

	certPEM, err := os.ReadFile(certPath)
	require.NoError(t, err)
	authority, err := ca.Load(filepath.Join(dir, "ca"))
	require.NoError(t, err)
	leaf, err := authority.VerifyLeaf(certPEM, x509.ExtKeyUsageServerAuth)
	require.NoError(t, err)
	assert.Equal(t, "build-box", leaf.Subject.CommonName)
	assert.ElementsMatch(t, []string{"build-box", "build-box.internal"}, leaf.DNSNames)

	// No token was minted or spent to get here.
	listOut, code := run(t, dir, "enroll", "list")
	require.Equal(t, 0, code)
	assert.Contains(t, listOut, "no enrollment tokens")
}

func TestCASign_RejectsAWildcardAddress(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)

	key, err := enroll.GenerateKey()
	require.NoError(t, err)
	csrDER, err := enroll.BuildCSR(key, "build-box", nil, nil)
	require.NoError(t, err)
	csrPath := filepath.Join(dir, "build-box.csr")
	require.NoError(t, os.WriteFile(csrPath, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrDER,
	}), 0o600))

	_, code = run(t, dir, "ca", "sign", "--csr", csrPath, "--subject", "build-box", "--address", "*.internal:9443")
	assert.NotEqual(t, 0, code, "the CA must refuse a wildcard even when the operator asks for one")
}

func TestUnknownCommand_ExitsNonZero(t *testing.T) {
	_, code := run(t, t.TempDir(), "definitely-not-a-command")
	assert.NotEqual(t, 0, code)
}

func TestList_EmptyFleet(t *testing.T) {
	out, code := run(t, t.TempDir(), "list")
	require.Equal(t, 0, code, out)
	assert.Contains(t, out, "no sandboxes enrolled")
}

func tokenFrom(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(line, "token:"); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatalf("no token in output:\n%s", out)
	return ""
}
