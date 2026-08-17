package fleetctl_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
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

// runCapturingErrors is run with both streams pointed at one buffer, for a test
// that asserts on the message a failure produces. Main sends errors to stderr,
// which is right for the binary and useless to a test.
func runCapturingErrors(t *testing.T, configDir string, args ...string) (string, int) {
	t.Helper()
	t.Setenv("FLEET_CONFIG_DIR", configDir)
	var buf bytes.Buffer
	root := fleetctl.NewRootCommand(&buf)
	root.SetErr(&buf)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		return buf.String(), 1
	}
	return buf.String(), 0
}

// runAsync is run for a command a test must be able to give up waiting on. The
// environment is set on the test's own goroutine, because t.Setenv is not safe
// to call from anywhere else.
func runAsync(t *testing.T, configDir string, args ...string) <-chan string {
	t.Helper()
	t.Setenv("FLEET_CONFIG_DIR", configDir)
	done := make(chan string, 1)
	go func() {
		var out bytes.Buffer
		_ = fleetctl.Main(args, &out)
		done <- out.String()
	}()
	return done
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

// The listing must not show the token value in *any* output mode. The text
// table is the obvious one to check and the JSON document is the one that would
// actually leak, because a caller pipes it somewhere.
func TestEnrollList_NeverShowsTheTokenValue(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)

	minted, code := run(t, dir, "enroll", "mint", "--name", "build-box")
	require.Equal(t, 0, code, minted)
	token := tokenFrom(t, minted)
	require.NotEmpty(t, token)

	for _, args := range [][]string{
		{"enroll", "list"},
		{"enroll", "list", "--json"},
	} {
		out, code := run(t, dir, args...)
		require.Equal(t, 0, code, out)
		assert.NotContains(t, out, token, "%v leaked the token value", args)
		assert.NotContains(t, out, enroll.TokenPrefix, "%v printed something token-shaped", args)
		// The id is what identifies a token instead, and it must be there or
		// `enroll revoke` has nothing to take.
		assert.Contains(t, out, tokenIDFrom(t, minted))
	}
}

func TestEnrollList_JSONParses(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)
	_, code = run(t, dir, "enroll", "mint", "--name", "build-box",
		"--address", "build-box.internal:8722", "--label", "arch=arm64")
	require.Equal(t, 0, code)

	out, code := run(t, dir, "enroll", "list", "--json")
	require.Equal(t, 0, code, out)

	var doc struct {
		Tokens []struct {
			ID        string            `json:"id"`
			Name      string            `json:"name"`
			State     string            `json:"state"`
			ExpiresAt string            `json:"expires_at"`
			Addresses []string          `json:"addresses"`
			Labels    map[string]string `json:"labels"`
		} `json:"tokens"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc), "enroll list --json did not parse:\n%s", out)
	require.Len(t, doc.Tokens, 1)
	assert.Equal(t, "build-box", doc.Tokens[0].Name)
	assert.Equal(t, "pending", doc.Tokens[0].State)
	assert.NotEmpty(t, doc.Tokens[0].ID)
	assert.NotEmpty(t, doc.Tokens[0].ExpiresAt)
	assert.Equal(t, []string{"build-box.internal:8722"}, doc.Tokens[0].Addresses)
	assert.Equal(t, map[string]string{"arch": "arm64"}, doc.Tokens[0].Labels)
}

// The acceptance criterion in the issue: the mint output is directly pasteable
// and enrolls a host with no edits. So the assertion is on the assembled
// command, not on the fields it was assembled from.
func TestEnrollMint_PrintsAPasteableInstallCommand(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)

	out, code := run(t, dir, "enroll", "mint",
		"--name", "build-box",
		"--address", "build-box.internal:9000",
		"--control", "workstation.internal:9443")
	require.Equal(t, 0, code, out)

	token := tokenFrom(t, out)
	fingerprint := fingerprintOf(t, dir)

	command := installCommandFrom(t, out)
	assert.Contains(t, command, "--token "+token)
	assert.Contains(t, command, "--control workstation.internal:9443")
	assert.Contains(t, command, "--ca-fingerprint "+fingerprint)
	// The port the operator authorized, not the installer's default: a host
	// enrolled on 8722 when its token authorizes 9000 is one the control plane
	// will never reach.
	assert.Contains(t, command, "--listen 0.0.0.0:9000")
	// Nothing left for the operator to fill in.
	assert.NotContains(t, command, "<")
}

// Without --control there is still a complete command; it just names this
// machine, and says so, rather than leaving a placeholder.
func TestEnrollMint_GuessesTheControlAddressAndSaysSo(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)

	out, code := run(t, dir, "enroll", "mint", "--name", "build-box")
	require.Equal(t, 0, code, out)

	hostname, err := os.Hostname()
	require.NoError(t, err)
	assert.Contains(t, installCommandFrom(t, out), "--control "+hostname+":9443")
	assert.Contains(t, out, "--control was not given")
}

func TestEnrollMint_JSONParsesAndCarriesTheInstallCommand(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)

	out, code := run(t, dir, "enroll", "mint", "--name", "build-box",
		"--control", "workstation.internal:9443", "--json")
	require.Equal(t, 0, code, out)

	var doc struct {
		Token          string `json:"token"`
		TokenID        string `json:"token_id"`
		Name           string `json:"name"`
		CAFingerprint  string `json:"ca_fingerprint"`
		InstallCommand string `json:"install_command"`
		InstallWindows string `json:"install_command_windows"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc), "enroll mint --json did not parse:\n%s", out)
	assert.True(t, strings.HasPrefix(doc.Token, enroll.TokenPrefix))
	assert.Equal(t, "build-box", doc.Name)
	assert.Equal(t, fingerprintOf(t, dir), doc.CAFingerprint)
	assert.Contains(t, doc.InstallCommand, doc.Token)
	assert.Contains(t, doc.InstallWindows, doc.Token)
	assert.NotEmpty(t, doc.TokenID)
}

// A token minted without a CA would be unusable: `fleet-agent enroll` refuses
// to run without the fingerprint, so the operator would have burnt a mint and
// have to do it again.
func TestEnrollMint_BeforeCAInitNamesTheCommandToRun(t *testing.T) {
	out, code := runCapturingErrors(t, t.TempDir(), "enroll", "mint", "--name", "build-box")
	assert.NotEqual(t, 0, code)
	assert.Contains(t, out, "fleetctl ca init")
}

func TestCAFingerprint_BeforeCAInitNamesTheCommandToRun(t *testing.T) {
	out, code := runCapturingErrors(t, t.TempDir(), "ca", "fingerprint")
	assert.NotEqual(t, 0, code)
	assert.Contains(t, out, "fleetctl ca init")
}

func TestCAFingerprint_JSONParses(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)

	out, code := run(t, dir, "ca", "fingerprint", "--json")
	require.Equal(t, 0, code, out)

	var doc struct {
		Fingerprint string `json:"ca_fingerprint"`
		Rotating    bool   `json:"rotating"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc), "ca fingerprint --json did not parse:\n%s", out)
	assert.Equal(t, fingerprintOf(t, dir), doc.Fingerprint)
	assert.False(t, doc.Rotating)
}

func TestEnrollRevoke_InvalidatesAnUnusedToken(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)

	minted, code := run(t, dir, "enroll", "mint", "--name", "build-box")
	require.Equal(t, 0, code, minted)
	token, id := tokenFrom(t, minted), tokenIDFrom(t, minted)

	out, code := run(t, dir, "enroll", "revoke", id)
	require.Equal(t, 0, code, out)
	assert.Contains(t, out, id)

	// The token is dead where it matters: in the store the serving process
	// reads, which is a different process from the one that revoked it.
	store, err := enroll.OpenTokenStore(filepath.Join(dir, "enrollment-tokens.yaml"))
	require.NoError(t, err)
	_, err = store.Redeem(token)
	require.ErrorIs(t, err, enroll.ErrTokenRevoked)

	listed, code := run(t, dir, "enroll", "list")
	require.Equal(t, 0, code)
	assert.Contains(t, listed, "revoked")
}

func TestEnrollRevoke_UnknownIDFails(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)

	_, code = run(t, dir, "enroll", "revoke", "deadbeef")
	assert.NotEqual(t, 0, code)
}

// The three rotation steps as an operator runs them, through the CLI, with the
// property that matters asserted at each one.
func TestCARotate_StagesActivatesAndRetires(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)
	original := fingerprintOf(t, dir)

	staged, code := run(t, dir, "ca", "rotate")
	require.Equal(t, 0, code, staged)
	assert.Contains(t, staged, "ca.crt")
	assert.Contains(t, staged, "--activate")
	// Staging must not change who signs.
	assert.Equal(t, original, fingerprintOf(t, dir))

	activated, code := run(t, dir, "ca", "rotate", "--activate")
	require.Equal(t, 0, code, activated)
	rotated := fingerprintOf(t, dir)
	assert.NotEqual(t, original, rotated)

	// Mid-rotation, `ca fingerprint` says which root to pin and which are only
	// still trusted, because pinning the wrong one fails at enrollment time.
	mid, code := run(t, dir, "ca", "fingerprint", "--json")
	require.Equal(t, 0, code, mid)
	midDoc := fingerprintDoc(t, mid)
	assert.Equal(t, rotated, midDoc.Fingerprint)
	assert.True(t, midDoc.Rotating)
	assert.Equal(t, []string{original}, midDoc.AlsoTrusted)

	retired, code := run(t, dir, "ca", "rotate", "--retire")
	require.Equal(t, 0, code, retired)

	after, code := run(t, dir, "ca", "fingerprint", "--json")
	require.Equal(t, 0, code, after)
	afterDoc := fingerprintDoc(t, after)
	assert.Equal(t, rotated, afterDoc.Fingerprint)
	assert.False(t, afterDoc.Rotating)
	assert.Empty(t, afterDoc.AlsoTrusted)
}

// fingerprintDoc decodes `ca fingerprint --json` into a fresh value each time.
// Unmarshalling twice into one struct would leave an omitted also_trusted at
// whatever the previous decode put there, which is exactly the field these
// assertions turn on.
func fingerprintDoc(t *testing.T, out string) struct {
	Fingerprint string   `json:"ca_fingerprint"`
	Rotating    bool     `json:"rotating"`
	AlsoTrusted []string `json:"also_trusted"`
} {
	t.Helper()
	var doc struct {
		Fingerprint string   `json:"ca_fingerprint"`
		Rotating    bool     `json:"rotating"`
		AlsoTrusted []string `json:"also_trusted"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc), "ca fingerprint --json did not parse:\n%s", out)
	return doc
}

func TestCARotate_BeforeCAInitNamesTheCommandToRun(t *testing.T) {
	out, code := runCapturingErrors(t, t.TempDir(), "ca", "rotate")
	assert.NotEqual(t, 0, code)
	assert.Contains(t, out, "fleetctl ca init")
}

// The control leaf is what fleet-mcp and `fleetctl list` present to agents, and
// before this there was no command that produced one: `ca sign` demanded a CSR
// the operator had no way to make.
func TestCASign_GeneratesTheControlLeafWithoutACSR(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)

	out, code := run(t, dir, "ca", "sign", "--profile", "control")
	require.Equal(t, 0, code, out)

	certPEM, err := os.ReadFile(filepath.Join(dir, "control.crt"))
	require.NoError(t, err)
	keyPEM, err := os.ReadFile(filepath.Join(dir, "control.key"))
	require.NoError(t, err)

	authority, err := ca.Load(filepath.Join(dir, "ca"))
	require.NoError(t, err)
	leaf, err := authority.VerifyLeaf(certPEM, x509.ExtKeyUsageClientAuth)
	require.NoError(t, err)
	assert.Contains(t, leaf.Subject.OrganizationalUnit, ca.ProfileControl.OrganizationalUnit())

	// The pair has to be usable as a keypair, which is the failure a
	// certificate written beside somebody else's key would produce later.
	_, err = tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	info, err := os.Stat(filepath.Join(dir, "control.key"))
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "a private key must not be world-readable")
	}
}

// An agent's private key must never leave the host it identifies, so this
// convenience is deliberately unavailable for an agent leaf.
func TestCASign_RefusesToGenerateAnAgentKeypair(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)

	out, code := runCapturingErrors(t, dir, "ca", "sign", "--subject", "build-box")
	assert.NotEqual(t, 0, code)
	assert.Contains(t, out, "--csr is required")
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
	return fieldFrom(t, out, "token:")
}

func tokenIDFrom(t *testing.T, out string) string {
	t.Helper()
	return fieldFrom(t, out, "token-id:")
}

func fieldFrom(t *testing.T, out, prefix string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(line, prefix); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatalf("no %q line in output:\n%s", prefix, out)
	return ""
}

// installCommandFrom returns the shell block `enroll mint` printed, which is
// what the acceptance criterion is actually about.
func installCommandFrom(t *testing.T, out string) string {
	t.Helper()
	_, after, ok := strings.Cut(out, "Run this on the host, as-is:")
	require.True(t, ok, "no install command in output:\n%s", out)
	block, _, ok := strings.Cut(after, "\nWindows,")
	require.True(t, ok, "install command was not followed by the Windows form:\n%s", out)
	// The command is wrapped for reading; join it back into the single line a
	// shell would see, so an assertion about "--token X" is not defeated by the
	// continuation between them.
	return strings.Join(strings.Fields(strings.ReplaceAll(block, "\\\n", " ")), " ")
}

// fingerprintOf reads the CA's fingerprint straight from disk, so a test
// asserting that a command printed the right one is not comparing the command's
// output with itself.
func fingerprintOf(t *testing.T, configDir string) string {
	t.Helper()
	authority, err := ca.Load(filepath.Join(configDir, "ca"))
	require.NoError(t, err)
	return ca.FormatFingerprint(authority.Fingerprint())
}
