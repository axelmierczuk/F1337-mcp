package fleetctl_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
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

// The generated command's whole claim is that it can be pasted unedited, so an
// endpoint that would change how the installer parses its own arguments is
// refused where the operator can still see it. Single quotes stop a shell
// acting on a value; nothing stops "-x:9443" being read as a flag.
//
// And nothing may be minted on the way to that refusal: a token is single-use,
// so a mint that failed after recording one would cost the operator a token to
// learn about a typo.
func TestEnrollMint_RefusesAnEndpointTheInstallerWouldReadAsAFlag(t *testing.T) {
	for name, args := range map[string][]string{
		"control leading dash": {"--control", "-oProxyCommand=x:9443"},
		"control no port":      {"--control", "workstation.internal"},
		"control named port":   {"--control", "workstation.internal:https"},
		"listen leading dash":  {"--listen", "-x"},
		"listen named port":    {"--control", "workstation.internal:9443", "--listen", "0.0.0.0:agent"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			_, code := run(t, dir, "ca", "init")
			require.Equal(t, 0, code)

			out, code := runCapturingErrors(t, dir, append([]string{"enroll", "mint", "--name", "build-box"}, args...)...)
			require.NotEqual(t, 0, code, "mint accepted %v:\n%s", args, out)

			listed, code := run(t, dir, "enroll", "list")
			require.Equal(t, 0, code, listed)
			assert.Contains(t, listed, "no enrollment tokens", "a refused mint spent a token anyway:\n%s", listed)
		})
	}
}

// --name and --address are the two inputs that reach the certificate rather
// than the installer, and nothing checked either. Both become subject
// alternative names, and the CA refuses names it will not sign — in Enroll,
// which redeems the token before it signs anything, so the operator pays a
// single-use secret and reads the refusal on a host they have walked away from.
// Verified against the enrollment service: a token reserving "build box" comes
// back marked used with an InvalidArgument beside it.
//
// A port is the milder version and fails more quietly still: one
// net.SplitHostPort accepts and strconv does not sends the generated --listen
// back to the installer's 8722 without a word, standing the agent up on a port
// the control plane will never dial.
func TestEnrollMint_RefusesATokenThatCouldNotBeRedeemed(t *testing.T) {
	for label, args := range map[string][]string{
		"name with a space":               {"--name", "build box"},
		"name ending a label with a dash": {"--name", "build-box-"},
		"wildcard name":                   {"--name", "*box"},
		"address named port":              {"--name", "build-box", "--address", "build-box.internal:https"},
		"address port too large":          {"--name", "build-box", "--address", "build-box.internal:99999"},
		"address leading dash":            {"--name", "build-box", "--address", "-oProxyCommand=x:9000"},
		"address wildcard":                {"--name", "build-box", "--address", "*.internal:9000"},
		"address unsignable":              {"--name", "build-box", "--address", "x-.internal:9000"},
	} {
		t.Run(label, func(t *testing.T) {
			dir := t.TempDir()
			_, code := run(t, dir, "ca", "init")
			require.Equal(t, 0, code)

			out, code := runCapturingErrors(t, dir, append([]string{"enroll", "mint"}, args...)...)
			require.NotEqual(t, 0, code, "mint accepted %v:\n%s", args, out)

			listed, code := run(t, dir, "enroll", "list")
			require.Equal(t, 0, code, listed)
			assert.Contains(t, listed, "no enrollment tokens",
				"a refused mint spent a token anyway, which is the whole cost this check avoids:\n%s", listed)
		})
	}
}

// And more subject alternative names than the CA will put on one leaf, which
// fails the same way and is the one shape no single value is wrong in.
func TestEnrollMint_RefusesMoreAddressesThanALeafCanCarry(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)

	args := []string{"enroll", "mint", "--name", "build-box"}
	for i := range ca.MaxSANs + 1 {
		args = append(args, "--address", fmt.Sprintf("host-%d.internal:9000", i))
	}
	out, code := runCapturingErrors(t, dir, args...)
	require.NotEqual(t, 0, code, "mint accepted more names than a leaf can carry:\n%s", out)

	listed, code := run(t, dir, "enroll", "list")
	require.Equal(t, 0, code, listed)
	assert.Contains(t, listed, "no enrollment tokens")
}

// The shapes that are not malformed keep working. A bare host authorizes a name
// without claiming a port; a wildcard bind authorizes no name at all, which
// enrollment drops rather than refusing, so mint must not refuse it either.
func TestEnrollMint_AcceptsWhatEnrollmentWouldHonour(t *testing.T) {
	for label, args := range map[string][]string{
		"underscore in a name": {"--name", "build_box"},
		"dotted name":          {"--name", "gpu-01.internal"},
		"bare host":            {"--name", "build-box", "--address", "build-box.internal"},
		"host and port":        {"--name", "build-box", "--address", "build-box.internal:9000"},
		"ipv4":                 {"--name", "build-box", "--address", "10.0.0.5:9000"},
		"ipv6":                 {"--name", "build-box", "--address", "[::1]:9000"},
		"wildcard bind":        {"--name", "build-box", "--address", "0.0.0.0:9000"},
		"port only":            {"--name", "build-box", "--address", ":9000"},
	} {
		t.Run(label, func(t *testing.T) {
			dir := t.TempDir()
			_, code := run(t, dir, "ca", "init")
			require.Equal(t, 0, code)

			full := append([]string{"enroll", "mint", "--control", "workstation.internal:9443"}, args...)
			out, code := runCapturingErrors(t, dir, full...)
			require.Equal(t, 0, code, "mint refused %v:\n%s", args, out)
		})
	}
}

// The two tests above assert mint's verdict against a list this test wrote down.
// This one asserts it against the only authority on the question: what redemption
// actually does with the same name and addresses.
//
// The list is what drifted. Round 2 added mint's check to stop `--name` costing a
// single-use token, and re-derived the SAN set to do it — running the *name*
// through net.SplitHostPort as though it were an address. So `--name build:box`
// was checked as "build", passed, minted, and was refused at redemption as
// "build:box" once Redeem had already marked the token used. Two of the eight
// address shapes went the other way: `[::1]` and `[::]` were refused by mint and
// would have been honoured, because enrollment strips the brackets and mint did
// not. A check that answers a question differently from the code it is
// speaking for is not a check.
//
// So this compares the two directly. Mint runs through the CLI; redemption runs
// through enroll.Service against a token minted straight into a store, so the
// mint verdict cannot gate the comparison.
//
// The invariant is one-sided, and saying so is the point. Mint must never accept
// what redemption would refuse — that is the direction that spends a single-use
// secret and is discovered on a host the operator has walked away from. Mint may
// refuse what redemption would honour, and on one shape it deliberately does:
// --listen is derived from --address when the operator gave none, so an address
// whose port net.SplitHostPort accepts and strconv does not would otherwise send
// the pasted command back to the installer's 8722 without a word. Those cases
// carry mintOnlyRefuses, and the asymmetry is asserted rather than omitted, so
// that a shape quietly moving from one column to the other fails here.
//
// A sweep of every name in this table against twenty address shapes found no
// disagreement outside the mintOnlyRefuses column.
func TestEnrollMint_AgreesWithRedemptionOnWhatCanBeCertified(t *testing.T) {
	cases := []struct {
		label     string
		name      string
		addresses []string
		// mintOnlyRefuses marks a case mint refuses on grounds of its own,
		// before certifiability is at issue. Redemption honours it.
		mintOnlyRefuses bool
	}{
		{label: "name with a colon", name: "build:box"},
		{label: "name that looks like an endpoint", name: "gpu-01:9000"},
		{label: "name with a space", name: "build box"},
		{label: "wildcard name", name: "*box"},
		{label: "plain name", name: "build-box"},
		{label: "underscore in a name", name: "build_box"},
		{label: "dotted name", name: "gpu-01.internal"},
		{label: "bare host", name: "build-box", addresses: []string{"build-box.internal"}},
		{label: "host and port", name: "build-box", addresses: []string{"build-box.internal:9000"}},
		{label: "ipv4", name: "build-box", addresses: []string{"10.0.0.5:9000"}},
		{label: "bracketed ipv6 with a port", name: "build-box", addresses: []string{"[::1]:9000"}},
		{label: "bracketed ipv6 with no port", name: "build-box", addresses: []string{"[::1]"}},
		{label: "bracketed wildcard bind", name: "build-box", addresses: []string{"[::]"}},
		{label: "bare ipv6", name: "build-box", addresses: []string{"::1"}},
		{label: "wildcard bind", name: "build-box", addresses: []string{"0.0.0.0:9000"}},
		{label: "port only", name: "build-box", addresses: []string{":9000"}},
		{label: "wildcard address", name: "build-box", addresses: []string{"*.internal:9000"}},

		{label: "named port", name: "build-box", addresses: []string{"build-box.internal:https"}, mintOnlyRefuses: true},
		{label: "port zero", name: "build-box", addresses: []string{"build-box.internal:0"}, mintOnlyRefuses: true},
		{label: "port past the range", name: "build-box", addresses: []string{"build-box.internal:65536"}, mintOnlyRefuses: true},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			dir := t.TempDir()
			_, code := run(t, dir, "ca", "init")
			require.Equal(t, 0, code)

			args := []string{"enroll", "mint", "--control", "workstation.internal:9443", "--name", tc.name}
			for _, addr := range tc.addresses {
				args = append(args, "--address", addr)
			}
			mintOut, mintCode := runCapturingErrors(t, dir, args...)

			redeemErr := redeemThroughEnrollment(t, dir, tc.name, tc.addresses)

			if tc.mintOnlyRefuses {
				assert.NotEqual(t, 0, mintCode, "mint was expected to refuse this on its own grounds:\n%s", mintOut)
				assert.NoError(t, redeemErr, "this shape is one redemption honours; only mint refuses it")
			} else {
				assert.Equal(t, redeemErr == nil, mintCode == 0,
					"mint and redemption disagree about --name %q --address %v\nmint: %s\nredemption: %v",
					tc.name, tc.addresses, mintOut, redeemErr)
			}

			// Whichever column it is in, a mint that was refused must not have
			// cost a token: that is the whole reason the check is at mint time.
			if mintCode != 0 {
				listed, code := run(t, dir, "enroll", "list")
				require.Equal(t, 0, code, listed)
				assert.Contains(t, listed, "no enrollment tokens",
					"a refused mint spent a token anyway:\n%s", listed)
			}
		})
	}
}

// redeemThroughEnrollment asks the real enrollment service to redeem a token
// reserving name and authorizing addresses, and returns what it said. The token
// is minted into an in-memory store rather than by the CLI, so what mint decided
// does not decide what this observes.
func redeemThroughEnrollment(t *testing.T, configDir, name string, addresses []string) error {
	t.Helper()
	authority, err := ca.Load(filepath.Join(configDir, "ca"))
	require.NoError(t, err)

	store := enroll.NewTokenStore()
	token, _, err := store.Mint(enroll.MintOptions{Name: name, Addresses: addresses})
	require.NoError(t, err)

	key, err := enroll.GenerateKey()
	require.NoError(t, err)
	csrDER, err := enroll.BuildCSR(key, name, nil, nil)
	require.NoError(t, err)

	svc := &enroll.Service{Tokens: store, CA: authority}
	_, err = svc.Enroll(context.Background(), &sandboxdv1.EnrollRequest{
		Token:         token,
		RequestedName: name,
		CsrDer:        csrDER,
	})
	return err
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

// "retired" counts roots this step dropped, so only a retirement can be
// non-zero. Reading it as a difference in superseded roots across any step made
// --activate report -1: activating *gains* a superseded root, because the
// outgoing issuer becomes one.
func TestCARotate_OnlyARetirementReportsARetirement(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)

	retiredIn := func(out string) int {
		t.Helper()
		var doc struct {
			Step    string `json:"step"`
			Retired int    `json:"retired"`
		}
		require.NoError(t, json.Unmarshal([]byte(out), &doc), "ca rotate --json did not parse:\n%s", out)
		return doc.Retired
	}

	staged, code := run(t, dir, "ca", "rotate", "--json")
	require.Equal(t, 0, code, staged)
	assert.Equal(t, 0, retiredIn(staged), "staging retires nothing")

	activated, code := run(t, dir, "ca", "rotate", "--activate", "--json")
	require.Equal(t, 0, code, activated)
	assert.Equal(t, 0, retiredIn(activated), "activating retires nothing; it supersedes the outgoing root")

	retired, code := run(t, dir, "ca", "rotate", "--retire", "--json")
	require.Equal(t, 0, code, retired)
	assert.Equal(t, 1, retiredIn(retired), "retiring dropped the one superseded root")

	again, code := run(t, dir, "ca", "rotate", "--retire", "--json")
	require.Equal(t, 0, code, again)
	assert.Equal(t, 0, retiredIn(again), "a retirement with nothing to drop retires nothing")
}

// Activate writes the incoming key and then the widened bundle, and a crash
// between them leaves the pair Load refuses. ca.Activate was taught to read the
// trust bundle directly so that re-running it finishes the job — but the
// command an operator actually types loaded the CA before dispatching to any
// step, so the repair stayed behind the damage and the CA directory still had
// no way back short of editing it by hand. A library that can recover and a CLI
// that cannot reach the recovery is the same outage.
func TestCARotate_ActivateFinishesAnInterruptedActivation(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)
	original := fingerprintOf(t, dir)

	staged, code := run(t, dir, "ca", "rotate")
	require.Equal(t, 0, code, staged)

	// The crash.
	caDir := filepath.Join(dir, "ca")
	nextKey, err := os.ReadFile(filepath.Join(caDir, "ca-next.key"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(caDir, "ca.key"), nextKey, 0o600))
	_, err = ca.Load(caDir)
	require.Error(t, err, "the fixture is only meaningful if this state is one Load rejects")

	out, code := runCapturingErrors(t, dir, "ca", "rotate", "--activate")
	require.Equal(t, 0, code, "the one command that can finish the activation could not run:\n%s", out)

	// And the directory is whole again for the commands that go through Load —
	// which, in this CLI, is all the ones that matter.
	rotated := fingerprintOf(t, dir)
	assert.NotEqual(t, original, rotated)
	fingerprint, code := run(t, dir, "ca", "fingerprint")
	require.Equal(t, 0, code, fingerprint)
	assert.Contains(t, fingerprint, rotated)
}

// The other half of that: the commands that cannot repair the state must still
// say what does. Every one of them reaches the operator through Load.
func TestCommands_NameTheRepairAfterAnInterruptedActivation(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)
	_, code = run(t, dir, "ca", "rotate")
	require.Equal(t, 0, code)

	caDir := filepath.Join(dir, "ca")
	nextKey, err := os.ReadFile(filepath.Join(caDir, "ca-next.key"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(caDir, "ca.key"), nextKey, 0o600))

	for _, args := range [][]string{
		{"ca", "fingerprint"},
		{"enroll", "mint", "--name", "build-box"},
		{"ca", "rotate", "--retire"},
	} {
		out, code := runCapturingErrors(t, dir, args...)
		require.NotEqual(t, 0, code, "%v should not have run against a half-activated CA:\n%s", args, out)
		assert.Contains(t, out, "ca rotate --activate", "%v left the operator with no way forward", args)
	}
}

// A --activate against a directory that holds no CA at all is still answered
// with the command that makes one, not with a rotation error. Reading the state
// without loading the CA is what makes the repair reachable; it must not cost
// the message every other command gives.
func TestCARotate_ActivateBeforeCAInitNamesTheCommandToRun(t *testing.T) {
	out, code := runCapturingErrors(t, t.TempDir(), "ca", "rotate", "--activate")
	assert.NotEqual(t, 0, code)
	assert.Contains(t, out, "fleetctl ca init")
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

// Re-issuing over an existing control.key has to leave 0600 behind, not the
// mode the file already had. os.WriteFile applies its mode only when it creates
// the file, so a key that something had left readable — a restored backup, an
// rsync without -p — was overwritten with a fresh secret at the old permissions
// and reported as written.
func TestCASign_TightensAControlKeyThatWasLeftReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)
	_, code = run(t, dir, "ca", "sign", "--profile", "control")
	require.Equal(t, 0, code)

	keyPath := filepath.Join(dir, "control.key")
	require.NoError(t, os.Chmod(keyPath, 0o644))

	out, code := run(t, dir, "ca", "sign", "--profile", "control")
	require.Equal(t, 0, code, out)

	info, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"re-issuing wrote a private key into permissions it found rather than the ones it promises")
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

// The keypair generation is reachable for exactly one profile string. Anything
// that is not literally "control" has to end without a key being written —
// whether it names the agent profile outright or arrives in a spelling somebody
// hoped would be folded into one.
//
// The refusal is written as "not the control profile" rather than as a list of
// what to reject, so this asserts the shape rather than the list: an unknown
// profile is refused at parse, and the only profile that reaches the generator
// is the one whose key belongs on this machine anyway.
func TestCASign_GeneratesAKeypairForNoProfileButControl(t *testing.T) {
	for _, profile := range []string{"agent", "Agent", "AGENT", "control-plane", "Control", "CONTROL", "", " control"} {
		t.Run("profile="+profile, func(t *testing.T) {
			dir := t.TempDir()
			_, code := run(t, dir, "ca", "init")
			require.Equal(t, 0, code)

			out, code := runCapturingErrors(t, dir, "ca", "sign", "--profile", profile, "--subject", "build-box")
			require.NotEqual(t, 0, code, "--profile %q produced a keypair:\n%s", profile, out)

			for _, name := range []string{"control.key", "build-box.key"} {
				_, err := os.Stat(filepath.Join(dir, name))
				assert.True(t, os.IsNotExist(err), "--profile %q wrote %s", profile, name)
			}
		})
	}
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

// The subject of an agent leaf is a name, not an endpoint, and it was being run
// through net.SplitHostPort as though it were one. `--subject build:box` split
// into host "build" and port "box", and the leaf came back naming "build" —
// which may well be another fleet member. The operator asked for one identity
// and silently got a different one, reported as success.
//
// A colon in a name is a mistake either way. Refusing it is the correct outcome;
// issuing a certificate for a name nobody typed is not.
func TestCASign_DoesNotSilentlyTruncateASubjectAtAColon(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)

	key, err := enroll.GenerateKey()
	require.NoError(t, err)
	csrDER, err := enroll.BuildCSR(key, "build:box", nil, nil)
	require.NoError(t, err)
	csrPath := filepath.Join(dir, "build.csr")
	require.NoError(t, os.WriteFile(csrPath, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrDER,
	}), 0o600))

	certPath := filepath.Join(dir, "build.crt")
	out, code := runCapturingErrors(t, dir, "ca", "sign",
		"--csr", csrPath, "--subject", "build:box", "--out", certPath)
	require.NotEqual(t, 0, code, "signed a leaf for a subject the CA will not certify:\n%s", out)

	// And nothing was written, so there is no leaf naming "build" on disk for a
	// later step to pick up and trust.
	_, statErr := os.Stat(certPath)
	assert.True(t, os.IsNotExist(statErr), "a refused sign left a certificate at %s", certPath)
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

// failingWriter is standard output that has gone away — a closed pipe, a full
// disk. cli.Printer records the first such failure and the command reports it,
// which is right; what it must not do is leave the socket it had already opened
// bound on the way out.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("no space left on device") }

// serve opens its listener before it prints its banner, so a banner that cannot
// be written returns from a function holding an open listening socket. In the
// binary the process exits and the kernel cleans up; in the shell that drives
// this through MainContext it does not, and the port stays bound for the life
// of that process.
func TestServe_ReleasesTheListenerWhenItCannotPrintItsBanner(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)

	// A port this test holds, then releases, so the address is known to be free
	// and serve is the only thing that could still be holding it afterwards.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := probe.Addr().String()
	require.NoError(t, probe.Close())

	t.Setenv("FLEET_CONFIG_DIR", dir)
	root := fleetctl.NewRootCommand(failingWriter{})
	root.SetErr(io.Discard)
	root.SetArgs([]string{"serve", "--listen", address, "--advertise", "127.0.0.1"})
	require.Error(t, root.Execute(), "a banner that could not be written must fail the command")

	again, err := net.Listen("tcp", address)
	require.NoError(t, err, "serve returned still holding %s", address)
	require.NoError(t, again.Close())
}

// serve starts a watcher that stops the server when the context is cancelled,
// then starts the server. A cancellation landing between the two — a Ctrl-C in
// serve's first instant, or a shell driving it through MainContext and changing
// its mind — reaches GracefulStop before Serve reaches its accept loop, and
// Serve then returns ErrServerStopped. That is the command being asked to stop,
// not a failure to serve, and reporting it as one made the exit code depend on
// which side of a mutex won.
//
// This used to be a 500-iteration loop, on the theory that the window was small
// but reachable. Measured, it was reached 0.12% of the time — so the loop caught
// its own regression under half the time it ran, and "confirmed to fail with the
// fix reverted" had been confirmed once, by luck. serve now waits for the
// watcher when it finds the context already cancelled, rather than racing it, so
// Serve always finds the server stopped and always returns ErrServerStopped.
//
// Which is what makes one iteration worth more than five hundred were, and it is
// worth being exact about whose regression this catches. It is the
// ErrServerStopped branch's — round 2's fix. Reverting that branch fails this
// test 50 times in 50 while the ordering guard is in place, and 0 times in 50
// without it, because without the guard the accept loop opens first and Serve
// returns nil from it instead. The guard is what turned a branch reached by one
// run in a thousand into one reached by every run.
//
// The guard's own regression is caught by the test below, not by this one:
// removing it leaves this test passing every time, since both paths still exit
// zero.
func TestServe_ExitsCleanlyWhenStoppedBeforeItStartsServing(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)
	t.Setenv("FLEET_CONFIG_DIR", dir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	code = fleetctl.MainContext(ctx, []string{
		"serve", "--listen", "127.0.0.1:0", "--advertise", "127.0.0.1",
	}, &out)
	require.Equal(t, 0, code, "a serve that was told to stop reported a failure:\n%s", out.String())
}

// The reason the ordering guard is worth having beyond testability: this
// endpoint is the one an unauthenticated caller can reach, so a serve that was
// cancelled before it began must not accept anything at all. Without the guard
// it opened the accept loop first and drained it a moment later, ~999 runs in
// 1000.
//
// Catching that requires observing serve *while* it runs, and the version of
// this test that shipped with the guard did not: it dialled the port after
// MainContext had returned, when nothing is listening either way. Measured, it
// passed 100 times in 100 with the guard removed — a test for a fix that would
// not have noticed the fix being deleted, which is the shape the previous three
// audit rounds each found once.
//
// So serve is caught in the act instead. Its banner is written to a gate that
// blocks the first write, which holds it after net.Listen and before it decides
// whether to serve: the port is open, and callers can queue in the kernel's
// accept backlog. Releasing the gate then decides it. With the guard, those
// callers are never accepted and the listener closes under them. Without it,
// the accept loop opens, takes them, and speaks TLS to at least one.
//
// One round of that is not enough on its own: gRPC's connection handler bails
// if GracefulStop has already fired, so a caller is served on about half of the
// runs that open the accept loop — measured at 51 in 100 with 16 callers, and
// no better with 64. It is one-sided, though. A handshake can only complete if
// something accepted it, so the guard never makes this fail: 40 runs in 40 clean
// with it in place. Rounds therefore only add catching power, and serveProbeRounds
// of them puts the chance of missing a deleted guard at about one in four
// thousand.
const serveProbeRounds = 12

// serveProbeCallers queue in the accept backlog while serve is held at its
// banner.
const serveProbeCallers = 16

// bannerGate blocks serve's first write until it is released, and reports when
// serve has reached it.
type bannerGate struct {
	once     sync.Once
	reached  chan struct{}
	released chan struct{}
}

func newBannerGate() *bannerGate {
	return &bannerGate{reached: make(chan struct{}), released: make(chan struct{})}
}

func (g *bannerGate) Write(p []byte) (int, error) {
	g.once.Do(func() {
		close(g.reached)
		<-g.released
	})
	return len(p), nil
}

func TestServe_AcceptsNothingWhenCancelledBeforeItStarts(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)
	t.Setenv("FLEET_CONFIG_DIR", dir)

	for round := 0; round < serveProbeRounds; round++ {
		// A fixed port, so the callers below queue on the socket serve was
		// given rather than on whatever the kernel hands out afterwards.
		addr := "127.0.0.1:" + freeTCPPort(t)
		gate := newBannerGate()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		exited := make(chan int, 1)
		go func() {
			exited <- fleetctl.MainContext(ctx, []string{
				"serve", "--listen", addr, "--advertise", "127.0.0.1",
			}, gate)
		}()

		select {
		case <-gate.reached:
		case <-time.After(20 * time.Second):
			t.Fatalf("round %d: serve never reached its banner", round)
		}

		callers := make([]net.Conn, 0, serveProbeCallers)
		for i := 0; i < serveProbeCallers; i++ {
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			require.NoError(t, err, "round %d: the port was not open while the banner was held", round)
			callers = append(callers, conn)
		}

		var (
			wg     sync.WaitGroup
			served atomic.Bool
		)
		for _, conn := range callers {
			wg.Add(1)
			go func(conn net.Conn) {
				defer wg.Done()
				<-gate.released
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				//nolint:gosec // this is a caller that must never be answered, not one verifying anything
				tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
				if tc.HandshakeContext(context.Background()) == nil {
					served.Store(true)
				}
				_ = conn.Close()
			}(conn)
		}

		close(gate.released)
		wg.Wait()

		select {
		case c := <-exited:
			require.Equal(t, 0, c, "round %d", round)
		case <-time.After(20 * time.Second):
			t.Fatalf("round %d: a cancelled serve never returned", round)
		}

		require.False(t, served.Load(),
			"round %d: a serve cancelled before it began completed a TLS handshake with a caller waiting on its listener", round)
	}
}

// Re-issuing writes the leaf beside the key, and the two are read as a pair.
// os.WriteFile truncates before it writes and applies its mode only on create,
// so the certificate half was neither atomic nor written at the mode this
// command promises — while the key half beside it was both.
func TestCASign_ReplacesAControlCertificateWholeAndAtItsOwnMode(t *testing.T) {
	dir := t.TempDir()
	_, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code)
	_, code = run(t, dir, "ca", "sign", "--profile", "control")
	require.Equal(t, 0, code)

	certPath := filepath.Join(dir, "control.crt")
	require.NoError(t, os.Chmod(certPath, 0o600))

	out, code := run(t, dir, "ca", "sign", "--profile", "control")
	require.Equal(t, 0, code, out)

	// A complete certificate, and one that still pairs with the key written
	// beside it in the same command.
	certPEM, err := os.ReadFile(certPath)
	require.NoError(t, err)
	keyPEM, err := os.ReadFile(filepath.Join(dir, "control.key"))
	require.NoError(t, err)
	_, err = tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	if runtime.GOOS != "windows" {
		info, err := os.Stat(certPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o644), info.Mode().Perm(),
			"re-issuing kept the mode it found rather than the one it writes")
	}
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
