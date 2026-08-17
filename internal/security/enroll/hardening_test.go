package enroll_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/security/ca"
	"github.com/axelmierczuk/fleet-mcp/internal/security/enroll"
)

// enrollOnce runs one full enrollment against svc and returns the response.
func enrollOnce(t *testing.T, lis *bufconn.Listener, caObj *ca.CA, req *sandboxdv1.EnrollRequest) (*sandboxdv1.EnrollResponse, error) {
	t.Helper()
	cc := requireDialControlPlane(t, lis, caObj.Fingerprint())

	key, err := enroll.GenerateKey()
	require.NoError(t, err)
	csrDER, err := enroll.BuildCSR(key, req.GetRequestedName(), nil, nil)
	require.NoError(t, err)
	req.CsrDer = csrDER

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return sandboxdv1.NewEnrollmentServiceClient(cc).Enroll(ctx, req)
}

func leafOf(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return leaf
}

// The central impersonation check. A host holding one valid token asks to be
// certified for a different fleet member's name and address. If the control
// plane obliges, that host can present itself as prod-db to the MCP server for
// the leaf's whole 90-day life, and mTLS stops being worth anything.
func TestEnroll_RequestedAddressesCannotWidenTheCertificate(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{Tokens: tokens, CA: caObj}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint(enroll.MintOptions{
		Name:      "rogue-box",
		Addresses: []string{"rogue-box.internal:9443"},
	})
	require.NoError(t, err)

	_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{
		Token:           token,
		RequestedName:   "rogue-box",
		ListenAddresses: []string{"prod-db.internal:9443"},
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "not authorized")
}

func TestEnroll_WildcardAddressRejected(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{Tokens: tokens, CA: caObj}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint(enroll.MintOptions{
		Name:      "rogue-box",
		Addresses: []string{"rogue-box.internal:9443"},
	})
	require.NoError(t, err)

	_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{
		Token:           token,
		RequestedName:   "rogue-box",
		ListenAddresses: []string{"*.internal:9443"},
	})
	require.Error(t, err)
}

// The leaf carries what the operator authorized at mint time, and nothing the
// enrolling host added on its own.
func TestEnroll_LeafCarriesOnlyAuthorizedNames(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{Tokens: tokens, CA: caObj}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint(enroll.MintOptions{
		Name:      "build-box",
		Addresses: []string{"build-box.internal:9443", "10.0.0.5:9443"},
	})
	require.NoError(t, err)

	resp, err := enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{
		Token:           token,
		RequestedName:   "build-box",
		ListenAddresses: []string{"10.0.0.5:9443"},
	})
	require.NoError(t, err)

	leaf := leafOf(t, resp.GetCertificatePem())
	assert.ElementsMatch(t, []string{"build-box", "build-box.internal"}, leaf.DNSNames)
	require.Len(t, leaf.IPAddresses, 1)
	assert.Equal(t, "10.0.0.5", leaf.IPAddresses[0].String())

	pool := x509.NewCertPool()
	pool.AddCert(caObj.Certificate())
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "prod-db.internal",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	require.Error(t, err, "the issued leaf must not be usable to impersonate another fleet member")
}

// A token minted without --address still enrolls; it just yields a leaf naming
// only the sandbox, and says so rather than quietly certifying whatever the
// agent asked for.
func TestEnroll_TokenWithoutAddressesNamesOnlyTheSandbox(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{Tokens: tokens, CA: caObj}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	resp, err := enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{Token: token, RequestedName: "build-box"})
	require.NoError(t, err)
	assert.Equal(t, []string{"build-box"}, leafOf(t, resp.GetCertificatePem()).DNSNames)

	// And an address it did not authorize is refused with an error that says
	// what to do about it.
	token2, _, err := tokens.Mint(enroll.MintOptions{Name: "other-box"})
	require.NoError(t, err)
	_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{
		Token:           token2,
		RequestedName:   "other-box",
		ListenAddresses: []string{"10.0.0.9:9443"},
	})
	require.Error(t, err)
	assert.Contains(t, status.Convert(err).Message(), "--address")
}

// Loopback names the enrolling host and nothing else, so it cannot be used to
// impersonate a peer and does not need pre-authorization.
func TestEnroll_LoopbackIsAlwaysAllowed(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{Tokens: tokens, CA: caObj}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint(enroll.MintOptions{Name: "local-box"})
	require.NoError(t, err)

	resp, err := enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{
		Token:           token,
		RequestedName:   "local-box",
		ListenAddresses: []string{"127.0.0.1:9443"},
	})
	require.NoError(t, err)

	leaf := leafOf(t, resp.GetCertificatePem())
	require.Len(t, leaf.IPAddresses, 1)
	assert.Equal(t, "127.0.0.1", leaf.IPAddresses[0].String())
}

// The enrollment listener is the one endpoint reachable without a credential.
// Leaving it unbounded means an attacker who finds it can drive the CA's
// signing path as fast as the network allows.
func TestEnroll_RateLimited(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{
		Tokens:  tokens,
		CA:      caObj,
		Limiter: enroll.NewRateLimiter(time.Minute, 3, 0),
	}
	lis := startControlPlane(t, svc, caObj)

	var limited bool
	for i := 0; i < 5; i++ {
		_, err := enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{
			Token:         "sbx_definitely-not-a-real-token",
			RequestedName: "build-box",
		})
		require.Error(t, err)
		if status.Code(err) == codes.ResourceExhausted {
			limited = true
			break
		}
	}
	assert.True(t, limited, "repeated enrollment attempts must eventually be throttled")
}

func TestRateLimiter_GlobalAndPerPeer(t *testing.T) {
	perPeer := enroll.NewRateLimiter(time.Minute, 2, 0)
	require.NoError(t, perPeer.Allow("10.0.0.1"))
	require.NoError(t, perPeer.Allow("10.0.0.1"))
	require.ErrorIs(t, perPeer.Allow("10.0.0.1"), enroll.ErrRateLimited)
	// A different address has its own budget.
	require.NoError(t, perPeer.Allow("10.0.0.2"))

	// Which is why the global limit exists: per-peer counting alone is
	// defeated by an attacker holding more than one address.
	global := enroll.NewRateLimiter(time.Minute, 0, 2)
	require.NoError(t, global.Allow("10.0.0.1"))
	require.NoError(t, global.Allow("10.0.0.2"))
	require.ErrorIs(t, global.Allow("10.0.0.3"), enroll.ErrRateLimited)

	// A window that has elapsed frees the budget again.
	short := enroll.NewRateLimiter(20*time.Millisecond, 1, 0)
	require.NoError(t, short.Allow("10.0.0.1"))
	require.ErrorIs(t, short.Allow("10.0.0.1"), enroll.ErrRateLimited)
	time.Sleep(40 * time.Millisecond)
	require.NoError(t, short.Allow("10.0.0.1"))
}

// `sandboxctl enroll mint` and `sandboxctl serve` are separate processes, so a
// token that only exists in the minting process's memory can never be
// redeemed.
func TestTokenStore_PersistsAcrossProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.yaml")

	minter, err := enroll.OpenTokenStore(path)
	require.NoError(t, err)
	token, _, err := minter.Mint(enroll.MintOptions{Name: "build-box", Addresses: []string{"build-box:9443"}})
	require.NoError(t, err)

	// A second handle stands in for the serving process.
	server, err := enroll.OpenTokenStore(path)
	require.NoError(t, err)
	rec, err := server.Redeem(token)
	require.NoError(t, err)
	assert.Equal(t, "build-box", rec.Name)
	assert.Equal(t, []string{"build-box:9443"}, rec.Addresses)

	// And the redemption is visible to the minting handle too, so a token
	// spent by the server cannot be spent again elsewhere.
	_, err = minter.Redeem(token)
	require.ErrorIs(t, err, enroll.ErrTokenUsed)
}

func TestTokenStore_FileHoldsNoPlaintextToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.yaml")
	store, err := enroll.OpenTokenStore(path)
	require.NoError(t, err)
	token, _, err := store.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	data, err := readFileForTest(path)
	require.NoError(t, err)
	assert.NotContains(t, string(data), token, "the token store must hold only a hash")
}

// A control plane that runs for months mints a token per host it ever
// enrolls. Without pruning, the store only grows, and every redemption scans
// all of it.
func TestTokenStore_PrunesSpentTokens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.yaml")

	// Written directly rather than minted, because a token old enough to
	// prune cannot be produced through Mint — which is the point: only the
	// passage of real time gets a store into this state.
	old := time.Now().UTC().Add(-72 * time.Hour).Format(time.RFC3339)
	recent := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	seed := "version: 1\ntokens:\n" +
		tokenYAML("aaaa", "long-expired", old, old, false) +
		tokenYAML("bbbb", "recently-used", old, recent, true) +
		tokenYAML("cccc", "live", recent, time.Now().UTC().Add(time.Hour).Format(time.RFC3339), false)
	require.NoError(t, os.WriteFile(path, []byte(seed), 0o600))

	store, err := enroll.OpenTokenStore(path)
	require.NoError(t, err)
	records, err := store.List()
	require.NoError(t, err)

	names := make([]string, 0, len(records))
	for _, rec := range records {
		names = append(names, rec.Name)
	}
	// The long-expired one goes; the recently-used one stays, so replaying it
	// is still reported as "already used" rather than as unrecognized.
	assert.ElementsMatch(t, []string{"recently-used", "live"}, names)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "long-expired", "pruning must be persisted, not just filtered on read")
}

func tokenYAML(hash, name, issued, expiresOrUsed string, used bool) string {
	out := "  - hash: " + hash + "\n    record:\n      name: " + name +
		"\n      issued_at: " + issued + "\n"
	if used {
		out += "      expires_at: " + issued + "\n      used: true\n      used_at: " + expiresOrUsed + "\n"
	} else {
		out += "      expires_at: " + expiresOrUsed + "\n      used: false\n"
	}
	return out
}

// Pinning has to survive the control plane presenting a leaf rather than the
// CA itself — that is the whole point of the change, since it is what lets the
// CA private key stay out of the listener.
func TestDial_PinnedCAVerifiesAChainedLeaf(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{Tokens: tokens, CA: caObj}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{Token: token, RequestedName: "build-box"})
	require.NoError(t, err)
}

// An agent leaf is server-auth and signed by the same CA, so chain
// verification alone would accept it. The hostname check is what stops a
// compromised sandbox from standing up a fake enrollment endpoint and
// harvesting tokens from hosts that were told to trust this fleet's CA.
func TestDial_AgentLeafCannotImpersonateTheControlPlane(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{Tokens: tokens, CA: caObj}

	// Stand up an "enrollment endpoint" presenting an agent leaf for a
	// different name, chained to the real fleet CA.
	agentCert := agentServingCert(t, caObj, "rogue-box")
	lis := bufconn.Listen(1024 * 1024)
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{agentCert},
		MinVersion:   tls.VersionTLS12,
	})
	server := grpc.NewServer(grpc.Creds(creds))
	sandboxdv1.RegisterEnrollmentServiceServer(server, svc)
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)

	token, _, err := tokens.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{Token: token, RequestedName: "build-box"})
	require.Error(t, err)

	// The handshake failed, so the token never left the client.
	_, err = tokens.Redeem(token)
	require.NoError(t, err, "the token must not have been transmitted to the impostor")
}

func agentServingCert(t *testing.T, caObj *ca.CA, name string) tls.Certificate {
	t.Helper()
	key, err := enroll.GenerateKey()
	require.NoError(t, err)
	csrDER, err := enroll.BuildCSR(key, name, []string{name}, nil)
	require.NoError(t, err)
	leaf, certPEM, err := caObj.SignCSR(csrDER, ca.SignOptions{
		Profile:  ca.ProfileAgent,
		Subject:  name,
		DNSNames: []string{name},
	})
	require.NoError(t, err)
	keyPEM, err := enroll.MarshalKey(key)
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	cert.Leaf = leaf
	cert.Certificate = append(cert.Certificate, caObj.Certificate().Raw)
	return cert
}

// The registry entry is what reserves a name, so it is taken before the
// certificate is signed.
func TestEnroll_RecordsSandboxInFleet(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	rec := &recordingFleet{}
	svc := &enroll.Service{Tokens: tokens, CA: caObj, Fleet: rec}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint(enroll.MintOptions{
		Name:      "build-box",
		Labels:    map[string]string{"role": "build"},
		Addresses: []string{"build-box.internal:9443"},
	})
	require.NoError(t, err)

	_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{
		Token:         token,
		RequestedName: "build-box",
		AgentVersion:  "0.2.0",
		Platform: &sandboxdv1.Platform{
			Os:       "linux",
			Arch:     "arm64",
			Hostname: "build-box.lan",
		},
	})
	require.NoError(t, err)

	require.Len(t, rec.recorded, 1)
	got := rec.recorded[0]
	assert.Equal(t, "build-box", got.Name)
	assert.Equal(t, "build-box.internal:9443", got.Address)
	assert.Equal(t, "linux", got.OS)
	assert.Equal(t, "arm64", got.Arch)
	assert.Equal(t, "build-box.lan", got.Hostname)
	assert.Equal(t, "0.2.0", got.AgentVersion)
	assert.Equal(t, map[string]string{"role": "build"}, got.Labels)
}

type recordingFleet struct {
	recorded []enroll.EnrolledSandbox
}

func (r *recordingFleet) Record(sb enroll.EnrolledSandbox) error {
	r.recorded = append(r.recorded, sb)
	return nil
}

func readFileForTest(path string) ([]byte, error) { return os.ReadFile(path) }
