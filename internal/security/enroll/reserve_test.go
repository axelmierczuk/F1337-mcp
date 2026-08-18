package enroll_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/security/ca"
	"github.com/axelmierczuk/fleet-mcp/internal/security/enroll"
)

// The registry entry is what reserves a name, and it cannot be taken back. So
// everything that can reject a request has to run before it — all of it, not
// most of it.
//
// Round 2 split ca.CheckCSR out of SignCSR for exactly this and moved it ahead
// of the write, then left the other half of SignCSR's validation, the subject
// alternative name check, where it was. A request whose SANs the CA refuses
// therefore still created a fleet member: token spent, registry entry written,
// no certificate, and a name nobody can now enroll under.
//
// Distinct loopback addresses are the reachable way in, because loopback is the
// one class of address an enrolling host may add on its own, and 127.0.0.0/8
// has sixteen million of them.
func TestEnroll_SANsRejectedByTheCARecordNothing(t *testing.T) {
	t.Parallel()
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	fleet := &recordingFleet{}
	svc := &enroll.Service{Tokens: tokens, CA: caObj, Fleet: fleet}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	// More distinct loopback addresses than ca.MaxSANs, so the SAN set the CA
	// is asked to sign is one it refuses.
	addrs := make([]string, 0, ca.MaxSANs+4)
	for i := 1; i <= ca.MaxSANs+4; i++ {
		addrs = append(addrs, fmt.Sprintf("127.0.0.%d:9443", i))
	}

	_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{
		Token:           token,
		RequestedName:   "build-box",
		ListenAddresses: addrs,
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err),
		"too many SANs is the caller's mistake, so it should be reported as one")
	assert.Empty(t, fleet.recorded,
		"a request the CA will refuse to sign must not leave a fleet member behind")
}

// The same ordering, reached through the operator's own input rather than the
// caller's: a token minted for a name the CA cannot put in a certificate.
func TestEnroll_UncertifiableReservedNameRecordsNothing(t *testing.T) {
	t.Parallel()
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	fleet := &recordingFleet{}
	svc := &enroll.Service{Tokens: tokens, CA: caObj, Fleet: fleet}
	lis := startControlPlane(t, svc, caObj)

	// A wildcard is the name the CA refuses hardest, and nothing stops an
	// operator typing one into `enroll mint --name`.
	token, _, err := tokens.Mint(enroll.MintOptions{Name: "*.internal"})
	require.NoError(t, err)

	_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{Token: token})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Empty(t, fleet.recorded)
}

// Collision resolution picks the name, so it is the resolved name — not the
// one on the token — whose certifiability decides whether the record is taken.
// A label one character under the DNS limit fits; the same label with the "-2"
// a collision appends does not.
func TestEnroll_UncertifiableCollisionNameRecordsNothing(t *testing.T) {
	t.Parallel()
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	fleet := &recordingFleet{}
	longName := strings.Repeat("a", 63)
	svc := &enroll.Service{
		Tokens: tokens,
		CA:     caObj,
		Names:  fakeNameChecker{existing: map[string]bool{longName: true}},
		Fleet:  fleet,
	}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint(enroll.MintOptions{Name: longName})
	require.NoError(t, err)

	_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{Token: token})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Empty(t, fleet.recorded,
		"the name collision resolution settled on is the one that has to be certifiable")
}

// The other end of the same question, which round 3 recorded as left open: the
// "-N" a collision appends overshoots maxNameLength, so a caller-chosen name at
// the 128-byte limit becomes a 130-byte one. That is only harmless for as long
// as a caller-chosen name reaches nothing but the registry key — a registry key
// is a YAML value with no length rule and no path component built from it.
//
// This asserts the premise rather than trusting it. The day a caller-chosen name
// starts reaching the leaf again — which is the exact defect rounds 1, 2 and 3
// each found once — the overshoot stops being harmless, and this fails.
func TestEnroll_OvershotCollisionNameReachesNoCertificate(t *testing.T) {
	t.Parallel()
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	fleet := &recordingFleet{}
	base := strings.Repeat("a", 128) // exactly the bound checkRequestedName allows
	svc := &enroll.Service{
		Tokens: tokens,
		CA:     caObj,
		Names:  fakeNameChecker{existing: map[string]bool{base: true}},
		Fleet:  fleet,
	}
	lis := startControlPlane(t, svc, caObj)

	// A token reserving no name: the enrolling host picks its own label, which
	// is the only way a caller-controlled string reaches collision resolution.
	token, _, err := tokens.Mint(enroll.MintOptions{})
	require.NoError(t, err)

	resp, err := enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{Token: token, RequestedName: base})
	require.NoError(t, err)

	assert.Len(t, resp.GetAssignedName(), 130, "the collision suffix overshoots the 128-byte bound")
	require.Len(t, fleet.recorded, 1)
	assert.Equal(t, resp.GetAssignedName(), fleet.recorded[0].Name,
		"the overshoot lands in the registry key, which has no length rule")

	leaf := leafOf(t, resp.GetCertificatePem())
	assert.Empty(t, leaf.Subject.CommonName, "a name this side did not choose is not a subject")
	assert.Empty(t, leaf.DNSNames, "a name this side did not choose is not a SAN")
	assert.Empty(t, leaf.IPAddresses)
}

// brokenSigner stands in for a control plane whose CA is unusable — a
// certificate beside a key from a different CA is the way that happens in
// practice. It still hands out a bundle, because the failure is in signing.
type brokenSigner struct{ bundle []byte }

func (b brokenSigner) SignCSR([]byte, ca.SignOptions) (*x509.Certificate, []byte, error) {
	return nil, nil, errors.New("ca: sign leaf certificate: x509: provided PrivateKey doesn't match parent's PublicKey")
}

func (b brokenSigner) CertPEM() []byte { return b.bundle }

// Once every caller-attributable check runs before the registry write, a
// failure at the signing step is the control plane's own. Reporting it as
// InvalidArgument tells an unauthenticated caller its request was malformed
// when it was not, and hands it the control plane's internal detail on the way.
func TestEnroll_SigningFailureIsNotBlamedOnTheCaller(t *testing.T) {
	t.Parallel()
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{Tokens: tokens, CA: brokenSigner{bundle: caObj.CertPEM()}}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{Token: token})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code(),
		"a broken CA is not the enrolling host's fault")
	assert.NotContains(t, st.Message(), "PrivateKey",
		"the control plane's own failure detail must not reach an unauthenticated caller")
}

// The CSR is caller-controlled too, and it is the one input that already
// carries a subject and a set of subject alternative names. Nothing in it is
// copied into the leaf but the public key: the leaf's template is built from
// what the token authorized, not from what the request asked for.
//
// This has always been true, and there is no test that says so — which is the
// same shape of gap that let the subject through. It is asserted here so that a
// later change to SignCSR that "helpfully" carries CSR names over is caught.
func TestEnroll_CSRContentsDoNotReachTheLeaf(t *testing.T) {
	t.Parallel()
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{Tokens: tokens, CA: caObj}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint(enroll.MintOptions{
		Name:      "build-box",
		Addresses: []string{"10.0.0.5:9443"},
	})
	require.NoError(t, err)

	// A CSR asking for everything the token does not authorize.
	key, err := enroll.GenerateKey()
	require.NoError(t, err)
	csrDER, err := enroll.BuildCSR(key, controlPlaneHost,
		[]string{"prod-db.internal", controlPlaneHost},
		[]net.IP{net.ParseIP("10.0.0.9")})
	require.NoError(t, err)

	cc := requireDialControlPlane(t, lis, caObj.Fingerprint())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := sandboxdv1.NewEnrollmentServiceClient(cc).Enroll(ctx, &sandboxdv1.EnrollRequest{
		Token:  token,
		CsrDer: csrDER,
	})
	require.NoError(t, err)

	leaf := leafOf(t, resp.GetCertificatePem())
	assert.Equal(t, "build-box", leaf.Subject.CommonName, "the CSR's subject is not the leaf's")
	assert.Equal(t, []string{"build-box"}, leaf.DNSNames)
	require.Len(t, leaf.IPAddresses, 1)
	assert.Equal(t, "10.0.0.5", leaf.IPAddresses[0].String())
	assert.Equal(t, key.PublicKey, *leaf.PublicKey.(*ecdsa.PublicKey),
		"the public key is the one thing the CSR does decide")
}

// A bracketed IPv6 literal without a port is a form net.SplitHostPort rejects.
// Left bracketed it reached the certificate as a DNS name, which the CA then
// refused — after the registry entry had been written.
func TestEnroll_BareBracketedIPv6LoopbackIsCertified(t *testing.T) {
	t.Parallel()
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	fleet := &recordingFleet{}
	svc := &enroll.Service{Tokens: tokens, CA: caObj, Fleet: fleet}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint(enroll.MintOptions{Name: "v6-box", Addresses: []string{"[::1]"}})
	require.NoError(t, err)

	resp, err := enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{Token: token})
	require.NoError(t, err)

	leaf := leafOf(t, resp.GetCertificatePem())
	require.Len(t, leaf.IPAddresses, 1)
	assert.Equal(t, "::1", leaf.IPAddresses[0].String())
	assert.NotContains(t, leaf.DNSNames, "[::1]")
}
