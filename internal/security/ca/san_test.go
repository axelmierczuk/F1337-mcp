package ca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/security/ca"
)

func csrFor(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	require.NoError(t, err)
	return der
}

// A wildcard SAN answers to every name in a domain. Signing one turns a single
// leaf into blanket authority over the fleet's namespace, so the CA refuses
// regardless of who asked.
func TestSignCSR_RejectsWildcardSAN(t *testing.T) {
	authority := newCA(t)
	_, _, err := authority.SignCSR(csrFor(t, "build-box"), ca.SignOptions{
		Profile:  ca.ProfileAgent,
		Subject:  "build-box",
		DNSNames: []string{"*.internal"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wildcard")
}

func TestSignCSR_RejectsMalformedSANs(t *testing.T) {
	authority := newCA(t)
	cases := map[string][]string{
		"empty":          {""},
		"empty label":    {"build..internal"},
		"leading hyphen": {"-build.internal"},
		"bad character":  {"build box.internal"},
		"long label":     {strings.Repeat("a", 64) + ".internal"},
	}
	for name, dnsNames := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := authority.SignCSR(csrFor(t, "build-box"), ca.SignOptions{
				Profile:  ca.ProfileAgent,
				Subject:  "build-box",
				DNSNames: dnsNames,
			})
			require.Error(t, err)
		})
	}
}

func TestSignCSR_RejectsUnspecifiedIPSAN(t *testing.T) {
	authority := newCA(t)
	_, _, err := authority.SignCSR(csrFor(t, "build-box"), ca.SignOptions{
		Profile:     ca.ProfileAgent,
		Subject:     "build-box",
		IPAddresses: []net.IP{net.ParseIP("0.0.0.0")},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unspecified")
}

func TestSignCSR_RejectsTooManySANs(t *testing.T) {
	authority := newCA(t)
	names := make([]string, ca.MaxSANs+1)
	for i := range names {
		names[i] = "host" + string(rune('a'+i%26)) + ".internal"
	}
	_, _, err := authority.SignCSR(csrFor(t, "build-box"), ca.SignOptions{
		Profile:  ca.ProfileAgent,
		Subject:  "build-box",
		DNSNames: names,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too many")
}

func TestSignCSR_AcceptsOrdinaryNames(t *testing.T) {
	authority := newCA(t)
	leaf, _, err := authority.SignCSR(csrFor(t, "build-box"), ca.SignOptions{
		Profile:     ca.ProfileAgent,
		Subject:     "build-box",
		DNSNames:    []string{"build-box", "build-box.fleet.internal", "trailing-dot.internal."},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.5"), net.ParseIP("127.0.0.1")},
	})
	require.NoError(t, err)
	assert.Len(t, leaf.DNSNames, 3)
	assert.Len(t, leaf.IPAddresses, 2)
}

// The control plane's own serving leaf is server-auth like an agent's, but
// carries its own OU so the two are never mistaken for one another.
func TestSignCSR_ControlPlaneProfile(t *testing.T) {
	authority := newCA(t)
	leaf, certPEM, err := authority.SignCSR(csrFor(t, "control"), ca.SignOptions{
		Profile:  ca.ProfileControlPlane,
		Subject:  "sandboxd control plane",
		DNSNames: []string{"control.internal"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"sandboxd-control-plane"}, leaf.Subject.OrganizationalUnit)

	_, err = authority.VerifyLeaf(certPEM, x509.ExtKeyUsageServerAuth)
	require.NoError(t, err)

	_, err = authority.VerifyLeaf(certPEM, x509.ExtKeyUsageClientAuth)
	require.Error(t, err, "a control plane serving leaf must not double as a client certificate")
}

// A directory holding a key but no certificate is a half-restored backup or an
// interrupted init. Overwriting the key there destroys the CA just as
// thoroughly as overwriting a complete one.
func TestInit_RefusesWhenOnlyTheKeyExists(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	_, err := ca.Init(dir, false)
	require.NoError(t, err)

	keyBefore, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	require.NoError(t, err)
	require.NoError(t, os.Remove(filepath.Join(dir, "ca.crt")))

	_, err = ca.Init(dir, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca.key")

	keyAfter, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	require.NoError(t, err)
	assert.Equal(t, keyBefore, keyAfter, "the existing CA key must be left untouched")
}

func TestServerCertificate_IssuesLeafAndReusesIt(t *testing.T) {
	authority := newCA(t)

	cert, err := authority.ServerCertificate([]string{"control.internal", "10.0.0.1"}, 0)
	require.NoError(t, err)

	// Leaf first, CA second: an enrolling host has no trust store, so the CA
	// has to travel with the leaf for the pin to be verifiable.
	require.Len(t, cert.Certificate, 2)
	assert.Equal(t, authority.Certificate().Raw, cert.Certificate[1])
	require.NotNil(t, cert.Leaf)
	assert.NoError(t, cert.Leaf.VerifyHostname("control.internal"))
	assert.NotEqual(t, authority.Certificate().Raw, cert.Certificate[0],
		"the listener must present its own leaf, not the CA certificate")

	again, err := authority.ServerCertificate([]string{"control.internal", "10.0.0.1"}, 0)
	require.NoError(t, err)
	assert.Equal(t, cert.Certificate[0], again.Certificate[0], "an existing usable leaf should be reused")

	// A host the cached leaf does not cover forces a re-issue rather than
	// silently serving a certificate that will fail verification.
	wider, err := authority.ServerCertificate([]string{"control.internal", "other.internal"}, 0)
	require.NoError(t, err)
	assert.NotEqual(t, cert.Certificate[0], wider.Certificate[0])
	assert.NoError(t, wider.Leaf.VerifyHostname("other.internal"))
}

func TestServerCertificate_KeyFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	authority := newCA(t)
	_, err := authority.ServerCertificate([]string{"control.internal"}, 0)
	require.NoError(t, err)

	info, err := os.Stat(filepath.Join(authority.Dir(), "control-plane.key"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func newCA(t *testing.T) *ca.CA {
	t.Helper()
	authority, err := ca.Init(filepath.Join(t.TempDir(), "ca"), false)
	require.NoError(t, err)
	return authority
}
