package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"time"
)

// Profile selects which extended key usage and organizational unit a leaf
// certificate is issued with. The two profiles are mutually exclusive by
// design: an agent leaf cannot pass a client-auth check, and a control leaf
// cannot pass a server-auth check, which is what stops a compromised
// sandbox from presenting its own leaf to drive other sandboxes.
type Profile int

const (
	// ProfileAgent issues a server-auth leaf for a sandboxd-agent host.
	ProfileAgent Profile = iota
	// ProfileControl issues a client-auth leaf for sandboxd-mcp.
	ProfileControl
)

// OrganizationalUnit for a profile is baked into the subject, and is also
// what the agent-side policy check (internal/agent, milestone M1) matches
// against to require the control OU on incoming client certificates.
func (p Profile) OrganizationalUnit() string {
	switch p {
	case ProfileAgent:
		return "sandboxd-agent"
	case ProfileControl:
		return "sandboxd-control"
	default:
		return ""
	}
}

// minRSAKeyBits is the smallest RSA modulus SignCSR accepts. 2048 bits is
// the floor NIST and every current CA/Browser Forum baseline treats as
// non-deprecated.
const minRSAKeyBits = 2048

// minECDSAKeyBits is the smallest ECDSA curve size SignCSR accepts.
const minECDSAKeyBits = 256

// SignOptions configures the leaf certificate SignCSR produces.
type SignOptions struct {
	// Profile selects the extended key usage and organizational unit.
	Profile Profile
	// Subject becomes the leaf's CommonName: the sandbox name for an agent
	// leaf, or an operator-chosen identifier for a control leaf.
	Subject string
	// DNSNames are the SANs an agent leaf's clients will dial by name.
	// Ignored for ProfileControl.
	DNSNames []string
	// IPAddresses are the SANs an agent leaf's clients will dial by IP.
	// Ignored for ProfileControl.
	IPAddresses []net.IP
	// TTL is the leaf's validity period. Defaults to DefaultLeafTTL (90
	// days) when zero.
	TTL time.Duration
}

// SignCSR verifies csrDER's signature and key strength, then signs a leaf
// certificate for it per opts.
//
// This is also the primitive certificate rotation uses: re-issuing a leaf
// before expiry is just calling SignCSR again with a fresh CSR from the same
// host, with no dependency on a new enrollment token.
func (c *CA) SignCSR(csrDER []byte, opts SignOptions) (*x509.Certificate, []byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("ca: CSR signature does not verify: %w", err)
	}
	if err := checkKeyStrength(csr.PublicKey); err != nil {
		return nil, nil, err
	}

	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultLeafTTL
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         opts.Subject,
			OrganizationalUnit: []string{opts.Profile.OrganizationalUnit()},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	switch opts.Profile {
	case ProfileAgent:
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = opts.DNSNames
		tmpl.IPAddresses = opts.IPAddresses
	case ProfileControl:
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default:
		return nil, nil, fmt.Errorf("ca: unknown profile %d", opts.Profile)
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: sign leaf certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: parse signed leaf certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, certPEM, nil
}

// checkKeyStrength rejects public keys too weak to be worth signing.
func checkKeyStrength(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < minRSAKeyBits {
			return fmt.Errorf("ca: rsa key too weak: %d bits, want at least %d", k.N.BitLen(), minRSAKeyBits)
		}
	case *ecdsa.PublicKey:
		if k.Curve.Params().BitSize < minECDSAKeyBits {
			return fmt.Errorf("ca: ecdsa key too weak: %d bits, want at least %d", k.Curve.Params().BitSize, minECDSAKeyBits)
		}
	case ed25519.PublicKey:
		// Ed25519 has a single, adequately strong parameter set.
	default:
		return fmt.Errorf("ca: unsupported public key type %T", pub)
	}
	return nil
}

// VerifyLeaf parses a PEM-encoded leaf certificate and checks that it
// chains to this CA and is valid for usage. This is the same check a TLS
// handshake performs, exposed directly so the agent-vs-client-cert
// separation between profiles can be asserted without standing up a real
// TLS listener.
func (c *CA) VerifyLeaf(certPEM []byte, usage x509.ExtKeyUsage) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("ca: no PEM certificate found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse leaf certificate: %w", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(c.cert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{usage},
	}); err != nil {
		return nil, fmt.Errorf("ca: verify leaf certificate: %w", err)
	}
	return cert, nil
}
