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
	"strings"
	"time"
)

// Profile selects which extended key usage and organizational unit a leaf
// certificate is issued with. The two profiles are mutually exclusive by
// design: an agent leaf cannot pass a client-auth check, and a control leaf
// cannot pass a server-auth check, which is what stops a compromised
// sandbox from presenting its own leaf to drive other sandboxes.
type Profile int

const (
	// ProfileAgent issues a server-auth leaf for a fleet-agent host.
	ProfileAgent Profile = iota
	// ProfileControl issues a client-auth leaf for fleet-mcp.
	ProfileControl
	// ProfileControlPlane issues a server-auth leaf for the control plane's
	// own enrollment listener, so that listener terminates TLS with a leaf
	// rather than with the CA key itself.
	ProfileControlPlane
)

// OrganizationalUnit for a profile is baked into the subject, and is also
// what the agent-side policy check (internal/agent, milestone M1) matches
// against to require the control OU on incoming client certificates.
//
// These deliberately kept their pre-rebrand names. An OU is not branding: it
// is written into every certificate this CA has ever issued, and it is matched
// on at every mTLS handshake. Renaming it would mean an agent enrolled before
// the rename presenting OU=sandboxd-agent to a control plane that now demands
// OU=fleet-agent, and a control plane presenting OU=fleet-control to an agent
// whose config still says require_client_ou: sandboxd-control — the whole
// fleet refusing to talk to itself until every member is re-enrolled. Changing
// them is a flag day, not a rename; see the PR that carried out the rebrand.
func (p Profile) OrganizationalUnit() string {
	switch p {
	case ProfileAgent:
		return "sandboxd-agent"
	case ProfileControl:
		return "sandboxd-control"
	case ProfileControlPlane:
		return "sandboxd-control-plane"
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

// MaxSANs bounds how many subject alternative names a single leaf may carry.
// A fleet member listens on a handful of addresses; a request for hundreds is
// either a mistake or an attempt to blanket the namespace.
const MaxSANs = 16

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
	csr, err := CheckCSR(csrDER)
	if err != nil {
		return nil, nil, err
	}
	// SANs decide which identity a leaf may answer to, so they are validated
	// here — at the only place that signs — rather than trusted from whatever
	// assembled them. The caller is expected to have already decided *which*
	// names are permissible for this subject; this is the check that they are
	// well-formed names at all, and that none of them is a wildcard.
	if err := CheckSANs(opts.DNSNames, opts.IPAddresses); err != nil {
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
	case ProfileAgent, ProfileControlPlane:
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

// CheckCSR parses csrDER and verifies that it is a signing request worth
// acting on: it decodes, its self-signature verifies under the key it carries,
// and that key is strong enough to sign.
//
// SignCSR runs this itself. It is exported so that a caller who must take some
// other action first — the enrollment service reserves a fleet name before it
// signs — can reject a bad request before taking an action it would then have
// to undo.
func CheckCSR(csrDER []byte) (*x509.CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("ca: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("ca: CSR signature does not verify: %w", err)
	}
	if err := checkKeyStrength(csr.PublicKey); err != nil {
		return nil, err
	}
	return csr, nil
}

// DecodeCSR accepts a certificate signing request as either PEM or raw DER
// and returns its DER encoding, so a caller reading one off disk does not
// have to care which form the tool that produced it wrote.
func DecodeCSR(data []byte) ([]byte, error) {
	if block, _ := pem.Decode(data); block != nil {
		if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
			return nil, fmt.Errorf("ca: expected a CERTIFICATE REQUEST PEM block, got %q", block.Type)
		}
		return block.Bytes, nil
	}
	if _, err := x509.ParseCertificateRequest(data); err != nil {
		return nil, fmt.Errorf("ca: input is neither a PEM nor a DER certificate signing request: %w", err)
	}
	return data, nil
}

// CheckSANs rejects subject alternative names that are malformed, wildcarded,
// or too numerous.
//
// The wildcard rule is the important one: a leaf bearing "*.internal" answers
// to every name in the domain, which turns a single issued certificate into
// blanket authority over the fleet's namespace. Nothing in fleet needs a
// wildcard — a sandbox is dialled by its own name and addresses — so refusing
// to sign one costs nothing and removes the whole class.
//
// SignCSR runs this itself. It is exported for the same reason CheckCSR is: a
// caller that must take an irreversible step before signing — the enrollment
// service reserves a fleet name — has to be able to reject a request *before*
// that step rather than after it. Leaving this check reachable only through
// SignCSR is what let a request that could not be signed still create a fleet
// member, which is the defect this split exists to prevent.
func CheckSANs(dnsNames []string, ips []net.IP) error {
	if len(dnsNames)+len(ips) > MaxSANs {
		return fmt.Errorf("ca: too many subject alternative names: %d, limit is %d", len(dnsNames)+len(ips), MaxSANs)
	}
	for _, name := range dnsNames {
		if err := checkDNSName(name); err != nil {
			return err
		}
	}
	for _, ip := range ips {
		if len(ip) == 0 {
			return fmt.Errorf("ca: empty IP subject alternative name")
		}
		if ip.IsUnspecified() {
			return fmt.Errorf("ca: refusing to sign unspecified IP subject alternative name %s", ip)
		}
	}
	return nil
}

// checkDNSName enforces the shape of a hostname as RFC 1123 defines it, with
// wildcards excluded.
func checkDNSName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("ca: empty DNS subject alternative name")
	case len(name) > 253:
		return fmt.Errorf("ca: DNS subject alternative name %q is longer than 253 characters", name)
	case strings.Contains(name, "*"):
		return fmt.Errorf("ca: refusing to sign wildcard DNS subject alternative name %q", name)
	}

	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			return fmt.Errorf("ca: DNS subject alternative name %q has an empty label", name)
		}
		if len(label) > 63 {
			return fmt.Errorf("ca: DNS subject alternative name %q has a label longer than 63 characters", name)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("ca: DNS subject alternative name %q has a label starting or ending with '-'", name)
		}
		for _, r := range label {
			isAlphanumeric := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
			if !isAlphanumeric && r != '-' && r != '_' {
				return fmt.Errorf("ca: DNS subject alternative name %q contains an invalid character %q", name, r)
			}
		}
	}
	return nil
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
