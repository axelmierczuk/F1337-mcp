package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	serverCertFileName = "control-plane.crt"
	serverKeyFileName  = "control-plane.key"

	// serverCertRenewBefore is how much of a leaf's remaining life is treated
	// as too little to reuse, so a long-running control plane re-issues on
	// restart rather than serving a certificate about to expire mid-session.
	serverCertRenewBefore = 7 * 24 * time.Hour
)

// ServerCertificate returns the TLS certificate the control plane's
// enrollment listener presents, issuing and caching one under the CA
// directory on first use and reusing it afterwards.
//
// The listener presents a leaf signed by the CA rather than the CA
// certificate itself. That keeps the CA private key out of the process that
// terminates TLS for the one endpoint unauthenticated hosts can reach: a
// vulnerability in that listener costs a re-issuable leaf, not the key that
// underwrites every identity in the fleet.
//
// The returned chain is leaf-then-CA, because an enrolling host has no trust
// store yet and pins the CA — it can only verify the leaf if the CA travels
// with it in the handshake.
func (c *CA) ServerCertificate(hosts []string, ttl time.Duration) (tls.Certificate, error) {
	certPath := filepath.Join(c.dir, serverCertFileName)
	keyPath := filepath.Join(c.dir, serverKeyFileName)

	if cert, ok := c.loadServerCertificate(certPath, keyPath, hosts); ok {
		return cert, nil
	}
	return c.issueServerCertificate(certPath, keyPath, hosts, ttl)
}

// loadServerCertificate returns a cached leaf when one exists, still chains to
// this CA, still covers hosts, and is not close to expiry. Any failure is
// reported as a miss: the certificate is re-issuable at will, so there is no
// reason to fail a startup over a stale or corrupt cache.
func (c *CA) loadServerCertificate(certPath, keyPath string, hosts []string) (tls.Certificate, bool) {
	certPEM, err := os.ReadFile(certPath) //nolint:gosec // path derived from the operator-supplied CA directory
	if err != nil {
		return tls.Certificate{}, false
	}
	keyPEM, err := os.ReadFile(keyPath) //nolint:gosec // path derived from the operator-supplied CA directory
	if err != nil {
		return tls.Certificate{}, false
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, false
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, false
	}
	if time.Now().Add(serverCertRenewBefore).After(leaf.NotAfter) {
		return tls.Certificate{}, false
	}

	pool := x509.NewCertPool()
	pool.AddCert(c.cert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return tls.Certificate{}, false
	}
	for _, host := range hosts {
		if err := leaf.VerifyHostname(host); err != nil {
			return tls.Certificate{}, false
		}
	}

	cert.Leaf = leaf
	cert.Certificate = append(cert.Certificate, c.cert.Raw)
	return cert, true
}

func (c *CA) issueServerCertificate(certPath, keyPath string, hosts []string, ttl time.Duration) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ca: generate control plane key: %w", err)
	}

	dnsNames, ips := splitHosts(hosts)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "fleet control plane"},
	}, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ca: create control plane CSR: %w", err)
	}

	leaf, certPEM, err := c.SignCSR(csrDER, SignOptions{
		Profile:     ProfileControlPlane,
		Subject:     "fleet control plane",
		DNSNames:    dnsNames,
		IPAddresses: ips,
		TTL:         ttl,
	})
	if err != nil {
		return tls.Certificate{}, err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ca: marshal control plane key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := writeFileAtomic(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{leaf.Raw, c.cert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// splitHosts separates bare hosts into DNS and IP subject alternative names.
func splitHosts(hosts []string) (dnsNames []string, ips []net.IP) {
	for _, host := range hosts {
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dnsNames = append(dnsNames, host)
	}
	return dnsNames, ips
}
