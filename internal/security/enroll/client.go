package enroll

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// ErrFingerprintRequired is returned by Dial when neither a pinned
// fingerprint nor an explicit opt-out was given. Enrolling without pinning
// trusts whatever certificate the network hands back, which is exactly what
// an on-path attacker needs to harvest tokens.
var ErrFingerprintRequired = errors.New("enroll: --ca-fingerprint is required (or set DialOptions.InsecureSkipPinning explicitly)")

// GenerateKey returns a fresh ECDSA P-256 keypair for a host enrolling into
// the fleet. The private key never leaves the process that generates it:
// only BuildCSR's output is ever sent over the wire.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("enroll: generate key: %w", err)
	}
	return priv, nil
}

// MarshalKey encodes a private key as PEM, for an enrolling host to persist
// alongside the certificate it was issued. Callers are expected to write the
// result at mode 0600.
func MarshalKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("enroll: marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// BuildCSR creates a PKCS#10 certificate signing request in DER form for
// the given key and identity. This, not the key itself, is what Enroll
// sends to the control plane.
func BuildCSR(key *ecdsa.PrivateKey, commonName string, dnsNames []string, ips []net.IP) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: commonName},
		DNSNames:    dnsNames,
		IPAddresses: ips,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("enroll: create CSR: %w", err)
	}
	return der, nil
}

// DialOptions configures Dial's connection to the control plane's
// enrollment listener.
type DialOptions struct {
	// Address is the control plane's host:port.
	Address string
	// CAFingerprint pins the SHA-256 fingerprint of the certificate the
	// control plane must present. Required unless InsecureSkipPinning is
	// set.
	CAFingerprint [32]byte
	// InsecureSkipPinning disables fingerprint pinning. Only ever meant for
	// tests: production enrollment without a pin trusts whatever the
	// network hands back.
	InsecureSkipPinning bool
	// ServerName is the name the control plane's leaf must be valid for.
	// Defaults to the host in Address, which is what an operator dialling a
	// control plane by name expects to be checked.
	ServerName string
	// ExtraDialOptions are appended after the transport credentials option,
	// for tests that route the connection over an in-memory transport
	// (grpc.WithContextDialer + bufconn) instead of a real socket.
	ExtraDialOptions []grpc.DialOption
}

// Dial connects to the control plane's enrollment listener with
// server-authenticated TLS, verifying the presented certificate against the
// pinned fingerprint during the TLS handshake itself — before any RPC,
// meaning before the enrollment token, is ever written to the connection.
//
// A wrong fingerprint aborts the handshake; the token is never transmitted.
func Dial(opts DialOptions) (*grpc.ClientConn, error) {
	if !opts.InsecureSkipPinning && opts.CAFingerprint == ([32]byte{}) {
		return nil, ErrFingerprintRequired
	}

	pinned := opts.CAFingerprint
	skipPinning := opts.InsecureSkipPinning
	serverName := opts.ServerName
	if serverName == "" {
		serverName = hostFromTarget(opts.Address)
	}
	tlsConfig := &tls.Config{
		// The enrolling host has no CA bundle yet — that is exactly what
		// this exchange bootstraps — so normal chain verification is
		// impossible. VerifyConnection substitutes the pinned fingerprint
		// for the trust store, and runs as part of the handshake, before any
		// application data (the token included) is sent.
		InsecureSkipVerify: true, //nolint:gosec
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if skipPinning {
				return nil
			}
			return verifyPinnedChain(cs, pinned, serverName)
		},
	}

	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	}
	dialOpts = append(dialOpts, opts.ExtraDialOptions...)

	cc, err := grpc.NewClient(opts.Address, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("enroll: dial %s: %w", opts.Address, err)
	}
	return cc, nil
}

// verifyPinnedChain accepts the connection when the pinned certificate is
// somewhere in the chain the control plane presented, and the leaf chains to
// it and is valid for serverName.
//
// Looking for the pin anywhere in the chain — not only at the leaf — is what
// lets the control plane serve a CA-signed leaf and keep the CA private key
// out of the process terminating TLS. The pin is the CA; the leaf is checked
// against it exactly as any other trust store would.
//
// The leaf-equals-pin case is still honoured, for the operator who pins a
// specific self-signed certificate on purpose. There, the fingerprint match
// *is* the whole trust decision, so no hostname check applies.
func verifyPinnedChain(cs tls.ConnectionState, pinned [32]byte, serverName string) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("enroll: control plane presented no certificate")
	}

	var pinnedCert *x509.Certificate
	for _, cert := range cs.PeerCertificates {
		sum := sha256.Sum256(cert.Raw)
		if subtle.ConstantTimeCompare(sum[:], pinned[:]) == 1 {
			pinnedCert = cert
			break
		}
	}
	if pinnedCert == nil {
		leafSum := sha256.Sum256(cs.PeerCertificates[0].Raw)
		return fmt.Errorf("enroll: control plane certificate does not match the pinned fingerprint: pinned %x, presented leaf %x", pinned, leafSum)
	}

	leaf := cs.PeerCertificates[0]
	if leaf.Equal(pinnedCert) {
		now := time.Now()
		if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
			return fmt.Errorf("enroll: pinned control plane certificate is outside its validity window (%s to %s)",
				leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339))
		}
		return nil
	}

	roots := x509.NewCertPool()
	roots.AddCert(pinnedCert)
	intermediates := x509.NewCertPool()
	for _, cert := range cs.PeerCertificates[1:] {
		if !cert.Equal(pinnedCert) {
			intermediates.AddCert(cert)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       serverName,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("enroll: control plane certificate does not chain to the pinned CA: %w", err)
	}
	return nil
}

// hostFromTarget extracts the hostname a gRPC target names, stripping the
// resolver scheme ("passthrough:///host:port") and any port. gRPC targets are
// URIs, not addresses, so a plain SplitHostPort is not enough.
func hostFromTarget(target string) string {
	addr := target
	if idx := strings.LastIndex(addr, "/"); idx >= 0 {
		addr = addr[idx+1:]
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
