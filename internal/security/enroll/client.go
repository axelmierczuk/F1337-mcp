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
	"errors"
	"fmt"
	"net"

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
	tlsConfig := &tls.Config{
		// The enrolling host has no CA bundle yet — that is exactly what
		// this exchange bootstraps — so normal chain verification is
		// impossible. VerifyConnection substitutes fingerprint pinning for
		// chain verification, and runs as part of the handshake, before any
		// application data (the token included) is sent.
		InsecureSkipVerify: true, //nolint:gosec
		MinVersion:         tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if skipPinning {
				return nil
			}
			if len(cs.PeerCertificates) == 0 {
				return errors.New("enroll: control plane presented no certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(got[:], pinned[:]) != 1 {
				return fmt.Errorf("enroll: control plane certificate fingerprint mismatch: pinned %x, got %x", pinned, got)
			}
			return nil
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
