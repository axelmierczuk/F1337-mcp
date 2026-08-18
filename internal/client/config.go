package client

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc"
)

// DefaultMaxMessageSize overrides gRPC's 4 MiB default, which bites hardest
// on fleet_read of anything but a small file and surfaces as an opaque
// ResourceExhausted with no hint that it is a configured limit rather than a
// real failure.
const DefaultMaxMessageSize = 32 * 1024 * 1024 // 32 MiB

// DefaultHealthInterval is how often a pooled connection's health is
// re-probed in the background.
const DefaultHealthInterval = 15 * time.Second

// DefaultHealthTimeout bounds a single health probe.
const DefaultHealthTimeout = 5 * time.Second

// Config configures a Pool.
type Config struct {
	// CACertPEM is the fleet CA bundle. Every agent's server certificate
	// must chain to it.
	CACertPEM []byte
	// CertPEM and KeyPEM are the control leaf fleet-mcp presents as its
	// client certificate.
	CertPEM []byte
	KeyPEM  []byte

	// CredentialErr is why this pool holds no mTLS material, for a caller that
	// could not load it.
	//
	// A workstation whose fleet is entirely mTLS-free has no CA and no control
	// leaf, and must still be able to dial: building the pool cannot be the
	// thing that fails. So a missing credential is carried here instead of
	// refused, and surfaces at the one moment it actually matters — a dial to a
	// sandbox that expects a certificate — where the message can name the file
	// and the command that creates it. See [Pool.Conn].
	CredentialErr error

	// Log is where the pool announces a connection this fleet does not
	// authenticate. Nil is silent.
	//
	// Not decoration, and not optional in production: an unauthenticated dial
	// is the client half of a posture whose whole failure mode is being held by
	// accident, and a control plane that took one without saying so would be
	// the only participant that never mentions it.
	Log *slog.Logger

	// MaxRecvMsgSize and MaxSendMsgSize bound a single gRPC message. Zero
	// uses DefaultMaxMessageSize.
	MaxRecvMsgSize int
	MaxSendMsgSize int

	// HealthInterval is how often each pooled connection's health is
	// re-probed. Zero uses DefaultHealthInterval.
	HealthInterval time.Duration
	// HealthTimeout bounds a single health probe. Zero uses
	// DefaultHealthTimeout.
	HealthTimeout time.Duration

	// DialOptions are appended to every dial. Production callers leave this
	// nil; tests use it to route connections over an in-memory transport
	// (bufconn) instead of a real socket.
	DialOptions []grpc.DialOption
}

func (c Config) withDefaults() Config {
	if c.MaxRecvMsgSize <= 0 {
		c.MaxRecvMsgSize = DefaultMaxMessageSize
	}
	if c.MaxSendMsgSize <= 0 {
		c.MaxSendMsgSize = DefaultMaxMessageSize
	}
	if c.HealthInterval <= 0 {
		c.HealthInterval = DefaultHealthInterval
	}
	if c.HealthTimeout <= 0 {
		c.HealthTimeout = DefaultHealthTimeout
	}
	return c
}

// hasCredentials reports whether any mTLS material was supplied at all. It is
// the difference between "this pool cannot dial an mTLS sandbox" and "this
// pool was handed half a credential", which are different errors.
func (c Config) hasCredentials() bool {
	return len(c.CACertPEM) > 0 || len(c.CertPEM) > 0 || len(c.KeyPEM) > 0
}

// buildTLSConfig assembles the mTLS configuration, or returns nil when no
// credentials were supplied.
//
// A nil configuration is not an error here: a pool on a workstation whose whole
// fleet runs without mTLS has nothing to load and every dial it makes is
// insecure by the operator's decision. It becomes an error at the first dial to
// a sandbox that is not marked insecure, which is where the missing file can be
// named. Half a credential is refused either way — a CA with no leaf is a
// misconfiguration, never a posture.
func (c Config) buildTLSConfig() (*tls.Config, error) {
	if !c.hasCredentials() {
		return nil, nil
	}
	if len(c.CACertPEM) == 0 {
		return nil, errors.New("client: CA certificate bundle is required")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(c.CACertPEM) {
		return nil, errors.New("client: no valid certificates found in CA bundle")
	}

	if len(c.CertPEM) == 0 || len(c.KeyPEM) == 0 {
		return nil, errors.New("client: control certificate and key are required")
	}
	cert, err := tls.X509KeyPair(c.CertPEM, c.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("client: load control certificate: %w", err)
	}

	return &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}
