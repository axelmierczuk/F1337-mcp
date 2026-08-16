package client

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
)

// DefaultMaxMessageSize overrides gRPC's 4 MiB default, which bites hardest
// on sandbox_read of anything but a small file and surfaces as an opaque
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
	// CertPEM and KeyPEM are the control leaf sandboxd-mcp presents as its
	// client certificate.
	CertPEM []byte
	KeyPEM  []byte

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

func (c Config) buildTLSConfig() (*tls.Config, error) {
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
