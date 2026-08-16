package client_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/client"
)

func TestNewPool_RequiresCACert(t *testing.T) {
	fleet := newTestFleet(t)
	certPEM, keyPEM := fleet.controlCert()

	_, err := client.NewPool(client.Config{CertPEM: certPEM, KeyPEM: keyPEM})
	require.Error(t, err)
}

func TestNewPool_RequiresControlCertificate(t *testing.T) {
	fleet := newTestFleet(t)

	_, err := client.NewPool(client.Config{CACertPEM: fleet.ca.CertPEM()})
	require.Error(t, err)
}

func TestNewPool_RejectsMalformedCert(t *testing.T) {
	fleet := newTestFleet(t)

	_, err := client.NewPool(client.Config{
		CACertPEM: fleet.ca.CertPEM(),
		CertPEM:   []byte("not a certificate"),
		KeyPEM:    []byte("not a key"),
	})
	require.Error(t, err)
}

func TestNewPool_ValidConfigSucceeds(t *testing.T) {
	fleet := newTestFleet(t)
	certPEM, keyPEM := fleet.controlCert()

	pool, err := client.NewPool(client.Config{
		CACertPEM: fleet.ca.CertPEM(),
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
	})
	require.NoError(t, err)
	require.NoError(t, pool.Close())
}
