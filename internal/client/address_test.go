package client_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertTLSFailure checks that an RPC failed because the handshake was
// rejected, not for some unrelated reason. gRPC surfaces a handshake failure
// as Unavailable with the TLS error in the message, so the message is where
// the evidence is.
func assertTLSFailure(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	msg := strings.ToLower(err.Error())
	for _, want := range []string{"certificate", "tls", "handshake", "bad certificate", "unknown authority"} {
		if strings.Contains(msg, want) {
			return
		}
	}
	t.Fatalf("expected a TLS/certificate failure, got: %v", err)
}

// The server name an agent's leaf is verified against comes from its
// registered address, so an address with no host is a configuration error that
// should be named as one. Left to the TLS stack it surfaces as "either
// ServerName or InsecureSkipVerify must be specified in the config", which
// names neither the sandbox nor the address at fault.
func TestPool_RejectsAddressWithoutHostPort(t *testing.T) {
	fleet := newTestFleet(t)
	pool := newTestPool(t, fleet)

	for _, address := range []string{"build-box", "", ":8722"} {
		t.Run(address, func(t *testing.T) {
			_, err := pool.Conn("build-box", address)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "build-box", "the error must name the sandbox")
		})
	}
}

func TestPool_AcceptsHostPort(t *testing.T) {
	fleet := newTestFleet(t)
	agent := newFakeAgent()
	addr, dialOpt, _ := serveAgent(t, fleet.ca, "agent-a", agent)

	pool := newTestPool(t, fleet, dialOpt)
	_, err := pool.Conn("agent-a", addr)
	require.NoError(t, err)
}
