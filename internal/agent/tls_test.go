package agent_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	"github.com/axelmierczuk/fleet-mcp/internal/security/ca"
)

// A control leaf issued by the fleet CA is the one identity that gets through,
// and the principal the handler sees is its common name.
func TestServer_ControlLeafIsAccepted(t *testing.T) {
	fleet := newTestFleet(t)
	svc := newCountingService()
	h := start(t, fleet.agentConfig(t), []agent.Registration{registration("host", svc)})

	certPEM, keyPEM := fleet.controlLeaf()
	hostClient := h.hostClient(t, fleet.ca.CertPEM(), certPEM, keyPEM)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := hostClient.Health(ctx, &sandboxdv1.HealthRequest{})
	require.NoError(t, err)
	assert.Equal(t, sandboxdv1.HealthResponse_STATUS_SERVING, resp.GetStatus())

	// At least one: internal/client's pool also health-probes in the
	// background, and both those calls and this one are real traffic through
	// the same handshake.
	assert.GreaterOrEqual(t, svc.servedCount(), int64(1))
	assert.Equal(t, "sandboxd-mcp", svc.seenPrincipal(),
		"the principal must be the client leaf's common name, taken from the verified chain")
}

// A client with no certificate is rejected at the TLS layer.
func TestServer_NoClientCertificate_Rejected(t *testing.T) {
	fleet := newTestFleet(t)
	svc := newCountingService()
	h := start(t, fleet.agentConfig(t), []agent.Registration{registration("host", svc)})

	// Trusts the fleet CA for the server, presents nothing of its own.
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(fleet.ca.CertPEM()))
	cc := h.rawConn(t, credentials.NewTLS(&tls.Config{
		RootCAs:    roots,
		ServerName: "test-agent",
		MinVersion: tls.VersionTLS12,
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := sandboxdv1.NewHostServiceClient(cc).Health(ctx, &sandboxdv1.HealthRequest{})
	require.Error(t, err)

	// The assertion that matters. An error alone would also be produced by a
	// misconfigured test; a zero served count is only produced by the
	// connection never reaching a handler.
	assert.Zero(t, svc.servedCount(), "a client with no certificate must never reach the service")
}

// A client whose certificate was issued by a different CA is rejected.
func TestServer_ClientCertFromAnotherCA_Rejected(t *testing.T) {
	fleet := newTestFleet(t)
	svc := newCountingService()
	h := start(t, fleet.agentConfig(t), []agent.Registration{registration("host", svc)})

	// A second, entirely legitimate CA — just not this fleet's. It even issues
	// a control-profile leaf, so the OU matches and only the chain does not.
	imposter, err := ca.Init(filepath.Join(t.TempDir(), "imposter-ca"), false)
	require.NoError(t, err)
	certPEM, keyPEM := signLeafWith(t, imposter, ca.ProfileControl, "sandboxd-mcp", nil)

	hostClient := h.hostClient(t, fleet.ca.CertPEM(), certPEM, keyPEM)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = hostClient.Health(ctx, &sandboxdv1.HealthRequest{})
	require.Error(t, err)
	assert.Zero(t, svc.servedCount(), "a certificate from another CA must never reach the service")
}

// The case chain verification does not settle on its own: an agent leaf and a
// control leaf are signed by the same CA, so only the OU distinguishes them. A
// compromised sandbox holding its own key must not be able to drive the fleet.
func TestServer_AgentLeafAsClientCert_Rejected(t *testing.T) {
	fleet := newTestFleet(t)
	svc := newCountingService()
	h := start(t, fleet.agentConfig(t), []agent.Registration{registration("host", svc)})

	// A perfectly valid leaf, issued by the right CA, to another agent.
	certPEM, keyPEM := fleet.agentLeaf("other-sandbox")
	hostClient := h.hostClient(t, fleet.ca.CertPEM(), certPEM, keyPEM)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := hostClient.Health(ctx, &sandboxdv1.HealthRequest{})
	require.Error(t, err)
	assert.Zero(t, svc.servedCount(), "an agent leaf presented as a client certificate must never reach the service")
}

// The OU check is asserted directly as well as through a handshake, because
// Go's TLS server also rejects an agent leaf for lacking clientAuth EKU. If
// the OU check were quietly removed, the handshake test above would keep
// passing on Go and the separation would be resting on a standard-library
// default. This is the test that would fail.
func TestAuthorizePeer_RejectsWrongOUEvenWithClientAuthUsage(t *testing.T) {
	fleet := newTestFleet(t)

	// An agent-OU leaf that *is* valid for client authentication: the EKU
	// backstop cannot catch this one, so only the OU check can.
	certPEM, _ := fleet.agentLeaf("other-sandbox")
	leaf := parseLeaf(t, certPEM)
	leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	state := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf, fleet.ca.Certificate()}},
	}

	_, err := agent.AuthorizePeerForTest(state, agent.DefaultClientOU)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sandboxd-agent", "the error should name the OU the leaf actually carries")
	assert.Contains(t, err.Error(), agent.DefaultClientOU)

	// And the control leaf, which differs only in its OU, passes.
	controlPEM, _ := fleet.controlLeaf()
	control := parseLeaf(t, controlPEM)
	accepted, err := agent.AuthorizePeerForTest(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{control},
		VerifiedChains:   [][]*x509.Certificate{{control, fleet.ca.Certificate()}},
	}, agent.DefaultClientOU)
	require.NoError(t, err)
	assert.Equal(t, "sandboxd-mcp", accepted.Subject.CommonName)
}

// An unverified connection is refused even if a certificate was presented.
func TestAuthorizePeer_RequiresAVerifiedChain(t *testing.T) {
	fleet := newTestFleet(t)
	certPEM, _ := fleet.controlLeaf()
	leaf := parseLeaf(t, certPEM)

	_, err := agent.AuthorizePeerForTest(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}, agent.DefaultClientOU)
	require.Error(t, err)

	_, err = agent.AuthorizePeerForTest(tls.ConnectionState{}, agent.DefaultClientOU)
	require.ErrorIs(t, err, agent.ErrNoClientCertificate)
}

// An empty required OU would accept every leaf the fleet CA ever signed,
// including every agent's. It is refused at construction rather than treated
// as "no constraint".
func TestServerTLSConfig_RefusesEmptyRequiredOU(t *testing.T) {
	fleet := newTestFleet(t)
	cfg := fleet.agentConfig(t)
	cfg.TLS.RequireClientOU = ""

	_, err := agent.ServerTLSConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "require_client_ou")
}

// The server presents an agent leaf and demands a client one. Reading the
// built config directly documents the profile pairing internal/client depends
// on: it verifies the agent's leaf for server auth and presents a control leaf
// of its own.
func TestServerTLSConfig_RequiresAndVerifiesClientCerts(t *testing.T) {
	fleet := newTestFleet(t)
	conf, err := agent.ServerTLSConfig(fleet.agentConfig(t))
	require.NoError(t, err)

	assert.Equal(t, tls.RequireAndVerifyClientCert, conf.ClientAuth)
	assert.NotNil(t, conf.ClientCAs)
	assert.NotNil(t, conf.VerifyConnection)
	assert.GreaterOrEqual(t, conf.MinVersion, uint16(tls.VersionTLS12))
	require.Len(t, conf.Certificates, 1)

	leaf, err := x509.ParseCertificate(conf.Certificates[0].Certificate[0])
	require.NoError(t, err)
	assert.Contains(t, leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth,
		"the agent presents a server-auth leaf, which is what internal/client verifies")
}

func parseLeaf(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return leaf
}
