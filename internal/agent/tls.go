package agent

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// ErrNoClientCertificate is the authorization failure for a peer that
// presented no certificate at all. The TLS stack rejects that case before
// authorizePeer runs; this exists so the check is total on its own terms.
var ErrNoClientCertificate = errors.New("agent: client presented no certificate")

// ServerTLSConfig builds the TLS configuration the agent's gRPC listener uses,
// or nil when this agent is configured to serve without mTLS.
//
// A nil configuration means plaintext gRPC: nothing is authenticated and
// nothing is encrypted by this process. That is a posture, not a fallback —
// it is reached only from `tls.enabled: false`, it is refused outright on an
// address that is neither loopback nor private without an explicit flag, and
// the daemon says what it is at every start. See [TLSConfig.Enabled] and
// [CheckListenPosture].
//
// With mTLS on, every parameter of it is mandatory: the agent is a remote code
// execution service, and the only thing standing between it and the network is
// this handshake.
//
//   - The agent presents its enrollment leaf, which the fleet CA issued under
//     ca.ProfileAgent — a server-auth certificate. internal/client verifies it
//     against the same CA and against the address it dialled.
//   - Clients must present a certificate (tls.RequireAndVerifyClientCert)
//     chaining to the same fleet CA.
//   - On top of chain verification, the verified leaf must carry
//     requireClientOU. Both agent and control leaves are signed by one CA, so
//     the chain alone does not distinguish them; the OU is what says "issued
//     to drive agents" rather than "issued to be an agent".
func ServerTLSConfig(cfg *Config) (*tls.Config, error) {
	if !cfg.TLS.IsEnabled() {
		return nil, nil
	}
	if cfg.TLS.RequireClientOU == "" {
		return nil, errors.New("agent: tls.require_client_ou is empty; refusing to accept any leaf the fleet CA signed")
	}

	cert, err := tls.LoadX509KeyPair(cfg.TLS.Certificate, cfg.TLS.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("agent: load agent certificate (%s / %s): %w", cfg.TLS.Certificate, cfg.TLS.PrivateKey, err)
	}

	caPEM, err := os.ReadFile(cfg.TLS.CABundle) //nolint:gosec // path is operator-supplied configuration, not caller input
	if err != nil {
		return nil, fmt.Errorf("agent: read CA bundle %s: %w", cfg.TLS.CABundle, err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("agent: no valid certificates in CA bundle %s", cfg.TLS.CABundle)
	}

	requiredOU := cfg.TLS.RequireClientOU
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS12,
		// VerifyConnection runs after the chain has been built, so it sees the
		// leaf the TLS stack actually trusted rather than whatever the peer
		// put first on the wire. Returning an error here aborts the handshake:
		// no stream is created, and no RPC reaches any registered service.
		VerifyConnection: func(cs tls.ConnectionState) error {
			_, err := authorizePeer(cs, requiredOU)
			return err
		},
	}, nil
}

// authorizePeer applies the agent's client-authorization policy to a verified
// connection state and returns the leaf it accepted.
//
// Two properties are checked beyond chaining to the fleet CA:
//
//   - The leaf carries requiredOU. This is the check that separates a control
//     leaf from an agent leaf. Both are signed by the same CA, so a compromised
//     sandbox holding its own key would otherwise be able to drive every other
//     sandbox in the fleet.
//   - The leaf is valid for client authentication. Go's TLS server already
//     verifies client chains with ExtKeyUsageClientAuth, so this is belt and
//     braces — but it is one line, and it means the separation does not depend
//     on a default in the standard library staying where it is.
func authorizePeer(cs tls.ConnectionState, requiredOU string) (*x509.Certificate, error) {
	if requiredOU == "" {
		return nil, errors.New("agent: no required client OU configured")
	}
	if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		if len(cs.PeerCertificates) == 0 {
			return nil, ErrNoClientCertificate
		}
		return nil, errors.New("agent: client certificate did not verify against the fleet CA")
	}

	leaf := cs.VerifiedChains[0][0]
	if !hasOU(leaf, requiredOU) {
		return nil, fmt.Errorf("agent: client certificate %q carries organizational unit %v, not %q; a leaf issued to an agent cannot be used to drive one",
			leaf.Subject.CommonName, leaf.Subject.OrganizationalUnit, requiredOU)
	}
	if !hasClientAuth(leaf) {
		return nil, fmt.Errorf("agent: client certificate %q is not valid for client authentication", leaf.Subject.CommonName)
	}
	return leaf, nil
}

func hasOU(cert *x509.Certificate, want string) bool {
	for _, ou := range cert.Subject.OrganizationalUnit {
		if ou == want {
			return true
		}
	}
	return false
}

// hasClientAuth reports whether cert may be used for client authentication. A
// leaf with no extended key usage at all is unconstrained and therefore
// allowed; one that names usages must name this one.
func hasClientAuth(cert *x509.Certificate) bool {
	if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
		return true
	}
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}
