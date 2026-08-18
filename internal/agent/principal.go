package agent

import (
	"context"
	"crypto/tls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/axelmierczuk/fleet-mcp/internal/security/policy"
)

// UnauthenticatedPrefix begins the name of every principal this daemon did not
// authenticate.
//
// It is the audit log's whole defence against ambiguity. A record whose
// principal is "whoever connected" must not read like one naming a verified
// certificate subject — otherwise the log quietly stops meaning what it meant,
// and every historical record with it. So an unauthenticated principal is
// spelled `unauthenticated:<peer address>`: it names the only identifying fact
// there is, and it cannot be mistaken for a common name at a glance or by a
// grep. [policy.Record.PrincipalSource] says the same thing in a field, for a
// reader that is matching rather than looking.
const UnauthenticatedPrefix = "unauthenticated:"

// unknownPeer is the address part when even that is unavailable, which means a
// context that never came from a served RPC.
const unknownPeer = "unknown"

// Principal is who the daemon is serving this RPC for, and how it knows.
//
// The two fields are not redundant. Name is what a human reads; Authenticated
// is what a machine matches on, and it is false for every RPC on an agent
// serving without mTLS — where "who is calling" has no answer this process can
// verify, only an address the network handed it.
type Principal struct {
	// Name identifies the caller: the common name from its verified client
	// certificate, or `unauthenticated:<peer address>`.
	Name string
	// Authenticated reports that Name came from a certificate chain this agent
	// verified against the fleet CA. False means the network decided who may
	// reach this port, and this agent checked nothing.
	Authenticated bool
}

// String renders the principal as it is recorded and echoed.
func (p Principal) String() string { return p.Name }

// Source is how the audit log names what established this principal.
func (p Principal) Source() policy.PrincipalSource {
	if p.Authenticated {
		return policy.PrincipalCertificate
	}
	return policy.PrincipalNetwork
}

// principalKey is the context key the interceptors stash the resolved
// principal under. It is unexported so nothing outside this package can
// forge a principal by writing to the context directly.
type principalKey struct{}

// PrincipalFromContext returns the identity the daemon resolved for this RPC.
//
// This is the value HostService echoes as authenticated_principal and the one
// every audit record (#17) is keyed on. With mTLS on it is derived from the
// verified chain during the TLS handshake, not from anything the caller sends,
// so it cannot be spoofed by a request field. With mTLS off there is no chain
// to derive anything from and it names the peer address instead — see
// [Principal] and [UnauthenticatedPrefix].
//
// The second return is false for a context that did not come from a served
// RPC, which in practice means a bug in a test harness rather than an
// unauthenticated caller: an agent serving mTLS rejects those at the handshake,
// and one serving without it still has a peer address for every real call.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	if p, ok := ctx.Value(principalKey{}).(Principal); ok {
		return p, true
	}
	return certificatePrincipal(ctx)
}

// certificatePrincipal digs the common name out of the gRPC peer's TLS state,
// for a context that did not pass through the interceptors.
func certificatePrincipal(ctx context.Context) (Principal, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return Principal{}, false
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return Principal{}, false
	}
	name, ok := commonNameOf(info.State)
	if !ok {
		return Principal{}, false
	}
	return Principal{Name: name, Authenticated: true}, true
}

// networkPrincipal names the caller of an RPC nothing authenticated.
//
// The peer address is all there is, and it is worth having: it is what joins an
// audit record to a tailnet's own access log, a firewall log, or a conntrack
// entry — which, on an agent serving without mTLS, is where the caller's actual
// identity lives.
func networkPrincipal(ctx context.Context) Principal {
	addr := unknownPeer
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		addr = p.Addr.String()
	}
	return Principal{Name: UnauthenticatedPrefix + addr}
}

func commonNameOf(state tls.ConnectionState) (string, bool) {
	if len(state.VerifiedChains) > 0 && len(state.VerifiedChains[0]) > 0 {
		return state.VerifiedChains[0][0].Subject.CommonName, true
	}
	return "", false
}

// withPrincipal returns ctx carrying the resolved principal.
func withPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// resolvePrincipal answers "who is this" once per RPC, from the daemon's own
// configuration rather than from what the connection happens to carry.
//
// mtls is the config's answer, not the connection's, and that is the whole
// point: an agent serving mTLS that somehow saw a certificate-less connection
// must refuse it, not fall back to naming an address. A check written the other
// way round — "use the certificate if there is one" — is a downgrade waiting
// for a bug in the TLS stack to trigger it.
func resolvePrincipal(ctx context.Context, mtls bool) (Principal, error) {
	if !mtls {
		return networkPrincipal(ctx), nil
	}
	p, ok := certificatePrincipal(ctx)
	if !ok {
		return Principal{}, status.Error(codes.Unauthenticated, "no authenticated client certificate on this connection")
	}
	return p, nil
}

// principalUnaryInterceptor resolves the peer's identity once per RPC and puts
// it in the context, so a handler does not repeat the peer/TLS/chain dance.
//
// With mTLS on it fails closed: an RPC whose peer identity cannot be
// established is refused. Reaching that state means the handshake succeeded
// without a verified chain, which should be impossible under
// tls.RequireAndVerifyClientCert — but "should be impossible" is not a reason
// to hand an anonymous caller to an exec service.
//
// With mTLS off there is nothing to fail closed to: the operator has said the
// network is the authentication, and every caller past it is legitimate by that
// decision. What the daemon owes them then is not a refusal but a record that
// says plainly that nobody was authenticated.
func principalUnaryInterceptor(mtls bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		p, err := resolvePrincipal(ctx, mtls)
		if err != nil {
			return nil, err
		}
		return handler(withPrincipal(ctx, p), req)
	}
}

// principalStreamInterceptor is principalUnaryInterceptor for streaming RPCs.
func principalStreamInterceptor(mtls bool) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		p, err := resolvePrincipal(ss.Context(), mtls)
		if err != nil {
			return err
		}
		return handler(srv, &principalStream{ServerStream: ss, ctx: withPrincipal(ss.Context(), p)})
	}
}

// principalStream overrides a server stream's context so handlers reading it
// see the principal, since grpc.ServerStream exposes no way to replace one.
type principalStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *principalStream) Context() context.Context { return s.ctx }
