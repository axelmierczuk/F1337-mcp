package agent

import (
	"context"
	"crypto/tls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// principalKey is the context key the interceptors stash the authenticated
// common name under. It is unexported so nothing outside this package can
// forge a principal by writing to the context directly.
type principalKey struct{}

// PrincipalFromContext returns the common name of the client certificate the
// daemon authenticated for this RPC.
//
// This is the value HostService echoes as authenticated_principal and the one
// every audit record (#17) is keyed on. It is derived from the verified chain
// during the TLS handshake, not from anything the caller sends, so it cannot
// be spoofed by a request field.
//
// The second return is false for a context that did not come from a served
// RPC, which in practice means a bug in a test harness rather than an
// unauthenticated caller: the server rejects those at the handshake.
func PrincipalFromContext(ctx context.Context) (string, bool) {
	if name, ok := ctx.Value(principalKey{}).(string); ok {
		return name, true
	}
	return principalFromPeer(ctx)
}

// principalFromPeer digs the common name out of the gRPC peer's TLS state, for
// a context that did not pass through the interceptors.
func principalFromPeer(ctx context.Context) (string, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return "", false
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", false
	}
	return commonNameOf(info.State)
}

func commonNameOf(state tls.ConnectionState) (string, bool) {
	if len(state.VerifiedChains) > 0 && len(state.VerifiedChains[0]) > 0 {
		return state.VerifiedChains[0][0].Subject.CommonName, true
	}
	return "", false
}

// withPrincipal returns ctx carrying the authenticated common name.
func withPrincipal(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, principalKey{}, name)
}

// principalUnaryInterceptor resolves the peer's identity once per RPC and puts
// it in the context, so a handler does not repeat the peer/TLS/chain dance.
//
// It fails closed: an RPC whose peer identity cannot be established is
// refused. Reaching this state means the handshake succeeded without a
// verified chain, which should be impossible under
// tls.RequireAndVerifyClientCert — but "should be impossible" is not a reason
// to hand an anonymous caller to an exec service.
func principalUnaryInterceptor(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	name, ok := principalFromPeer(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no authenticated client certificate on this connection")
	}
	return handler(withPrincipal(ctx, name), req)
}

// principalStreamInterceptor is principalUnaryInterceptor for streaming RPCs.
func principalStreamInterceptor(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	name, ok := principalFromPeer(ss.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "no authenticated client certificate on this connection")
	}
	return handler(srv, &principalStream{ServerStream: ss, ctx: withPrincipal(ss.Context(), name)})
}

// principalStream overrides a server stream's context so handlers reading it
// see the principal, since grpc.ServerStream exposes no way to replace one.
type principalStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *principalStream) Context() context.Context { return s.ctx }
