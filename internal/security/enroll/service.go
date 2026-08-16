package enroll

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/security/ca"
)

// Signer is the subset of *ca.CA the enrollment service needs: signing a
// CSR into an agent leaf, and handing back the trust bundle every enrolled
// agent must pin.
type Signer interface {
	SignCSR(csrDER []byte, opts ca.SignOptions) (*x509.Certificate, []byte, error)
	CertPEM() []byte
}

// NameChecker reports whether a sandbox name is already taken in the fleet.
// It exists as its own small interface, rather than a direct dependency on
// internal/registry, so this package's only blocker stays the CA.
type NameChecker interface {
	Exists(name string) bool
}

// Service implements sandboxdv1.EnrollmentServiceServer: it is the only RPC
// surface an unenrolled host may reach, so every step here runs before that
// host holds any certificate at all.
type Service struct {
	sandboxdv1.UnimplementedEnrollmentServiceServer

	Tokens *TokenStore
	CA     Signer
	// Names is consulted for collisions between RequestedName (or the
	// token's reserved name) and the existing fleet. A nil Names performs no
	// collision checking.
	Names NameChecker
	// LeafTTL overrides the signed leaf's validity period. Zero uses the CA
	// package's default.
	LeafTTL time.Duration
}

// Enroll redeems req.Token, signs req.CsrDer into an agent leaf, and
// returns it along with the CA bundle and the name finally assigned to this
// sandbox.
func (s *Service) Enroll(_ context.Context, req *sandboxdv1.EnrollRequest) (*sandboxdv1.EnrollResponse, error) {
	rec, err := s.Tokens.Redeem(req.GetToken())
	if err != nil {
		switch {
		case errors.Is(err, ErrTokenExpired):
			return nil, status.Error(codes.DeadlineExceeded, err.Error())
		case errors.Is(err, ErrTokenUsed):
			return nil, status.Error(codes.PermissionDenied, err.Error())
		default:
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
	}

	name := req.GetRequestedName()
	if name == "" {
		name = rec.Name
	}
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "enroll: no sandbox name requested and token reserved none")
	}
	name = s.resolveCollision(name)

	dnsNames, ips := splitListenAddresses(req.GetListenAddresses())
	// The name itself must also resolve, since that's what a caller dialing
	// by sandbox name will present as the TLS server name.
	dnsNames = append(dnsNames, name)

	ttl := s.LeafTTL

	cert, certPEM, err := s.CA.SignCSR(req.GetCsrDer(), ca.SignOptions{
		Profile:     ca.ProfileAgent,
		Subject:     name,
		DNSNames:    dnsNames,
		IPAddresses: ips,
		TTL:         ttl,
	})
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "enroll: sign CSR: %v", err)
	}

	return &sandboxdv1.EnrollResponse{
		CertificatePem: certPEM,
		CaBundlePem:    s.CA.CertPEM(),
		AssignedName:   name,
		NotAfter:       timestamppb.New(cert.NotAfter),
	}, nil
}

// resolveCollision appends a short, deterministic-enough suffix until name
// is free. The response's AssignedName tells the caller which name it
// actually got, so a collision is visible rather than silently masked.
func (s *Service) resolveCollision(name string) string {
	if s.Names == nil || !s.Names.Exists(name) {
		return name
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s-%d", name, i)
		if !s.Names.Exists(candidate) {
			return candidate
		}
	}
}

// splitListenAddresses separates host:port addresses into DNS names and IP
// SANs for the signed leaf.
func splitListenAddresses(addrs []string) (dnsNames []string, ips []net.IP) {
	for _, addr := range addrs {
		host := addr
		if h, _, err := net.SplitHostPort(addr); err == nil {
			host = h
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dnsNames = append(dnsNames, host)
	}
	return dnsNames, ips
}
