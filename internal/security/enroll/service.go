package enroll

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
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

// EnrolledSandbox is what a successful enrollment learned about the host, for
// the fleet registry to record. The fields are flattened rather than reusing
// either the generated protobuf types or registry's own structs, so that
// neither dependency leaks into this package.
type EnrolledSandbox struct {
	Name         string
	Address      string
	Labels       map[string]string
	AgentVersion string

	OS            string
	Arch          string
	KernelVersion string
	Hostname      string
	PathSeparator string
}

// Recorder persists a newly enrolled sandbox. The control plane wires this to
// the fleet registry; a nil Recorder skips recording, which is what the
// package's own tests use.
type Recorder interface {
	Record(sb EnrolledSandbox) error
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
	// Fleet records each successful enrollment. A nil Fleet skips recording.
	Fleet Recorder
	// LeafTTL overrides the signed leaf's validity period. Zero uses the CA
	// package's default.
	LeafTTL time.Duration
	// Limiter throttles enrollment attempts. A nil Limiter gets the defaults,
	// because this RPC is reachable without any credential and should not be
	// the one unbounded thing in the system. To disable throttling, set a
	// limiter with non-positive limits rather than leaving this nil.
	Limiter *RateLimiter

	limiterOnce     sync.Once
	fallbackLimiter *RateLimiter
	// Log receives the reason a token was rejected. The reason is
	// deliberately not returned to the caller, so this is the only place it
	// is visible. A nil Log discards it.
	Log *slog.Logger
}

// Enroll redeems req.Token, signs req.CsrDer into an agent leaf, and
// returns it along with the CA bundle and the name finally assigned to this
// sandbox.
func (s *Service) Enroll(ctx context.Context, req *sandboxdv1.EnrollRequest) (*sandboxdv1.EnrollResponse, error) {
	if err := s.limiter().Allow(peerAddr(ctx)); err != nil {
		return nil, status.Error(codes.ResourceExhausted, err.Error())
	}

	rec, err := s.Tokens.Redeem(req.GetToken())
	if err != nil {
		// Every rejection reason is reported to the caller identically. The
		// caller already holds whatever token it sent, so telling it *which*
		// of invalid, expired, or already-used applies teaches it something
		// about the store's contents without helping a legitimate agent,
		// whose operator can read the real reason in the control plane's log.
		s.log().Warn("enrollment token rejected",
			slog.String("peer", peerAddr(ctx)),
			slog.String("reason", err.Error()),
		)
		return nil, status.Error(codes.Unauthenticated, "enroll: enrollment token rejected")
	}

	name := req.GetRequestedName()
	if name == "" {
		name = rec.Name
	}
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "enroll: no sandbox name requested and token reserved none")
	}
	name = s.resolveCollision(name)

	// The SANs come from what the operator authorized when minting, never
	// from the request. Without this, a host holding one valid token could
	// ask for — and be handed — a CA-signed leaf bearing another sandbox's
	// name, which is precisely the impersonation mTLS is here to prevent.
	dnsNames, ips, err := authorizedSANs(name, rec.Addresses, req.GetListenAddresses())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// Record before signing: the registry entry is what reserves the name, so
	// taking it first closes the window where two hosts enrolling at once
	// both pass the collision check. A failure here means no certificate is
	// issued at all, which is the safe direction.
	if s.Fleet != nil {
		if err := s.Fleet.Record(enrolledSandbox(name, rec, req)); err != nil {
			return nil, status.Errorf(codes.Internal, "enroll: record sandbox: %v", err)
		}
	}

	cert, certPEM, err := s.CA.SignCSR(req.GetCsrDer(), ca.SignOptions{
		Profile:     ca.ProfileAgent,
		Subject:     name,
		DNSNames:    dnsNames,
		IPAddresses: ips,
		TTL:         s.LeafTTL,
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

func (s *Service) limiter() *RateLimiter {
	if s.Limiter != nil {
		return s.Limiter
	}
	s.limiterOnce.Do(func() {
		s.fallbackLimiter = NewRateLimiter(DefaultRateWindow, DefaultPerPeerRate, DefaultGlobalRate)
	})
	return s.fallbackLimiter
}

func (s *Service) log() *slog.Logger {
	if s.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.Log
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

// authorizedSANs computes the subject alternative names the leaf may carry:
// the assigned name, plus the hosts the operator authorized when minting the
// token. Addresses the agent asks for are checked against that set rather
// than added to it.
//
// A loopback address is allowed unconditionally. It names the enrolling host
// and nothing else, so it cannot be used to impersonate another fleet member,
// and requiring an operator to pre-authorize 127.0.0.1 to run a sandbox
// locally would be friction with no security return.
func authorizedSANs(name string, authorized, requested []string) (dnsNames []string, ips []net.IP, err error) {
	allowedHosts := map[string]bool{name: true}
	for _, addr := range authorized {
		if host := hostOf(addr); host != "" {
			allowedHosts[host] = true
		}
	}

	for _, addr := range requested {
		host := hostOf(addr)
		if host == "" {
			continue
		}
		if allowedHosts[host] {
			continue
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			allowedHosts[host] = true
			continue
		}
		if len(authorized) == 0 {
			return nil, nil, fmt.Errorf(
				"enroll: this token authorizes no addresses, so %q cannot be certified; re-mint the token with --address %s",
				host, addr)
		}
		return nil, nil, fmt.Errorf(
			"enroll: address %q is not authorized by this token (authorized: %s)",
			host, strings.Join(authorized, ", "))
	}

	for host := range allowedHosts {
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dnsNames = append(dnsNames, host)
	}
	// Map iteration order is random; a certificate's contents should not be.
	slices.Sort(dnsNames)
	slices.SortFunc(ips, func(a, b net.IP) int { return bytes.Compare(a, b) })
	return dnsNames, ips, nil
}

// hostOf strips the port from a host:port address, tolerating a bare host and
// discarding wildcard listen addresses, which name no host at all.
func hostOf(addr string) string {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	if host == "0.0.0.0" || host == "::" || host == "[::]" {
		return ""
	}
	return host
}

func enrolledSandbox(name string, rec TokenRecord, req *sandboxdv1.EnrollRequest) EnrolledSandbox {
	address := ""
	if len(rec.Addresses) > 0 {
		address = rec.Addresses[0]
	} else if addrs := req.GetListenAddresses(); len(addrs) > 0 {
		address = addrs[0]
	}
	p := req.GetPlatform()
	return EnrolledSandbox{
		Name:          name,
		Address:       address,
		Labels:        rec.Labels,
		AgentVersion:  req.GetAgentVersion(),
		OS:            p.GetOs(),
		Arch:          p.GetArch(),
		KernelVersion: p.GetKernelVersion(),
		Hostname:      p.GetHostname(),
		PathSeparator: p.GetPathSeparator(),
	}
}

// peerAddr returns the calling host's address for rate limiting and logging,
// or "unknown" when the transport does not report one.
func peerAddr(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return "unknown"
	}
	if host, _, err := net.SplitHostPort(p.Addr.String()); err == nil {
		return host
	}
	return p.Addr.String()
}
