package enroll

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

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
//
// A Recorder that is asked to record a name another fleet member already holds
// must report it as ErrNameTaken. That is what lets Enroll hand the loser of a
// race the next free name instead of failing it: the record, not the
// NameChecker consulted beforehand, is what actually reserves a name.
type Recorder interface {
	Record(sb EnrolledSandbox) error
}

// ErrNameTaken is the error a Recorder returns when the name it was asked to
// record is already held.
var ErrNameTaken = errors.New("enroll: sandbox name already taken")

// maxNameAttempts bounds collision resolution.
//
// The bound is not paranoia about a fleet with sixty-four "build-box"es. A
// NameChecker may report every name as taken — registry.Exists deliberately
// does exactly that when it cannot read the registry at all, because refusing a
// name it cannot rule out is the safe direction — and an unbounded search then
// spins forever inside an RPC any unauthenticated host can start.
const maxNameAttempts = 64

// Service implements sandboxdv1.EnrollmentServiceServer: it is the only RPC
// surface an unenrolled host may reach, so every step here runs before that
// host holds any certificate at all.
type Service struct {
	sandboxdv1.UnimplementedEnrollmentServiceServer

	Tokens *TokenStore
	CA     Signer
	// Names is consulted for collisions between the name this enrollment
	// settles on and the existing fleet. A nil Names performs no collision
	// checking, leaving the Recorder to reject a duplicate.
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
	// Log receives the detail behind a rejection: which of invalid, expired or
	// used a token was, and why a fleet registry write failed. None of it is
	// returned to the caller — the caller is unauthenticated — so this is the
	// only place it is visible. A nil Log discards it.
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

	// A token authorizes an identity, not merely admission. The name is half
	// of that identity — it is what the leaf's SANs are built from — so a
	// request to be enrolled under some other name is refused rather than
	// quietly honoured. Without this, one valid token yields a CA-signed leaf
	// for any name its holder cares to type, which is precisely the
	// impersonation mTLS is here to prevent.
	requested := req.GetRequestedName()
	if err := checkRequestedName(requested); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	// The name is not the only string this request writes into the fleet
	// registry, and the registry is printed back to the operator as a table.
	// Everything else the host says about itself is bounded here for the same
	// reason the name is.
	if err := checkHostDescription(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	switch {
	case rec.Name != "" && requested != "" && requested != rec.Name:
		return nil, status.Errorf(codes.InvalidArgument,
			"enroll: this token reserves the name %q and cannot be used to enroll as %q", rec.Name, requested)
	case rec.Name == "" && requested == "":
		return nil, status.Error(codes.InvalidArgument, "enroll: no sandbox name requested and token reserved none")
	}
	// Two names, deliberately. name is the fleet registry's label for this
	// sandbox and the enrolling host may choose it; certName is the name the
	// leaf may be certified for and only the operator may choose it, at mint
	// time. A token that reserved none lets its holder pick a label — a
	// legitimate choice for bulk enrollment — but a name this side did not
	// choose stays out of the certificate entirely: out of the SANs, and out of
	// the subject. They are the same field to an attacker.
	name, certName := requested, ""
	if rec.Name != "" {
		name, certName = rec.Name, rec.Name
	}

	// Everything that can reject this request runs before the registry write
	// below, so a request that cannot be signed leaves no fleet member behind.
	// "Everything" has to mean it: ca.CheckCSR here covers the request, and the
	// certifiable closure below covers the names, which is the half that stayed
	// inside SignCSR and so ran after the write.
	extraHosts, err := checkRequestedAddresses(certName, rec.Addresses, req.GetListenAddresses())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if _, err := ca.CheckCSR(req.GetCsrDer()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "enroll: %v", err)
	}

	// certifiable reports whether the leaf for a candidate name could actually
	// be signed. Collision resolution decides that name, and the registry write
	// that reserves it is irreversible, so the question has to be answerable
	// before the write rather than after it.
	certifiable := func(candidate string) error {
		dnsNames, ips := sanSet(certifiedName(certName, candidate), rec.Addresses, extraHosts)
		return ca.CheckSANs(dnsNames, ips)
	}

	// Record before signing: the registry entry is what reserves the name, so
	// taking it first closes the window where two hosts enrolling at once both
	// pass the collision check. A failure here means no certificate is issued
	// at all, which is the safe direction.
	name, err = s.reserve(name, enrolledSandbox(rec, req), certifiable)
	switch {
	case errors.Is(err, errUncertifiable):
		// The caller's own request is what cannot be certified, so it gets to
		// hear why — nothing here describes the control plane.
		return nil, status.Error(codes.InvalidArgument, err.Error())
	case err != nil:
		// The caller is unauthenticated and a registry failure is the control
		// plane's own problem, described in the control plane's own terms —
		// down to absolute paths on its filesystem. It goes to the log.
		s.log().Error("enrollment could not reserve a sandbox name",
			slog.String("peer", peerAddr(ctx)),
			slog.String("name", name),
			slog.String("error", err.Error()),
		)
		return nil, status.Error(codes.Internal, "enroll: could not record this sandbox in the fleet registry")
	}
	// Collision resolution may have moved the name; certify what was actually
	// created, never the name it collided with.
	certName = certifiedName(certName, name)
	dnsNames, ips := sanSet(certName, rec.Addresses, extraHosts)

	cert, certPEM, err := s.CA.SignCSR(req.GetCsrDer(), ca.SignOptions{
		Profile: ca.ProfileAgent,
		// The subject is a certificate field like any other, so it comes from
		// the token and not from the request. Round 2 kept the host's chosen
		// name out of the SANs but passed it here, which still yielded a
		// CA-signed leaf whose common name was whatever its holder typed —
		// the control plane's own name included.
		Subject:     certName,
		DNSNames:    dnsNames,
		IPAddresses: ips,
		TTL:         s.LeafTTL,
	})
	if err != nil {
		// Everything the caller could have got wrong — the CSR, the addresses,
		// the names — was checked before the registry write above. A failure
		// this late is the control plane's own: a CA whose key does not match
		// its certificate, a signing step that broke. Blaming the caller for it
		// with InvalidArgument would be wrong, and the detail is internal.
		s.log().Error("enrollment could not sign an agent leaf",
			slog.String("peer", peerAddr(ctx)),
			slog.String("name", name),
			slog.String("error", err.Error()),
		)
		return nil, status.Error(codes.Internal, "enroll: could not sign a certificate for this sandbox")
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

// errUncertifiable marks a reserve failure caused by the request itself rather
// than by the fleet registry, so Enroll can tell the caller what was wrong with
// what it sent instead of reporting the control plane as broken.
var errUncertifiable = errors.New("enroll: this request cannot be certified")

// reserve records sb under base, or under the first free "base-N" when base is
// taken, and returns the name it settled on. The response's AssignedName tells
// the caller which name it actually got, so a collision is visible rather than
// silently masked.
//
// The NameChecker is consulted first because it makes the common case one
// write, but it is not trusted: between the check and the record, another host
// enrolling concurrently can take the name. The record is the reservation, so
// an ErrNameTaken from it simply moves the search on.
//
// certifiable is consulted for the candidate this call is about to take, and it
// is what keeps the reservation and the certificate in step. The registry entry
// cannot be taken back, so a candidate whose leaf could not be signed must be
// rejected before the write, not discovered after it.
func (s *Service) reserve(base string, sb EnrolledSandbox, certifiable func(string) error) (string, error) {
	for i := 0; i < maxNameAttempts; i++ {
		candidate := base
		if i > 0 {
			candidate = fmt.Sprintf("%s-%d", base, i+1)
		}
		if s.Names != nil && s.Names.Exists(candidate) {
			continue
		}
		if err := certifiable(candidate); err != nil {
			return candidate, fmt.Errorf("%w: %w", errUncertifiable, err)
		}
		if s.Fleet == nil {
			return candidate, nil
		}
		sb.Name = candidate
		switch err := s.Fleet.Record(sb); {
		case err == nil:
			return candidate, nil
		case errors.Is(err, ErrNameTaken):
			continue
		default:
			return candidate, err
		}
	}
	return base, fmt.Errorf("enroll: no name free for %q after %d attempts", base, maxNameAttempts)
}

// certifiedName is the name a leaf may carry once collision resolution has
// settled on assigned.
//
// A token that reserved a name certifies whichever name was actually created
// for it — the reserved one, or the free "-N" the collision moved it to. A
// token that reserved none certifies nothing: the name such a host picks for
// itself is a registry label, and a label the control plane did not choose has
// no business in a certificate, as a subject or as anything else.
func certifiedName(reserved, assigned string) string {
	if reserved == "" {
		return ""
	}
	return assigned
}

// maxNameLength bounds a caller-supplied sandbox name. The name reaches the
// leaf's subject and the fleet registry, and neither has any use for a
// kilobyte of it. Names the operator chose at mint time are not checked: those
// are the operator's business, and an operator holding the CA can already ask
// `ca sign` for any subject at all.
const maxNameLength = 128

// checkRequestedName bounds the one identifier an unauthenticated caller can
// put into a certificate's subject and a registry entry's key.
func checkRequestedName(name string) error {
	if len(name) > maxNameLength {
		return fmt.Errorf("enroll: requested sandbox name is %d bytes, limit is %d", len(name), maxNameLength)
	}
	for _, r := range name {
		// Printable, non-space ASCII. A sandbox name is typed on a command
		// line and printed in a table; anything else in it is a mistake at
		// best and something crafted for a log or a terminal at worst.
		if r <= ' ' || r > '~' {
			return fmt.Errorf("enroll: requested sandbox name contains an invalid character %q", r)
		}
	}
	return nil
}

// maxDescriptorLength bounds each of the strings an enrolling host uses to
// describe itself. None of them is an identity — they are recorded for an
// operator to read — but all of them are persisted in the fleet registry and
// printed back in `sandboxctl list`, and a kernel version has no more use for a
// kilobyte than a name does.
const maxDescriptorLength = 256

// maxListenAddresses bounds how many endpoints one request may name. A fleet
// member listens on a handful; the number here is generous for that and still
// keeps the registry a record of a host rather than of a message.
const maxListenAddresses = 32

// checkHostDescription bounds every caller-supplied string on the request
// other than the name, which checkRequestedName has already covered.
//
// These reach the same two places the name does — a registry entry and an
// operator's terminal — so they get the same treatment. Round 2 bounded the
// name because "a sandbox name is typed on a command line and printed in a
// table"; that is equally true of the platform an agent claims to run on and
// the version it claims to be, and those were left unbounded and unchecked.
func checkHostDescription(req *sandboxdv1.EnrollRequest) error {
	p := req.GetPlatform()
	for _, field := range []struct{ name, value string }{
		{"agent version", req.GetAgentVersion()},
		{"platform OS", p.GetOs()},
		{"platform architecture", p.GetArch()},
		{"platform kernel version", p.GetKernelVersion()},
		{"platform hostname", p.GetHostname()},
		{"platform path separator", p.GetPathSeparator()},
	} {
		if err := checkDescriptor(field.name, field.value); err != nil {
			return err
		}
	}

	addrs := req.GetListenAddresses()
	if len(addrs) > maxListenAddresses {
		return fmt.Errorf("enroll: request names %d listen addresses, limit is %d", len(addrs), maxListenAddresses)
	}
	for _, addr := range addrs {
		if err := checkDescriptor("listen address", addr); err != nil {
			return err
		}
	}
	return nil
}

// checkDescriptor bounds one self-described string's length and rejects
// anything in it that is not text.
//
// Control characters are the point: the first listen address becomes the
// registry's address for this sandbox, and every one of these fields is
// printed into `sandboxctl list`'s table. A terminal escape sequence there
// rewrites what the operator sees about their own fleet, and a newline splits
// one row into two.
func checkDescriptor(field, value string) error {
	if len(value) > maxDescriptorLength {
		return fmt.Errorf("enroll: %s is %d bytes, limit is %d", field, len(value), maxDescriptorLength)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("enroll: %s is not valid UTF-8", field)
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("enroll: %s contains a control character %q", field, r)
		}
	}
	return nil
}

// checkRequestedAddresses verifies that every address the enrolling host asked
// to be certified for is one the operator authorized when minting the token,
// and returns the extra hosts the request is allowed to add on its own.
//
// Addresses the agent asks for are checked against the authorized set rather
// than added to it. A loopback address is the one exception, allowed
// unconditionally: it names the enrolling host and nothing else, so it cannot
// be used to impersonate another fleet member, and requiring an operator to
// pre-authorize 127.0.0.1 to run a sandbox locally would be friction with no
// security return.
func checkRequestedAddresses(certName string, authorized, requested []string) ([]string, error) {
	allowedHosts := map[string]bool{}
	if certName != "" {
		allowedHosts[certName] = true
	}
	for _, addr := range authorized {
		if host := hostOf(addr); host != "" {
			allowedHosts[host] = true
		}
	}

	var extra []string
	for _, addr := range requested {
		host := hostOf(addr)
		if host == "" || allowedHosts[host] {
			continue
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			allowedHosts[host] = true
			extra = append(extra, host)
			continue
		}
		if len(authorized) == 0 {
			return nil, fmt.Errorf(
				"enroll: this token authorizes no addresses, so %q cannot be certified; re-mint the token with --address %s",
				host, addr)
		}
		return nil, fmt.Errorf(
			"enroll: address %q is not authorized by this token (authorized: %s)",
			host, strings.Join(authorized, ", "))
	}
	return extra, nil
}

// sanSet assembles the subject alternative names the leaf carries: the name the
// operator reserved for this token, the addresses the operator authorized with
// it, and the loopback addresses checkRequestedAddresses cleared. Nothing the
// enrolling host chose for itself reaches this set.
func sanSet(certName string, authorized, extra []string) (dnsNames []string, ips []net.IP) {
	hosts := map[string]bool{}
	if certName != "" {
		hosts[certName] = true
	}
	for _, addr := range authorized {
		if host := hostOf(addr); host != "" {
			hosts[host] = true
		}
	}
	for _, host := range extra {
		hosts[host] = true
	}

	for host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dnsNames = append(dnsNames, host)
	}
	// Map iteration order is random; a certificate's contents should not be.
	slices.Sort(dnsNames)
	slices.SortFunc(ips, func(a, b net.IP) int { return bytes.Compare(a, b) })
	return dnsNames, ips
}

// hostOf strips the port from a host:port address, tolerating a bare host and
// discarding wildcard listen addresses, which name no host at all.
//
// A bracketed IPv6 literal without a port ("[::1]") is a form SplitHostPort
// rejects, so the brackets are stripped here instead. Leaving them on turned a
// loopback address into a string net.ParseIP could not read, which then reached
// the certificate as a DNS name and was refused there — after the registry
// entry had already been written.
func hostOf(addr string) string {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	} else if len(host) > 1 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if host == "0.0.0.0" || host == "::" {
		return ""
	}
	return host
}

// enrolledSandbox describes the host for the fleet registry. Name is left for
// reserve to fill in, since which name this host ends up with is not settled
// until the record that reserves it succeeds.
func enrolledSandbox(rec TokenRecord, req *sandboxdv1.EnrollRequest) EnrolledSandbox {
	address := ""
	if len(rec.Addresses) > 0 {
		address = rec.Addresses[0]
	} else if addrs := req.GetListenAddresses(); len(addrs) > 0 {
		address = addrs[0]
	}
	p := req.GetPlatform()
	return EnrolledSandbox{
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
