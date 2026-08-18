package agent

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// ErrUnauthenticatedPublicListen is the refusal at the centre of #85: an agent
// with mTLS off, binding an address that is neither loopback nor private, and
// no flag saying the operator meant it.
//
// With mTLS off this daemon authenticates nobody. Its whole purpose is running
// commands on this host, so a reachable port with nothing in front of it is
// unauthenticated remote code execution — and the failure is silent, because an
// agent that skipped the CA ceremony works immediately and looks identical to a
// secured one. `--listen 0.0.0.0:8722` with no mTLS is the shape this exists to
// refuse.
//
// It is a sentinel so the command that produced it can add the config path and
// the two ways out, and so a test can hold the refusal to this reason rather
// than to any startup failure at all.
var ErrUnauthenticatedPublicListen = errors.New("agent: refusing to serve without mTLS on an address that is neither loopback nor private")

// CheckListenPosture reports whether this config may open its listener.
//
// It is the one function that decides, and it is called twice: by
// [Config.Validate], which is what `fleet-agent serve` runs, and by [New],
// which is what actually binds the socket. Both, because this repository has
// three times shipped a guard the running command reached by another path —
// and because the two callers are the two ways an agent starts.
//
// With mTLS on it permits everything: the handshake is the boundary and a
// public address is a legitimate deployment. With mTLS off it permits only an
// address whose reachability is already bounded — loopback, or a private
// network — unless allowPublic says the operator has accepted the rest.
func CheckListenPosture(cfg *Config, allowPublic bool) error {
	if cfg.TLS.IsEnabled() || allowPublic {
		return nil
	}
	reach, err := classifyListen(cfg.Listen)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnauthenticatedPublicListen, err)
	}
	if reach.bounded {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrUnauthenticatedPublicListen, reach.why)
}

// reachability is what classifyListen concluded about a listen address.
type reachability struct {
	// bounded reports that the address cannot be reached from outside a
	// network the operator already controls.
	bounded bool
	// why names what the address is, for the refusal message.
	why string
}

// classifyListen decides whether an address the agent would bind is reachable
// only from somewhere already bounded.
//
// The rules, and why each is where it is:
//
//   - A wildcard — "0.0.0.0", "::", or no host at all — binds every interface
//     this machine has, including any public one it grows later. It is the
//     default listen address, and it is the exact shape #85 names as the one
//     that must never be allowed silently.
//   - Loopback is reachable only from this machine.
//   - A private address (RFC 1918, unique-local IPv6, link-local) is reachable
//     only from a network the operator is on. So is carrier-grade NAT space,
//     100.64.0.0/10, which is not "private" by [net.IP.IsPrivate] and is where
//     every Tailscale node lives — the precise deployment this option is for.
//   - "localhost" is loopback by every resolver anyone runs, and is what an
//     operator types.
//   - Any other name is refused rather than resolved. Resolving would make a
//     security boundary depend on what DNS answered at this instant, on a
//     machine whose resolver an attacker may control, and would move the
//     posture the day a record changed. An operator with a name has two exact
//     answers available — the address, or the flag — and both say what they
//     mean.
func classifyListen(listen string) (reachability, error) {
	host := strings.TrimSpace(listen)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")

	if host == "" || host == "0.0.0.0" || host == "::" {
		return reachability{why: fmt.Sprintf("%s binds every interface on this host, including any public one", listen)}, nil
	}
	if strings.EqualFold(host, "localhost") {
		return reachability{bounded: true, why: "loopback"}, nil
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return reachability{}, fmt.Errorf("%s names a host this agent cannot judge: %q is not an IP address, and resolving it would make the check depend on what DNS answers", listen, host)
	}
	switch {
	case ip.IsLoopback():
		return reachability{bounded: true, why: "loopback"}, nil
	case ip.IsUnspecified():
		return reachability{why: fmt.Sprintf("%s binds every interface on this host, including any public one", listen)}, nil
	case ip.IsPrivate(), ip.IsLinkLocalUnicast(), isCarrierGradeNAT(ip):
		return reachability{bounded: true, why: "private"}, nil
	default:
		return reachability{why: fmt.Sprintf("%s is a public address", listen)}, nil
	}
}

// cgnat is 100.64.0.0/10, RFC 6598. Every Tailscale node has an address in it,
// and [net.IP.IsPrivate] does not count it as private because it is carrier
// space rather than site space.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func isCarrierGradeNAT(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && cgnat.Contains(v4)
}

// UnauthenticatedListenRemedy is appended to the refusal wherever it reaches an
// operator, so the message that stops a start also says how to proceed.
//
// Three ways out, in the order they should be preferred, and the flag last:
// enrolling is the posture the product is built around, a private address is
// the posture this option exists to support, and the flag is the one that
// leaves an unauthenticated agent on a reachable port.
const UnauthenticatedListenRemedy = "\n\nWith mTLS off this agent authenticates nobody: anyone who can reach this port can run commands on this host as the account it runs as.\n" +
	"Either:\n" +
	"  - enroll this host and set tls.enabled: true, so callers are authenticated by certificate; or\n" +
	"  - listen on a loopback or private address — a tailnet or VPC address is what this posture is for; or\n" +
	"  - pass --allow-unauthenticated-public if this network authenticates its peers and you mean to serve there anyway."
