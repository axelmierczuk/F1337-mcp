package client

import "github.com/axelmierczuk/fleet-mcp/internal/registry"

// Target is one sandbox as a dialer needs it: which name to pool a channel
// under, which address to reach it at, and whether this fleet's own transport
// authentication is in force for it.
//
// It is one value rather than the (name, address) pair it replaces because
// [Target.Insecure] has to travel with the address it applies to. A caller that
// passed the pair and forgot the third field would dial a plaintext agent over
// mTLS — a connection failure, which is survivable — or, on a pool holding no
// credentials at all, would fail to build a channel for a sandbox that was
// reachable all along. Both are the kind of drift a struct removes.
type Target struct {
	// Name is the fleet-unique name. It is the pool's key, so two targets
	// naming the same sandbox share a channel.
	Name string
	// Address is the agent's host:port.
	Address string
	// Insecure dials this sandbox in plaintext: no client certificate is
	// presented, the agent's certificate is not verified, and nothing is
	// encrypted by this product.
	//
	// It is the client half of the agent's `tls.enabled: false`, and it is
	// only ever safe on a network that authenticates its own peers. See
	// [registry.Sandbox.Insecure] and docs/security.md.
	Insecure bool
}

// TargetFor is the registry entry as a dial target.
//
// It exists so the posture recorded in the registry and the posture dialled
// with are one fact with one conversion, rather than three fields copied by
// hand at every call site — which is exactly where a new field gets dropped.
func TargetFor(sb registry.Sandbox) Target {
	return Target{Name: sb.Name, Address: sb.Address, Insecure: sb.Insecure}
}

// Authenticated reports whether this fleet's own transport authenticates the
// connection. It is the word `fleetctl list` and `fleet_info` render.
func (t Target) Authenticated() bool { return !t.Insecure }

// AuthName is how a target's transport authentication is named in every view
// of the fleet — `fleetctl list`, `fleetctl info`, `fleet_list`, `fleet_info`.
//
// One function, for the same reason the health names live in this package: an
// operator's word for a sandbox's posture and the model's word for it must not
// drift apart.
func (t Target) AuthName() string {
	if t.Insecure {
		return AuthNone
	}
	return AuthMTLS
}

// The names a sandbox's transport authentication is reported under.
const (
	// AuthMTLS means both ends presented certificates issued by the fleet CA.
	AuthMTLS = "mtls"
	// AuthNone means this fleet authenticated neither end: whatever the
	// network provides is the whole of it.
	AuthNone = "none"
)
