package agent_test

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/agent"
)

// forward.socks_enabled defaults to false, and that default is the whole
// security posture of #45: a proxy reaches every host the machine's network
// reaches, so it has to be something an operator turned on rather than
// something that arrived with an upgrade.

func writeConfig(t *testing.T, body string) *agent.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
listen: "0.0.0.0:8722"
tls:
  certificate: "agent.crt"
  private_key: "agent.key"
  ca_bundle: "ca.crt"
`+body), 0o600))

	cfg, err := agent.Load(path)
	require.NoError(t, err)
	return cfg
}

func TestSocksConfig_DefaultsToOff(t *testing.T) {
	cfg := writeConfig(t, "")
	assert.False(t, cfg.Forward.SocksEnabled,
		"a config that never mentions proxying must not permit it")
	assert.False(t, cfg.Forward.SocksAllowsAnyHost(),
		"an agent that does not proxy is not an unrestricted pivot, whatever its allow list says")
}

// The one configuration that makes the agent a general-purpose pivot, named so
// that the daemon and both clients can say so in the same words.
func TestSocksConfig_UnrestrictedIsProxyingWithNoAllowList(t *testing.T) {
	cfg := writeConfig(t, `
forward:
  socks_enabled: true
`)
	require.True(t, cfg.Forward.SocksEnabled)
	assert.True(t, cfg.Forward.SocksAllowsAnyHost())

	narrowed := writeConfig(t, `
forward:
  socks_enabled: true
  allowed_hosts: ["10.0.4.0/24"]
`)
	assert.True(t, narrowed.Forward.SocksEnabled)
	assert.False(t, narrowed.Forward.SocksAllowsAnyHost(),
		"an allow list is what stops a proxy being unrestricted")

	// And an allow list without proxying is not a proxy at all. This is the
	// configuration every agent that used #26's allowed_hosts already has, and
	// it must not have become a proxy when this feature landed.
	forwardOnly := writeConfig(t, `
forward:
  allowed_hosts: ["db.internal"]
`)
	assert.False(t, forwardOnly.Forward.SocksEnabled)
	assert.False(t, forwardOnly.Forward.SocksAllowsAnyHost())
}

// The allow list is one list for both paths, and #45 asks it to hold CIDR
// blocks as well as names. A block that did not match would be an allow list
// that reads as permitting a subnet and permits nothing.
func TestAllowedHosts_MatchAddressesAndBlocks(t *testing.T) {
	cfg := agent.ForwardConfig{AllowedHosts: []string{
		"build-host.internal", " 10.0.4.7 ", "10.9.0.0/16", "2001:db8::/32",
	}}

	assert.True(t, cfg.AddressAllowed(net.ParseIP("10.0.4.7")), "a listed address matches itself")
	assert.True(t, cfg.AddressAllowed(net.ParseIP("10.9.3.1")), "an address inside a listed block matches")
	assert.True(t, cfg.AddressAllowed(net.ParseIP("2001:db8::1")), "and an IPv6 block")

	assert.False(t, cfg.AddressAllowed(net.ParseIP("10.8.3.1")), "an address outside every block does not")
	assert.False(t, cfg.AddressAllowed(net.ParseIP("2001:db9::1")))
	assert.False(t, cfg.AddressAllowed(nil))

	// A hostname entry is matched as a name, never resolved to an address.
	// Resolving it would make the answer depend on what DNS said at this
	// instant, for the one kind of entry an operator wrote precisely because
	// the name is the stable part.
	assert.True(t, cfg.HostAllowed("BUILD-HOST.INTERNAL"))
	assert.False(t, cfg.AddressAllowed(net.ParseIP("127.0.0.1")),
		"a name on the list does not make loopback an allowed address")
}

// A block nobody can parse silently becomes a hostname that nothing matches:
// safe, and confusing. Worth a line in the log and not worth refusing to start
// over — a stray character in a setting the agent may never use should not stop
// it serving.
func TestAllowedHosts_MalformedEntriesAreReportedNotFatal(t *testing.T) {
	cfg := agent.ForwardConfig{AllowedHosts: []string{
		"db.internal",    // a name
		"10.0.4.7",       // an address
		"10.9.0.0/16",    // a block
		"10.0.0.0/33",    // a block with an impossible prefix
		"10.0.4.256",     // an address with an impossible octet
		"10.0.0.0 /8",    // a block with a stray space
		"my-host-2",      // a name with digits in it, which is not numeric
		"::1",            // an address
		"2001:db8::/129", // an IPv6 block with an impossible prefix
	}}

	assert.ElementsMatch(t,
		[]string{"10.0.0.0/33", "10.0.4.256", "10.0.0.0 /8", "2001:db8::/129"},
		cfg.MalformedAllowedHosts(),
		"only entries that were trying to be an address or a block are judged; a hostname is whatever the operator's resolver knows")

	// And the broken ones match nothing, rather than matching everything.
	assert.False(t, cfg.AddressAllowed(net.ParseIP("10.0.0.1")))
	assert.False(t, cfg.AddressAllowed(net.ParseIP("10.0.4.255")))
	assert.True(t, cfg.AddressAllowed(net.ParseIP("10.9.0.1")), "the entries that do parse still work")
}

// A block whose host bits are set is valid and wider than it reads.
//
// "10.0.4.7/24" is a plausible way to write "this one host" and it permits two
// hundred and fifty-four others. MalformedAllowedHosts cannot see it, because
// the entry is not malformed — net.ParseCIDR accepts it — so it is the one way
// this list fails wider than the operator wrote, which is the direction that
// matters for a pivot's allow list.
func TestAllowedHosts_ABlockWiderThanItReadsIsReported(t *testing.T) {
	cfg := agent.ForwardConfig{AllowedHosts: []string{
		"10.0.4.7/24",      // meant one host, permits the block
		"10.9.0.0/16",      // written as its own network: nothing to say
		"2001:db8:1::5/48", // the same mistake in IPv6
		"10.0.4.7",         // no mask at all, so exactly one host
		"db.internal",      // a name
		"10.0.0.0/33",      // malformed, which is the other check's business
	}}

	widened := cfg.WidenedAllowedHosts()
	require.Len(t, widened, 2, "only the entries wider than they read: %v", widened)
	assert.Contains(t, widened[0], "10.0.4.7/24")
	assert.Contains(t, widened[0], "10.0.4.0/24", "the warning has to say what it actually permits")
	assert.Contains(t, widened[1], "2001:db8:1::5/48")
	assert.Contains(t, widened[1], "2001:db8:1::/48")

	// And it is a report, not a refusal: the block still works, because these
	// are the semantics every other tool applies to a mask.
	assert.True(t, cfg.AddressAllowed(net.ParseIP("10.0.4.99")))
}

// An allow list holding a block that covers its whole address family narrows
// nothing, and the length of the list is the only thing that could ever have
// shown it.
//
// This is the shape an operator arrives at when they want the lab-box posture
// and have been told — by fleet_socks's own refusal, in as many words — to
// "list the hosts, addresses or CIDR blocks the proxy should reach". Written as
// `0.0.0.0/0` it turned the agent's loudest startup line off and the tool's
// refusal off with it, while permitting every IPv4 host the machine can reach.
func TestAllowedHosts_ABlockCoveringEverythingIsNotANarrowing(t *testing.T) {
	covering := agent.ForwardConfig{SocksEnabled: true, AllowedHosts: []string{"0.0.0.0/0"}}
	require.Len(t, covering.FullCoverAllowedHosts(), 1)
	assert.Contains(t, covering.FullCoverAllowedHosts()[0], "0.0.0.0/0")
	assert.Contains(t, covering.FullCoverAllowedHosts()[0], "IPv4")
	assert.True(t, covering.SocksReachesAnyHost(),
		"a proxy bounded by 0.0.0.0/0 is bounded by nothing, and the agent has to say so")
	assert.False(t, covering.SocksAllowsAnyHost(),
		"the dialing path is a different question: this list still resolves and checks, which is what keeps IPv6 out")

	v6 := agent.ForwardConfig{SocksEnabled: true, AllowedHosts: []string{"::/0"}}
	require.Len(t, v6.FullCoverAllowedHosts(), 1)
	assert.Contains(t, v6.FullCoverAllowedHosts()[0], "IPv6")
	assert.True(t, v6.SocksReachesAnyHost())

	// A genuinely narrowed list, and the two neighbouring spellings that are
	// not /0 — including a half of the address space, which is deliberately not
	// caught: this names the plausible mistake rather than doing CIDR
	// arithmetic that would still miss the next one.
	for _, entry := range []string{"10.0.4.0/24", "0.0.0.0/1", "10.0.4.7", "db.internal", "10.0.0.0/33"} {
		cfg := agent.ForwardConfig{SocksEnabled: true, AllowedHosts: []string{entry}}
		assert.Emptyf(t, cfg.FullCoverAllowedHosts(), "%q is not a block covering everything", entry)
		assert.Falsef(t, cfg.SocksReachesAnyHost(), "%q narrows something", entry)
	}

	// And a covering block on an agent that does not proxy at all is not a
	// proxy posture. It is #26's forwarding allow list, which this feature must
	// not have widened.
	forwardOnly := agent.ForwardConfig{AllowedHosts: []string{"0.0.0.0/0"}}
	assert.False(t, forwardOnly.SocksReachesAnyHost())

	// It is still only a description. The block permits what a block permits.
	assert.True(t, covering.AddressAllowed(net.ParseIP("203.0.113.9")))
	assert.False(t, covering.AddressAllowed(net.ParseIP("2001:db8::1")),
		"an IPv4 block covers one family, which is what every other tool does with a mask")
}

// The shipped example documents the setting; this is what stops it drifting
// from what the code accepts.
func TestSocksConfig_ShippedExampleParses(t *testing.T) {
	path, err := filepath.Abs(filepath.Join("..", "..", "examples", "agent.yaml"))
	require.NoError(t, err)

	cfg, err := agent.Load(path)
	require.NoError(t, err)
	assert.False(t, cfg.Forward.SocksEnabled,
		"the shipped example must not turn a machine into a network pivot")
	assert.Empty(t, cfg.Forward.MalformedAllowedHosts())
}
