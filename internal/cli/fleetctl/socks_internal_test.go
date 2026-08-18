package fleetctl

import (
	"bytes"
	"context"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/cli"
	"github.com/axelmierczuk/fleet-mcp/internal/registry"
	"github.com/axelmierczuk/fleet-mcp/internal/socks"
)

// `fleetctl socks` opening a proxy end to end needs a real agent, and
// test/e2e/socks_test.go drives one. What is here is the part that decides
// whether a proxy is opened at all, and the part an operator reads when it is —
// both of which are this file's own and neither of which needs a network.

// The refusals, which are the same three an agent can present.
//
// The one an operator can be in and the tool still proceeds is the fourth:
// proxying on with an empty allow list. That is the whole difference between
// this command and fleet_socks, so it is asserted here rather than left to be
// inferred from the absence of a case.
func TestSocksPolicy_RefusesWhatTheAgentWillNotServe(t *testing.T) {
	t.Run("an agent too old to have one", func(t *testing.T) {
		err := checkSocksPolicy("build-box", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "older than this fleetctl")
	})

	t.Run("forwarding off entirely", func(t *testing.T) {
		err := checkSocksPolicy("build-box", &sandboxdv1.ForwardPolicy{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "forward.enabled")
	})

	t.Run("proxying off", func(t *testing.T) {
		err := checkSocksPolicy("build-box", &sandboxdv1.ForwardPolicy{
			Enabled:      true,
			AllowedHosts: []string{"db.internal"},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "forward.socks_enabled")
		assert.Contains(t, err.Error(), "forward.allowed_hosts",
			"an operator being told to turn it on should be told to narrow it in the same breath")
	})

	t.Run("proxying on with nothing narrowing it", func(t *testing.T) {
		// The case fleet_socks refuses. An operator running this command made
		// the decision themselves, about a machine they chose, now — so the
		// command proceeds and says so, loudly. See printSocksBanner.
		require.NoError(t, checkSocksPolicy("build-box", &sandboxdv1.ForwardPolicy{
			Enabled: true, SocksEnabled: true,
		}))
	})

	t.Run("proxying on and narrowed", func(t *testing.T) {
		require.NoError(t, checkSocksPolicy("build-box", &sandboxdv1.ForwardPolicy{
			Enabled: true, SocksEnabled: true, AllowedHosts: []string{"10.0.4.0/24"},
		}))
	})
}

// The banner is the only place an operator finds out that the proxy they just
// opened is bounded by nothing. It has to be unmissable rather than implied by
// the absence of a line.
func TestSocksBanner_AnnouncesAnUnrestrictedProxy(t *testing.T) {
	banner := func(r socksResult) string {
		var buf bytes.Buffer
		p := cli.NewPrinter(&buf)
		printSocksBanner(p, r)
		require.NoError(t, p.Err())
		return buf.String()
	}

	unrestricted := banner(socksResult{
		Sandbox: "lab-box", LocalAddress: "127.0.0.1:1080", Unrestricted: true,
	})
	assert.Contains(t, unrestricted, "THIS PROXY REACHES ANY HOST LAB-BOX CAN.")
	assert.Contains(t, unrestricted, "forward.allowed_hosts",
		"and names the setting that narrows it")
	assert.Contains(t, unrestricted, "audit log")

	narrowed := banner(socksResult{
		Sandbox: "build-box", LocalAddress: "127.0.0.1:1080",
		AllowedHosts: []string{"10.0.4.0/24", "db.internal"},
	})
	assert.NotContains(t, narrowed, "ANY HOST",
		"an operator who narrowed it has nothing to be warned about")
	assert.Contains(t, narrowed, "db.internal")
	assert.Contains(t, narrowed, "10.0.4.0/24")

	// Both say the two things a reader needs next: what to point at it, and
	// where resolution happens.
	for _, out := range []string{unrestricted, narrowed} {
		assert.Contains(t, out, "--socks5-hostname")
		assert.Contains(t, out, "127.0.0.1:1080")
		assert.Contains(t, out, "resolved on")
	}

	// An allow list that covers everything is the case the two halves of this
	// banner disagree about: it has entries, and it narrows nothing. The
	// warning has to fire *and* name the entry — an operator who reads "ANY
	// HOST" over a list they wrote themselves will believe the list unless the
	// line below says which one is the reason.
	covering := banner(socksResult{
		Sandbox: "lab-box", LocalAddress: "127.0.0.1:1080",
		AllowedHosts: []string{"0.0.0.0/0"}, Unrestricted: true,
	})
	assert.Contains(t, covering, "THIS PROXY REACHES ANY HOST LAB-BOX CAN.")
	assert.Contains(t, covering, "0.0.0.0/0")
	assert.NotContains(t, covering, "is empty",
		"the agent's allow list is not empty here; saying so sends the operator looking for a line that is in front of them")
	assert.NotContains(t, covering, "The agent permits:",
		"a list that covers everything must never be printed as a bound")

	// Client-side narrowing is reported as the convenience it is, never as a
	// boundary: an operator who read it as one would stop narrowing the agent.
	withAllow := banner(socksResult{
		Sandbox: "build-box", LocalAddress: "127.0.0.1:1080",
		AllowedHosts: []string{"10.0.4.0/24"}, Allow: []string{"10.0.4.7:5432"},
	})
	assert.Contains(t, withAllow, "10.0.4.7:5432")
	assert.Contains(t, withAllow, "the agent checks every connection anyway")
}

// The allow list is the agent's own words, and it lands in the banner that says
// what this proxy reaches.
//
// A sandbox is a machine running someone else's code — see TestSafeText — and
// an allow-list entry carrying a terminal escape rewrites the display it is
// printed into, including the line above it that says whether the proxy is
// bounded at all. Every other agent-supplied string this CLI prints is cleaned
// on the way to the terminal; this one was not.
func TestSocksBanner_CleansWhatTheAgentSaidBeforePrintingIt(t *testing.T) {
	var buf bytes.Buffer
	p := cli.NewPrinter(&buf)
	printSocksBanner(p, socksResult{
		Sandbox: "build-box", LocalAddress: "127.0.0.1:1080",
		// An entry that clears the screen and then writes a wider posture than
		// the one this agent has, and one that overwrites the line it is on.
		AllowedHosts: []string{"\x1b[2Jdb.internal", "10.0.4.0/24\rANY HOST"},
	})
	require.NoError(t, p.Err())

	out := buf.String()
	assert.NotContains(t, out, "\x1b", "an escape byte reached the terminal")
	assert.NotContains(t, out, "\r", "a carriage return reached the terminal")
	assert.Contains(t, out, "[2Jdb.internal", "the defused text still names what the agent permits")
	assert.Contains(t, out, "10.0.4.0/24 ANY HOST")

	// And in the note, which is the sentence a --json consumer prints.
	note := socksNote("build-box", "10.0.0.9:8722", false, []string{"\x1b[2Jdb.internal"})
	assert.NotContains(t, note, "\x1b")
	assert.Contains(t, note, "[2Jdb.internal")

	// The count survives cleaning: it is what decides whether this proxy is
	// announced as unrestricted, and a list that shrank would announce the
	// wrong one.
	require.Len(t, safeHosts([]string{"\x1b", "db.internal"}), 2)
	assert.Nil(t, safeHosts(nil))
}

// --json must not silence the warning. The document says so in a field, which
// is right for the script and invisible to the person watching the terminal.
func TestSocksBanner_JSONStillWarnsOnStderr(t *testing.T) {
	warn := func(asJSON bool, r socksResult) string {
		var buf bytes.Buffer
		warnUnrestricted(&buf, &output{w: io.Discard, asJSON: asJSON}, r)
		return buf.String()
	}

	unrestricted := socksResult{Sandbox: "lab-box", Unrestricted: true}
	assert.Contains(t, warn(true, unrestricted), "ANY host lab-box can")
	assert.Contains(t, warn(true, unrestricted), "forward.allowed_hosts")

	assert.Empty(t, warn(true, socksResult{Sandbox: "build-box", AllowedHosts: []string{"db.internal"}}),
		"an operator who narrowed it has nothing to be warned about")

	// And the covering-block case names the entry rather than claiming the list
	// is empty.
	covering := warn(true, socksResult{Sandbox: "lab-box", AllowedHosts: []string{"0.0.0.0/0"}, Unrestricted: true})
	assert.Contains(t, covering, "ANY host lab-box can")
	assert.Contains(t, covering, "0.0.0.0/0")
	assert.NotContains(t, covering, "is empty")
	assert.Empty(t, warn(false, unrestricted),
		"human output carries it in the banner; a second copy would be noise")
}

// The note is what a --json consumer reads instead of the banner, so it has to
// carry the same fact.
func TestSocksNote_SaysWhetherTheProxyIsBounded(t *testing.T) {
	assert.Contains(t, socksNote("lab-box", "10.0.0.9:8722", true, nil), "ANY host")
	bounded := socksNote("build-box", "10.0.0.9:8722", false, []string{"db.internal"})
	assert.Contains(t, bounded, "db.internal")
	assert.NotContains(t, bounded, "ANY host")

	// An allow list that covers everything is the case where the two halves of
	// the sentence disagree: it has entries and it narrows nothing, so the note
	// has to say both or a reader believes the list.
	covering := socksNote("lab-box", "10.0.0.9:8722", true, []string{"0.0.0.0/0"})
	assert.Contains(t, covering, "ANY host")
	assert.Contains(t, covering, "0.0.0.0/0")
}

// The document the command actually emits, assembled from the same three
// things RunE has: the sandbox, the listener, and what the agent said.
//
// Composed inline in RunE, every field here was asserted only against values a
// test wrote itself — which is how the note came to name the local listener in
// a sentence that is about the machine the connections are made from, with the
// sandbox's own address sitting unused in the field next to it.
func TestSocksResult_IsAssembledFromWhatTheCommandHas(t *testing.T) {
	sb := registry.Sandbox{Name: "build-box", Address: "10.0.0.9:8722"}
	server, err := socks.Listen(0, socks.Options{Connect: func(context.Context, net.Conn, socks.Destination, func() error) error {
		return nil
	}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, server.Close()) })

	t.Run("narrowed", func(t *testing.T) {
		r := newSocksResult(sb, server, &sandboxdv1.ForwardPolicy{
			Enabled: true, SocksEnabled: true, AllowedHosts: []string{"db.internal"},
		}, []string{"db.internal:5432"})

		assert.Equal(t, sb.Address, r.Address)
		assert.Equal(t, server.Addr(), r.LocalAddress)
		assert.Equal(t, server.Port(), r.LocalPort)
		assert.False(t, r.Unrestricted)
		assert.Equal(t, []string{"db.internal:5432"}, r.Allow)
		assert.Contains(t, r.Note, sb.Address,
			"the note says which machine the connections are made from, which is the sandbox's address and not this workstation's listener")
		assert.NotContains(t, r.Note, r.LocalAddress,
			"local_address is a field of its own; repeating it here reads as the sandbox being at 127.0.0.1")
	})

	t.Run("an allow list that covers everything", func(t *testing.T) {
		// The agent's own verdict, which is the only place the rule lives. A
		// result that re-derived it from the list's length would call this
		// narrowed and print the list as a bound.
		r := newSocksResult(sb, server, &sandboxdv1.ForwardPolicy{
			Enabled: true, SocksEnabled: true, AllowedHosts: []string{"0.0.0.0/0"}, Unrestricted: true,
		}, nil)

		require.True(t, r.Unrestricted,
			"an allow list of 0.0.0.0/0 narrows nothing, and the agent says so; a banner driven by the list's length would announce a bounded proxy")
		assert.Contains(t, r.Note, "ANY host")
	})

	t.Run("an agent older than the unrestricted field", func(t *testing.T) {
		// It reports an empty list and nothing else, and that shape has to keep
		// reading as unrestricted: the flag defaults to false on the wire.
		r := newSocksResult(sb, server, &sandboxdv1.ForwardPolicy{
			Enabled: true, SocksEnabled: true,
		}, nil)
		assert.True(t, r.Unrestricted)
	})
}

// Naming the sandbox is optional only where it cannot be ambiguous. Guessing
// which of several networks to open a pivot into is not a decision to make on
// someone's behalf.
func TestSoleSandbox_OnlyGuessesWhenThereIsNothingToGuess(t *testing.T) {
	open := func(t *testing.T, sandboxes ...registry.Sandbox) *registry.Registry {
		t.Helper()
		fleet, err := registry.Open(filepath.Join(t.TempDir(), "registry.yaml"))
		require.NoError(t, err)
		for _, sb := range sandboxes {
			require.NoError(t, fleet.Add(sb))
		}
		return fleet
	}

	t.Run("an empty fleet", func(t *testing.T) {
		_, err := soleSandbox(open(t), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "enroll mint")
	})

	t.Run("one sandbox", func(t *testing.T) {
		sb, err := soleSandbox(open(t, registry.Sandbox{Name: "build-box", Address: "10.0.0.9:8722"}), nil)
		require.NoError(t, err)
		assert.Equal(t, "build-box", sb.Name)
	})

	t.Run("several sandboxes", func(t *testing.T) {
		fleet := open(t,
			registry.Sandbox{Name: "build-box", Address: "10.0.0.9:8722"},
			registry.Sandbox{Name: "gpu-01", Address: "10.0.0.10:8722"},
		)
		_, err := soleSandbox(fleet, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "name the sandbox")
		assert.Contains(t, err.Error(), "build-box")
		assert.Contains(t, err.Error(), "gpu-01")

		// And naming one works, by name.
		sb, err := soleSandbox(fleet, []string{"gpu-01"})
		require.NoError(t, err)
		assert.Equal(t, "gpu-01", sb.Name)

		// An unknown name answers with the names that do exist rather than with
		// the one that does not.
		_, err = soleSandbox(fleet, []string{"typo"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "build-box")
	})
}

// The help text is where a reader finds out what this does and does not do, and
// both halves matter: a caller who assumes UDP works builds on a capability
// that does not exist.
func TestSocksCommand_HelpNamesWhatItIsAndIsNot(t *testing.T) {
	var out bytes.Buffer
	cmd := newSocksCommand(&out)

	help := cmd.Short + "\n" + cmd.Long
	for _, want := range []string{
		"ssh -D",
		"--socks5-hostname",
		"CONNECT only",
		"no UDP",
		"loopback",
		"forward.socks_enabled",
		"forward.allowed_hosts",
	} {
		assert.Containsf(t, help, want, "the help must mention %q", want)
	}
	assert.True(t, strings.Contains(help, "not a boundary") || strings.Contains(help, "convenience"),
		"--allow must not read as a security boundary; the agent's list is the boundary")
}
