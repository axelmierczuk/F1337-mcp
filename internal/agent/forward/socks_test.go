package forward

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	"github.com/axelmierczuk/fleet-mcp/internal/security/policy"
)

// The agent's half of #45 is one gate on the path #26 already built. These
// drive it over a real gRPC connection, like the rest of this file's
// neighbours, because the thing being asserted is what a caller is told — the
// code, the sentence, and the audit line — and a direct call would assert on
// none of the three.

// openSocks starts a stream declared as a proxied connection and consumes the
// ForwardOpened.
func openSocks(ctx context.Context, t *testing.T, client sandboxdv1.ForwardServiceClient, port int, host string) (grpc.BidiStreamingClient[sandboxdv1.ForwardRequest, sandboxdv1.ForwardResponse], *sandboxdv1.ForwardOpened, error) {
	t.Helper()
	stream, err := client.Forward(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&sandboxdv1.ForwardRequest{
		Event: &sandboxdv1.ForwardRequest_Open{Open: &sandboxdv1.ForwardOpen{
			RemotePort: uint32(port), RemoteHost: host, Socks: true,
		}},
	}))
	resp, err := stream.Recv()
	if err != nil {
		return stream, nil, err
	}
	return stream, resp.GetOpened(), nil
}

// socksContext is the deadline every scenario here runs under.
func socksContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// drain half-closes a stream and reads it out, which is how a connection ends
// cleanly — and the audit record is written when it does.
func drain(t *testing.T, stream grpc.BidiStreamingClient[sandboxdv1.ForwardRequest, sandboxdv1.ForwardResponse]) {
	t.Helper()
	require.NoError(t, stream.CloseSend())
	for {
		if _, err := stream.Recv(); err != nil {
			return
		}
	}
}

// ------------------------------------------------------- the socks gate

// The default. An agent nobody turned proxying on for refuses it, and says
// which setting would permit it — an operator who genuinely wants this should
// not have to find the knob by reading source.
func TestSocks_DisabledAgentRefusesNamingTheSetting(t *testing.T) {
	port := echoServer(t)
	svc := newService(t, agent.ForwardConfig{})
	client := serve(t, svc)

	_, _, err := openSocks(socksContext(t), t, client, port, "")
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "forward.socks_enabled",
		"the refusal must name the setting that would permit it")
}

// And it refuses even a target it would happily *forward* to. The refusal is
// about the capability, not about where this connection was going: an agent
// that does not proxy does not proxy to its own loopback either, and answering
// with a destination error would send an operator to check the destination.
func TestSocks_DisabledAgentRefusesEvenAPermittedTarget(t *testing.T) {
	port := echoServer(t)
	svc := newService(t, agent.ForwardConfig{AllowedHosts: []string{"127.0.0.1"}})
	client := serve(t, svc)

	// The same target, forwarded, works — which is what makes the refusal above
	// about proxying rather than about this port.
	_, opened, err := open(socksContext(t), t, client, port, "")
	require.NoError(t, err)
	require.True(t, opened.GetSuccess(), opened.GetError())

	_, _, err = openSocks(socksContext(t), t, client, port, "")
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "forward.socks_enabled")
}

// Turning it on without an allow list is the lab-box posture: any host this
// machine can reach.
func TestSocks_EnabledWithNoAllowListReachesAnyHost(t *testing.T) {
	port := echoServer(t)
	svc := newService(t, agent.ForwardConfig{SocksEnabled: true})
	// Dialed by name, and the name is not one this machine's resolver knows —
	// which is the case a proxy exists for. Pointed back at loopback so the
	// connection can be asserted as made rather than merely permitted.
	svc.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		assert.Equal(t, "anything.internal", host,
			"a proxy dials the name it was given; resolving it here would defeat the point")
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	}
	client := serve(t, svc)

	_, opened, err := openSocks(socksContext(t), t, client, 8080, "anything.internal")
	require.NoError(t, err)
	require.True(t, opened.GetSuccess(), opened.GetError())
}

// The narrowed posture, which is the one #45 asks fleet_socks to require: a
// destination inside a listed CIDR block is reached, and the block is matched
// against what the name resolves to on the agent.
func TestSocks_AllowListPermitsAnAddressInsideAListedBlock(t *testing.T) {
	port := echoServer(t)
	svc := newService(t, agent.ForwardConfig{
		SocksEnabled: true,
		AllowedHosts: []string{"10.0.4.0/24"},
	})
	svc.resolver = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.0.4.7")}}, nil
	}
	svc.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		assert.Equal(t, "10.0.4.7", host,
			"a name that passed by resolution is dialed at the address that passed, not re-resolved")
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	}
	client := serve(t, svc)

	stream, opened, err := openSocks(socksContext(t), t, client, 5432, "db.internal")
	require.NoError(t, err)
	require.True(t, opened.GetSuccess(), opened.GetError())

	// The record is written when the connection *ends*, because that is when
	// the volume and the outcome exist. Ending it here rather than asserting
	// immediately is the difference between a test that reads the log and one
	// that races it.
	drain(t, stream)

	rec := waitForRecord(t, svc)
	assert.Equal(t, policy.OutcomeOK, rec.Outcome)
	assert.Equal(t, "db.internal", rec.RemoteHost, "the record keeps the name the caller asked for")
	assert.Equal(t, uint32(5432), rec.RemotePort)
}

// And a destination outside the list is refused, named, and recorded. The
// refusal says what *is* permitted as well as what is not: a proxy's caller
// chooses destinations one connection at a time, and "not that one" without
// "these ones" costs a round trip per guess.
func TestSocks_DestinationOutsideTheAllowListIsRefusedAndAudited(t *testing.T) {
	svc := newService(t, agent.ForwardConfig{
		SocksEnabled: true,
		AllowedHosts: []string{"10.0.4.0/24"},
	})
	svc.resolver = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.9")}}, nil
	}
	client := serve(t, svc)

	_, _, err := openSocks(socksContext(t), t, client, 443, "elsewhere.example")
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	msg := status.Convert(err).Message()
	assert.Contains(t, msg, "forward.allowed_hosts")
	assert.Contains(t, msg, "elsewhere.example")
	assert.Contains(t, msg, "10.0.4.0/24", "the refusal must say where the proxy may go")

	// The single most useful line in the audit file: somebody asked.
	rec := onlyRecord(t, svc)
	assert.Equal(t, policy.OutcomeDenied, rec.Outcome)
	assert.Equal(t, "forward.allowed_hosts", rec.Rule)
	assert.Equal(t, "elsewhere.example", rec.RemoteHost)
	assert.Equal(t, uint32(443), rec.RemotePort)
	assert.Empty(t, rec.ResolvedAddress, "nothing was dialed, so nothing resolved is recorded")
}

// A refusal for want of the capability is recorded too, and against the setting
// that caused it rather than against the allow list, which had nothing to do
// with it.
func TestSocks_RefusalByTheDisabledSettingIsAudited(t *testing.T) {
	svc := newService(t, agent.ForwardConfig{})
	client := serve(t, svc)

	_, _, err := openSocks(socksContext(t), t, client, 5432, "db.internal")
	require.Error(t, err)

	rec := onlyRecord(t, svc)
	assert.Equal(t, policy.OutcomeDenied, rec.Outcome)
	assert.Equal(t, "forward.socks_enabled", rec.Rule)
	assert.Equal(t, "db.internal", rec.RemoteHost)
	assert.Contains(t, rec.Error, "forward.socks_enabled")
}

// A proxied connection to the agent's own loopback is permitted and, like every
// other loopback connection, not recorded: it reaches a port on a machine the
// caller already has command execution on.
func TestSocks_LoopbackIsPermittedAndNotRecorded(t *testing.T) {
	port := echoServer(t)
	svc := newService(t, agent.ForwardConfig{
		SocksEnabled: true,
		AllowedHosts: []string{"10.0.4.0/24"},
	})
	client := serve(t, svc)

	stream, opened, err := openSocks(socksContext(t), t, client, port, "127.0.0.1")
	require.NoError(t, err)
	require.True(t, opened.GetSuccess(), opened.GetError())
	drain(t, stream)

	assert.Empty(t, records(t, svc),
		"a proxied connection to the sandbox's own loopback adds volume without adding an answer")
}

// ---------------------------------------------------- the forward path

// The gate is on the proxy, and it must not have moved the forward path
// underneath #26. An agent with proxying off and an allow list still forwards
// to exactly the hosts it always did.
func TestSocks_ForwardingIsUnchangedByTheProxySetting(t *testing.T) {
	port := echoServer(t)
	svc := newService(t, agent.ForwardConfig{AllowedHosts: []string{"build-host.internal"}})
	svc.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	}
	client := serve(t, svc)

	_, opened, err := open(socksContext(t), t, client, 8080, "build-host.internal")
	require.NoError(t, err)
	assert.True(t, opened.GetSuccess(), opened.GetError())

	// And a host that is not listed is still refused, on the forward path,
	// whatever proxying is set to.
	_, _, err = open(socksContext(t), t, client, 8080, "192.0.2.1")
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// Turning proxying on must not widen the forward path either. `socks_enabled`
// with an empty allow list means "a proxy may go anywhere"; it does not mean a
// port forward may.
func TestSocks_EnablingProxyingDoesNotWidenForwarding(t *testing.T) {
	svc := newService(t, agent.ForwardConfig{SocksEnabled: true})
	client := serve(t, svc)

	_, _, err := open(socksContext(t), t, client, 8080, "192.0.2.1")
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "forward.allowed_hosts")
}

// ------------------------------------------------------------- the log

// The posture is said out loud at every start, because it is invisible in
// ordinary use: forwarding a dev server works identically whether or not this
// machine is also an unrestricted route into its network.
func TestSocks_StartupLogAnnouncesAnUnrestrictedProxy(t *testing.T) {
	warnings := func(cfg agent.ForwardConfig, audited bool) string {
		t.Helper()
		var buf bytes.Buffer
		logPosture(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})), cfg, audited)
		return buf.String()
	}

	unrestricted := warnings(agent.ForwardConfig{SocksEnabled: true}, true)
	assert.Contains(t, unrestricted, "THIS AGENT WILL PROXY TO ANY HOST IT CAN REACH")
	assert.Contains(t, unrestricted, "forward.allowed_hosts")

	narrowed := warnings(agent.ForwardConfig{SocksEnabled: true, AllowedHosts: []string{"10.0.4.0/24"}}, true)
	assert.NotContains(t, narrowed, "ANY HOST",
		"an operator who narrowed it has nothing to be warned about")
	assert.Contains(t, narrowed, "10.0.4.0/24")

	quiet := warnings(agent.ForwardConfig{}, true)
	assert.NotContains(t, quiet, "PROXY")

	// The two settings are only dangerous together.
	unaudited := warnings(agent.ForwardConfig{SocksEnabled: true, AllowedHosts: []string{"10.0.4.0/24"}}, false)
	assert.Contains(t, unaudited, "NO AUDIT LOG")

	// And an entry nothing will ever match reads as permitting a subnet while
	// permitting nothing, which is a safe failure and a confusing one.
	malformed := warnings(agent.ForwardConfig{SocksEnabled: true, AllowedHosts: []string{"10.0.0.0/33"}}, true)
	assert.Contains(t, malformed, "not a valid address or CIDR block")
	assert.Contains(t, malformed, "10.0.0.0/33")
}
