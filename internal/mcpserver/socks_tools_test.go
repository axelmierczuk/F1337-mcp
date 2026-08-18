package mcpserver_test

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"golang.org/x/net/proxy"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver/tools"
	"github.com/axelmierczuk/fleet-mcp/internal/security/policy"
	"github.com/axelmierczuk/fleet-mcp/internal/socks"
)

// fleet_socks against the real agent services, over bufconn, with a real SOCKS
// client on the near end.
//
// The agent under test runs in this process, so "the sandbox's network" is this
// machine's loopback. That is enough topology for everything this tool has to
// get right — a listener on one side, a dialer chosen per connection on the
// other, a policy decision in between — and it lets these point a proxy at real
// servers rather than at a mock. The one thing it cannot show is a name that
// resolves differently on the two sides; test/e2e/socks_test.go has separate
// processes and covers it there.

// ------------------------------------------------------ the policy gate

// The decision #45 left open, and the one this tool exists to make: a model
// does not inherit an operator's "any host" choice.
func TestSocks_RefusesAnAgentThatPermitsEveryHost(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{socksEnabled: true})

	msg := f.liveFails("fleet_socks", nil)
	assert.Contains(t, msg, "forward.allowed_hosts",
		"the refusal must name the setting that fixes it")
	assert.Contains(t, msg, "any host",
		"and say what the agent currently permits")
	assert.Contains(t, msg, "fleetctl socks",
		"and name the operator's own path, which has no such rule")

	// Nothing was opened. A refusal that left a listener behind would be worse
	// than no refusal: the model would hold an address that refuses everything.
	assert.Empty(t, activeProxies(t, f), "a refused proxy must leave no listener")
}

// And an allow list that covers everything, which is the same grant written so
// that it looks like a narrowing.
//
// This is the gate the whole asymmetry leans on, and until now it was the
// length of a list: `allowed_hosts: ["0.0.0.0/0"]` has a length of one, so the
// tool served it, the agent's loudest startup line stayed quiet, and both
// clients printed the entry as a bound. It is also the shape an operator
// arrives at from the refusal's own remedy, which asks them to "list the hosts,
// addresses or CIDR blocks the proxy should reach".
//
// The judgement is the agent's, over the wire in ForwardPolicy.unrestricted:
// this fixture runs the real HostService over the real config, so what is under
// test is the agent's answer rather than this file's opinion of it.
func TestSocks_RefusesAnAllowListThatCoversEveryHost(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{
		socksEnabled:        true,
		forwardAllowedHosts: []string{"0.0.0.0/0"},
	})

	msg := f.liveFails("fleet_socks", nil)
	assert.Contains(t, msg, "0.0.0.0/0",
		"the refusal has to name the entry; an operator told their list is empty will go looking for a line that is in front of them")
	assert.Contains(t, msg, "any host")
	assert.Contains(t, msg, "fleetctl socks")
	assert.Empty(t, activeProxies(t, f), "a refused proxy must leave no listener")
}

// And the other two postures an agent can be in.
func TestSocks_RefusesAnAgentThatDoesNotProxy(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{forwardAllowedHosts: []string{"db.internal"}})

	msg := f.liveFails("fleet_socks", nil)
	assert.Contains(t, msg, "forward.socks_enabled",
		"an agent with an allow list but no proxying still refuses, naming the setting that would permit it")
}

func TestSocks_RefusesAnAgentThatDoesNotForwardAtAll(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{forwardDisabled: true})

	msg := f.liveFails("fleet_socks", nil)
	assert.Contains(t, msg, "forward.enabled")
}

// ------------------------------------------------- the boundary itself

// The gate the whole feature rests on, met by a real SOCKS client on a proxy
// the workstation-side preflight never saw.
//
// Both halves of this are thoroughly tested and they never meet. The agent's
// refusal is asserted against a ForwardOpen built by hand in
// internal/agent/forward; the field that selects it is asserted against a
// recording stream in internal/socks; and every scenario that puts a real
// client in front of a real agent goes through fleet_socks or `fleetctl socks`,
// both of which refuse this configuration on the workstation before a listener
// exists. So the composition — a proxy actually running against an agent that
// does not serve one — was asserted by nothing, and it is the one this PR calls
// the boundary: "enforced per connection on the far side, where no caller can
// skip it".
//
// The preflight is skipped here deliberately. It is the guardrail, and a
// guardrail is exactly what a caller that did not go through this MCP server
// would not have — a hand-written SOCKS client pointed at socks.ForwardConnector
// is a caller of this repository's own shipping code with no preflight in it.
//
// The allow list is non-empty and names the destination, so what refuses the
// connection can only be the capability gate: an agent that judged this as a
// forward would permit it, dial it, and answer 0x00.
func TestSocks_AnAgentThatDoesNotProxyRefusesTheConnectionItself(t *testing.T) {
	destination := startLineServer(t)
	f := newLiveFixture(t, liveAgentOptions{
		// socks_enabled is off — the shipped default — and the allow list
		// permits the destination for forwarding.
		forwardAllowedHosts: []string{"localhost"},
	})

	// The shipping connector against the real agent, behind a real listener,
	// with no policy preflight anywhere in front of it.
	server, err := socks.Listen(0, socks.Options{
		Connect: socks.ForwardConnector(sandboxdv1.NewForwardServiceClient(f.agent.conn)),
	})
	require.NoError(t, err)
	var serving sync.WaitGroup
	serving.Add(1)
	go func() {
		defer serving.Done()
		server.Serve(t.Context())
	}()
	t.Cleanup(func() {
		require.NoError(t, server.Close())
		serving.Wait()
	})

	_, portStr, err := net.SplitHostPort(destination)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	code := connectThroughProxy(t, server.Addr(), "localhost", port)
	require.Equal(t, byte(0x02), code,
		"an agent with forward.socks_enabled false must refuse a proxied connection to a host its allow list permits: the refusal is about the capability, not the destination")

	// And it is recorded against the setting, which is what makes "somebody
	// pointed a proxy at an agent that does not serve one" a line an operator
	// can find.
	var denied *policy.Record
	eventually(t, 30*time.Second, "the refusal to reach the audit log", func() bool {
		for _, rec := range auditRecords(t, f.agent.auditPath) {
			if rec.Outcome == policy.OutcomeDenied {
				denied = &rec
				return true
			}
		}
		return false
	})
	require.NotNil(t, denied)
	assert.Equal(t, "forward.socks_enabled", denied.Rule)
	assert.Equal(t, "localhost", denied.RemoteHost)
	assert.Equal(t, uint32(port), denied.RemotePort)
}

// ------------------------------------------------------------- the tool

// The ordinary case: a narrowed agent, a proxy, and a real client reaching a
// destination through it.
func TestSocks_ReachesADestinationThroughTheSandbox(t *testing.T) {
	destination := startLineServer(t)
	f := newLiveFixture(t, liveAgentOptions{
		socksEnabled: true,
		// The agent dials an allow-listed host by name. Pointed at loopback so
		// the destination is real, and listed by the name the client will send,
		// so what is exercised is the allow list rather than a bypass of it.
		forwardAllowedHosts: []string{"localhost"},
	})

	out := liveOK[tools.SocksResult](f, "fleet_socks", nil)
	require.NotEmpty(t, out.LocalAddress)
	assert.Positive(t, out.LocalPort, "local_port: 0 must allocate and report a port")
	assert.Equal(t, "127.0.0.1", hostOf(t, out.LocalAddress),
		"the listener binds loopback, so it is not reachable from another machine")
	assert.Equal(t, []string{"localhost"}, out.AllowedHosts,
		"the result must say where the proxy may reach; it is the question a caller asks next")
	assert.Contains(t, out.Note, "--socks5-hostname")

	// And every call lists what is open, so nothing has to be remembered.
	require.Len(t, out.Active, 1)
	assert.Equal(t, out.LocalAddress, out.Active[0].LocalAddress)
	assert.Equal(t, liveSandboxName, out.Active[0].Sandbox)

	assert.Equal(t, "HELLO THROUGH THE SANDBOX\n",
		throughProxy(t, out.LocalAddress, destination, "hello through the sandbox\n"))

	// A second call reuses the proxy rather than opening a second listener.
	again := liveOK[tools.SocksResult](f, "fleet_socks", nil)
	assert.True(t, again.Existing)
	assert.Equal(t, out.LocalPort, again.LocalPort)

	// But a call that names a different local port is refused rather than
	// answered with the port that is open: a caller that named one wants that
	// one, and reporting the other as if it had been granted is how a model
	// ends up pointing a client at a port nothing is listening on. Reverting
	// that check left every test in this tree green.
	moved := f.liveFails("fleet_socks", map[string]any{"local_port": out.LocalPort + 1})
	assert.Contains(t, moved, "already proxied")
	assert.Contains(t, moved, "stop=true", "and is told how to move it")

	// Stopping it releases the listener, which is the half a caller can check.
	stopped := liveOK[tools.SocksResult](f, "fleet_socks", map[string]any{"stop": true})
	require.True(t, stopped.Stopped)
	assert.Empty(t, stopped.Active)
	eventually(t, 30*time.Second, "the local listener to close", func() bool {
		return !dialable(out.LocalAddress)
	})

	// And stopping one that is not open says so rather than reporting success.
	msg := f.liveFails("fleet_socks", map[string]any{"stop": true})
	assert.Contains(t, msg, "no proxy is open")
}

// The name crosses the wire unresolved, which is the whole point of a proxy and
// the whole point of --socks5-hostname.
//
// A name that resolves nowhere is what makes this assertable in one process:
// the failure comes back in the *agent's* words, which it could only do if the
// agent is what tried to resolve it. A client that had resolved locally would
// have failed on this side, before the proxy saw anything.
func TestSocks_ResolvesTheDestinationNameOnTheAgent(t *testing.T) {
	const unresolvable = "nowhere.invalid"
	f := newLiveFixture(t, liveAgentOptions{
		socksEnabled:        true,
		forwardAllowedHosts: []string{unresolvable},
	})

	out := liveOK[tools.SocksResult](f, "fleet_socks", nil)

	code := connectThroughProxy(t, out.LocalAddress, unresolvable, 80)
	assert.Equal(t, byte(0x04), code,
		"a name the far side could not resolve is reported as host-unreachable, not as a refused connection")

	// The agent's own sentence, which is what proves where the resolution was
	// attempted. It reaches the listing through the connection's failure.
	eventually(t, 30*time.Second, "the agent's resolution failure to reach the listing", func() bool {
		for _, line := range activeProxies(t, f) {
			if strings.Contains(line.LastError, "on the sandbox") {
				return true
			}
		}
		return false
	})
}

// And a name that goes nowhere reads the same whether or not the agent's allow
// list happens to name it.
//
// The test above uses an agent that *lists* the unresolvable name, so the agent
// dials it and the failure comes back in ForwardOpened.error. A name that is
// not listed takes the other path — resolved first, refused as an
// InvalidArgument status — and reached a client as 0x01 "general server
// failure" for exactly the same typo, with nothing in front of it to explain
// why the same command answered differently against two agents.
func TestSocks_AnUnresolvableNameIsUnreachableWhicheverPathReportsIt(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{
		socksEnabled: true,
		// The destination below is deliberately *not* on this list, so the
		// agent resolves before it decides.
		forwardAllowedHosts: []string{"db.internal"},
	})
	out := liveOK[tools.SocksResult](f, "fleet_socks", nil)

	code := connectThroughProxy(t, out.LocalAddress, "nowhere.invalid", 80)
	assert.Equal(t, byte(0x04), code,
		"a name the agent could not resolve is host-unreachable on both of the agent's paths; 0x01 sends the client's operator looking at the proxy")
}

// A destination outside the agent's allow list is refused by the agent, told to
// the client in the protocol's own terms, and recorded.
func TestSocks_DestinationOutsideTheAllowListIsRefusedAndAudited(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{
		socksEnabled:        true,
		forwardAllowedHosts: []string{"10.0.4.0/24"},
	})
	out := liveOK[tools.SocksResult](f, "fleet_socks", nil)

	code := connectThroughProxy(t, out.LocalAddress, "203.0.113.9", 443)
	assert.Equal(t, byte(0x02), code,
		"a destination the agent's policy refused is 'connection not allowed by ruleset', not 'connection refused': a client shown the latter sends its operator to check a service that is up")

	// The single most useful line in the audit file: somebody asked.
	var denied *policy.Record
	eventually(t, 30*time.Second, "the refusal to reach the audit log", func() bool {
		for _, rec := range auditRecords(t, f.agent.auditPath) {
			if rec.Outcome == policy.OutcomeDenied {
				denied = &rec
				return true
			}
		}
		return false
	})
	require.NotNil(t, denied)
	assert.Equal(t, "forward.allowed_hosts", denied.Rule)
	assert.Equal(t, "203.0.113.9", denied.RemoteHost)
	assert.Equal(t, uint32(443), denied.RemotePort)
	assert.Equal(t, "sandboxd.v1.ForwardService/Forward", denied.RPC)
}

// One connection, one audit record, with the destination and the volume in it.
func TestSocks_EveryConnectionProducesExactlyOneAuditRecord(t *testing.T) {
	destination := startLineServer(t)
	f := newLiveFixture(t, liveAgentOptions{
		socksEnabled:        true,
		forwardAllowedHosts: []string{"localhost"},
	})
	out := liveOK[tools.SocksResult](f, "fleet_socks", nil)

	const connections = 5
	for i := range connections {
		payload := fmt.Sprintf("audited-%d\n", i)
		require.Equal(t, strings.ToUpper(payload), throughProxy(t, out.LocalAddress, destination, payload))
	}

	var records []policy.Record
	eventually(t, 30*time.Second, "every connection's record to be written", func() bool {
		records = auditRecords(t, f.agent.auditPath)
		return len(records) >= connections
	})
	require.Len(t, records, connections,
		"one record per connection: not one per proxy, and not two per connection")

	for _, rec := range records {
		assert.Equal(t, policy.OutcomeOK, rec.Outcome)
		assert.Equal(t, "localhost", rec.RemoteHost, "the record names the destination the client asked for")
		assert.NotEmpty(t, rec.ResolvedAddress, "and the address it actually went to")
		assert.Positive(t, rec.BytesToRemote)
		assert.Positive(t, rec.BytesFromRemote)
		assert.NotContains(t, string(mustJSON(t, rec)), "audited-",
			"the record counts bytes and never holds them")
	}
}

// ------------------------------------------------ concurrency and volume

func TestSocks_CarriesManyConcurrentConnections(t *testing.T) {
	destination := startLineServer(t)
	f := newLiveFixture(t, liveAgentOptions{
		socksEnabled:        true,
		forwardAllowedHosts: []string{"localhost"},
	})
	out := liveOK[tools.SocksResult](f, "fleet_socks", nil)

	const n = 24
	var wg sync.WaitGroup
	got := make([]string, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i] = throughProxy(t, out.LocalAddress, destination, fmt.Sprintf("concurrent-%d\n", i))
		}()
	}
	wg.Wait()

	for i := range n {
		assert.Equalf(t, fmt.Sprintf("CONCURRENT-%d\n", i), got[i], "connection %d", i)
	}
}

// A large body streams rather than accumulating, and the assertion is on
// arrival order rather than on bytes eventually matching: the first chunk has
// to reach the client while the destination is still writing the rest, which a
// proxy that buffered the whole body could not do. Written as a deadlock rather
// than a timing comparison so it cannot pass slowly.
func TestSocks_LargeTransferStreamsRatherThanBuffering(t *testing.T) {
	const (
		chunk  = 64 * 1024
		chunks = 128 // 8 MiB, comfortably past every buffer in the path
	)
	firstChunkRead := make(chan struct{})
	destination := startDestination(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		body := make([]byte, chunk)
		for i := range body {
			body[i] = byte('a' + i%26)
		}
		if _, err := conn.Write(body); err != nil {
			return
		}
		select {
		case <-firstChunkRead:
		case <-time.After(60 * time.Second):
			return
		}
		for range chunks - 1 {
			if _, err := conn.Write(body); err != nil {
				return
			}
		}
	})

	f := newLiveFixture(t, liveAgentOptions{
		socksEnabled:        true,
		forwardAllowedHosts: []string{"localhost"},
	})
	out := liveOK[tools.SocksResult](f, "fleet_socks", nil)

	conn := openProxiedConnection(t, out.LocalAddress, destination)
	first := make([]byte, chunk)
	_, err := io.ReadFull(conn, first)
	require.NoError(t, err, "the first chunk must arrive before the body is complete; a proxy that buffered the whole body would deadlock here")
	close(firstChunkRead)

	rest, err := io.ReadAll(conn)
	require.NoError(t, err)
	assert.Equal(t, chunk*chunks, len(first)+len(rest), "and the whole body still arrives")
}

// A client that has finished sending is still waiting to receive. Shutting the
// whole connection at a half-close is the bug that makes `curl` hang.
func TestSocks_HalfCloseLetsTheResponseComeBack(t *testing.T) {
	const reply = "answered only once the request had ended"
	destination := startDestination(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		if _, err := io.Copy(io.Discard, conn); err != nil {
			return
		}
		_, _ = conn.Write([]byte(reply))
	})

	f := newLiveFixture(t, liveAgentOptions{
		socksEnabled:        true,
		forwardAllowedHosts: []string{"localhost"},
	})
	out := liveOK[tools.SocksResult](f, "fleet_socks", nil)

	conn := openRawProxiedConnection(t, out.LocalAddress, destination)
	_, err := conn.Write([]byte("a request the server will not answer until it ends"))
	require.NoError(t, err)
	require.NoError(t, conn.CloseWrite())

	got, err := io.ReadAll(conn)
	require.NoError(t, err)
	assert.Equal(t, reply, string(got))
}

// ------------------------------------------------------------- lifetime

// The MCP server exiting releases every listener and every connection.
//
// A listener that survived the process would hold its port against the next
// server, and the user would see "address already in use" from a process that
// no longer exists.
func TestSocks_ServerCloseReleasesEveryListener(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{
		socksEnabled:        true,
		forwardAllowedHosts: []string{"localhost"},
	})
	out := liveOK[tools.SocksResult](f, "fleet_socks", nil)
	require.True(t, dialable(out.LocalAddress))

	require.NoError(t, f.server.Close())

	assert.False(t, dialable(out.LocalAddress), "the listener must be gone by the time Close returns")

	// Genuinely released, not merely deaf: the port is free for the next
	// process to want it.
	_, port, err := net.SplitHostPort(out.LocalAddress)
	require.NoError(t, err)
	lis, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", port))
	require.NoError(t, err, "the port was not released")
	require.NoError(t, lis.Close())
}

// Deregistering a sandbox closes the proxy that reached through it, for the
// same reason it closes the forwards: the pooled channel behind it is dropped,
// so what would be left is a local port that accepts a connection and then
// fails it — and a client pointed at a proxy cannot tell that from every
// destination being down.
func TestSocks_RemovingTheSandboxClosesItsProxy(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{
		socksEnabled:        true,
		forwardAllowedHosts: []string{"localhost"},
	})
	out := liveOK[tools.SocksResult](f, "fleet_socks", nil)
	require.True(t, dialable(out.LocalAddress))

	removed := liveOK[tools.RemoveResult](f, "fleet_remove", map[string]any{"name": f.sandbox})
	assert.Equal(t, out.LocalAddress, removed.ProxyClosed)
	assert.Contains(t, removed.Note, out.LocalAddress)

	eventually(t, 30*time.Second, "the proxy's listener to close with its sandbox", func() bool {
		return !dialable(out.LocalAddress)
	})
}

// --------------------------------------------------------------- goleak

// One connection is two pump goroutines, a gRPC stream and two sockets. A proxy
// left open for hours across many connections is where those accumulate, and
// the failure is invisible until the MCP server is slowly using a gigabyte — so
// the count has to come back down, not merely stay plausible.
//
// It counts with the proxy **still open**, and that is the whole point. This
// repository has twice shipped a connection-lifetime leak that a goleak
// assertion could not see, both times because the assertion tore the listener
// down before counting and tearing a listener down cancels everything beneath
// it. A hold that exists only while the proxy is serving is invisible to that
// shape of test by construction. So here every connection is first observed to
// have ended — through the proxy's own open_now, asked of the running server —
// and only then is the count taken, with the listener still accepting.
//
// It counts descriptors as well as goroutines. goleak does not see a socket,
// and a proxy that returns every goroutine while keeping every descriptor still
// stops working after a few thousand connections, just with a different error.
//
// What it still cannot see, and what nothing shaped like it can: a hold that
// ends when the *client* closes. Every connection below eventually closes, so a
// connection released only by that would be released here too. The two cancels
// in tunnel.Carry that exist for exactly that case are pinned instead by
// TestCarry_ReleasesAConnectionWhoseStreamEnded and
// TestCarry_ReleasesAConnectionWhoseLocalClientDied in
// internal/mcpserver/tools, which drive the pump against a client that never
// speaks again and fail deterministically rather than statistically. Both were
// checked by reverting the cancel they name.
func TestSocks_ReleasesEveryConnectionWhileItStaysOpen(t *testing.T) {
	line := startLineServer(t)
	// A destination that reads a request and then resets instead of answering,
	// which is what a server crashing mid-request does to its socket.
	crashing := startDestination(t, func(conn net.Conn) {
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		_ = conn.Close()
	})
	// And one that will volunteer nothing at all: it never reads, never writes,
	// and never closes. Nothing on the far side will ever end one of these, so
	// what ends it has to be this side noticing that its own client is gone.
	parked, releaseParked := startParkedDestination(t)

	f := newLiveFixture(t, liveAgentOptions{
		socksEnabled:        true,
		forwardAllowedHosts: []string{"localhost"},
	})
	out := liveOK[tools.SocksResult](f, "fleet_socks", nil)

	// One of each first, so gRPC's own long-lived goroutines and the pool's own
	// descriptors are in the baseline rather than counted as a hold.
	throughProxy(t, out.LocalAddress, line, "warmup\n")
	abortedThroughProxy(t, out.LocalAddress, crashing)
	resetThroughProxy(t, out.LocalAddress, parked)
	refusedThroughProxy(t, out.LocalAddress)
	waitForNoOpenProxyConnections(t, f)

	baseline := goleak.IgnoreCurrent()
	descriptorsBefore, canCountDescriptors := descriptorSnapshot()

	const (
		sequential = 120
		concurrent = 60
		aborted    = 60
		killed     = 40
		refused    = 40
		idle       = 40
	)

	for i := range sequential {
		throughProxy(t, out.LocalAddress, line, fmt.Sprintf("sequential-%d\n", i))
	}

	// Overlapping, because the sequential case cannot show a hold that only
	// happens when accepts interleave.
	var wg sync.WaitGroup
	for i := range concurrent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			throughProxy(t, out.LocalAddress, line, fmt.Sprintf("concurrent-%d\n", i))
		}()
	}
	wg.Wait()

	// The far side killed mid-request. This is the ordinary way a proxied
	// connection dies, not an exotic one.
	for range aborted {
		wg.Add(1)
		go func() {
			defer wg.Done()
			abortedThroughProxy(t, out.LocalAddress, crashing)
		}()
	}
	wg.Wait()

	// And this side killed mid-request, against a destination that will never
	// volunteer anything: ^C on a curl, a closed browser tab, a client process
	// killed. Nothing on the far side ends these.
	for range killed {
		resetThroughProxy(t, out.LocalAddress, parked)
	}

	// And connections the agent refuses outright, on a proxy that is open and
	// listening: the handshake completes, the stream opens, and the connection
	// ends on the agent's answer before either pump exists.
	for range refused {
		refusedThroughProxy(t, out.LocalAddress)
	}

	// And connections that complete their handshake and then do nothing. A
	// browser's keep-alive connection through a proxy is exactly this: parked,
	// with a send pump waiting on a client that has no reason to speak.
	held := make([]net.Conn, 0, idle)
	for range idle {
		held = append(held, openProxiedConnection(t, out.LocalAddress, line))
	}
	eventually(t, 60*time.Second, "the idle connections to be counted as carried", func() bool {
		return openProxyConnections(t, f) == idle
	})
	for _, conn := range held {
		require.NoError(t, conn.Close())
	}

	// Now the count, with the proxy still open and still listening.
	waitForNoOpenProxyConnections(t, f)

	// The stand-in server's own sockets go last, and only now: the proxy has
	// already been observed releasing every connection, so what is left to count
	// is the proxy's, not the fixture's.
	releaseParked()

	goleak.VerifyNone(t, baseline)

	if canCountDescriptors {
		descriptorsAfter, _ := descriptorSnapshot()
		// No growth at all, rather than a tolerance. Everything opened above is
		// a connection that has been observed to end, and the listeners were
		// open before the baseline was taken, so there is nothing left for a
		// tolerance to cover — and a tolerance is where a leak of one descriptor
		// every seven connections hides.
		assert.LessOrEqualf(t, len(descriptorsAfter), len(descriptorsBefore),
			"descriptors grew from %d to %d across %d proxied connections, and goleak does not see a socket: %s",
			len(descriptorsBefore), len(descriptorsAfter),
			sequential+concurrent+aborted+killed+refused+idle,
			describeNewDescriptors(descriptorsBefore, descriptorsAfter))
	}

	// And the proxy still works, so none of the above was achieved by breaking
	// it.
	assert.Equal(t, "STILL SERVING\n", throughProxy(t, out.LocalAddress, line, "still serving\n"))
}

// --------------------------------------------------------------- helpers

// activeProxies is the tool's own listing, asked of the running server.
func activeProxies(t *testing.T, f *liveFixture) []tools.SocksLine {
	t.Helper()
	// Reading the listing means opening or reusing a proxy, which for a fixture
	// that refuses to open one is itself an error — so a refusal is read as an
	// empty listing rather than as a failure.
	res := f.call("fleet_socks", nil)
	if res.IsError {
		return nil
	}
	return structured[tools.SocksResult](t, res).Active
}

// openProxyConnections asks the proxy how many connections it is carrying right
// now. A repeated call for an open proxy reuses it, so this is a question
// rather than an action.
func openProxyConnections(t *testing.T, f *liveFixture) int {
	t.Helper()
	for _, line := range activeProxies(t, f) {
		return line.OpenNow
	}
	return -1
}

func waitForNoOpenProxyConnections(t *testing.T, f *liveFixture) {
	t.Helper()
	eventually(t, 60*time.Second, "the proxy to release every connection", func() bool {
		return openProxyConnections(t, f) == 0
	})
}

// startLineServer answers one newline-terminated request, upper-cased, and
// closes. Request-and-response rather than echo-at-EOF because the SOCKS client
// used here does not expose a half-close.
func startLineServer(t *testing.T) string {
	t.Helper()
	return startDestination(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte(strings.ToUpper(line)))
	})
}

// startDestination runs a destination on loopback and returns its address.
// It is startTCPServer from the forward tests, which already runs one of these,
// with the address a SOCKS request needs rather than the bare port a forward
// does.
func startDestination(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	return loopbackAddress(startTCPServer(t, handle))
}

// startParkedDestination accepts and holds: it never reads, never writes and
// never closes. It is the forward tests' parked server — one accept goroutine
// and no goroutine per connection, so this fixture's own goroutines and
// descriptors are a constant rather than something a leak count has to allow
// for.
func startParkedDestination(t *testing.T) (string, func()) {
	t.Helper()
	server, release := startParkedServer(t)
	return loopbackAddress(server), release
}

func loopbackAddress(server remoteServer) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(server.port))
}

// throughProxy opens a proxied connection, sends payload, and reads the answer.
func throughProxy(t *testing.T, proxyAddr, destination, payload string) string {
	t.Helper()
	conn := openProxiedConnection(t, proxyAddr, destination)
	defer func() { _ = conn.Close() }()

	_, err := conn.Write([]byte(payload))
	require.NoError(t, err)
	got, err := io.ReadAll(conn)
	require.NoError(t, err)
	return string(got)
}

// openProxiedConnection completes a SOCKS5 CONNECT to destination, by name.
//
// The destination is spelled "localhost" rather than "127.0.0.1" so the request
// carries a name: it is the address type a proxy exists to carry, and the one
// the agent's allow list is matched against.
func openProxiedConnection(t *testing.T, proxyAddr, destination string) net.Conn {
	t.Helper()
	_, port, err := net.SplitHostPort(destination)
	require.NoError(t, err)

	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	require.NoError(t, err)
	conn, err := dialer.(proxy.ContextDialer).DialContext(t.Context(), "tcp", net.JoinHostPort("localhost", port))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(60*time.Second)))
	return conn
}

// connectThroughProxy performs the handshake by hand and returns the reply
// code, which is the only way to assert on a refusal: a client library turns
// every non-zero code into the same error.
func connectThroughProxy(t *testing.T, proxyAddr, host string, port int) byte {
	t.Helper()
	conn, code := handshakeThroughProxy(t, proxyAddr, host, port)
	_ = conn.Close()
	return code
}

// openRawProxiedConnection is [openProxiedConnection] for the assertions that
// need the socket itself: a half-close and a linger-zero reset are both
// *net.TCPConn methods, and golang.org/x/net/proxy hands back a wrapper that
// has neither. The interop client is used everywhere it can be; this is where
// it cannot.
func openRawProxiedConnection(t *testing.T, proxyAddr, destination string) *net.TCPConn {
	t.Helper()
	_, portStr, err := net.SplitHostPort(destination)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	conn, code := handshakeThroughProxy(t, proxyAddr, "localhost", port)
	require.Equalf(t, byte(0x00), code, "the proxy refused the connection with code 0x%02x", code)
	tcp, ok := conn.(*net.TCPConn)
	require.True(t, ok)
	return tcp
}

// handshakeThroughProxy greets and sends one CONNECT, returning the socket and
// the reply code.
func handshakeThroughProxy(t *testing.T, proxyAddr, host string, port int) (net.Conn, byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(60*time.Second)))

	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	var greeting [2]byte
	_, err = io.ReadFull(conn, greeting[:])
	require.NoError(t, err)
	require.Equal(t, byte(0x05), greeting[0])
	require.Equal(t, byte(0x00), greeting[1])

	request := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	request = append(request, host...)
	request = binary.BigEndian.AppendUint16(request, uint16(port)) //nolint:gosec // a port in a test is well inside uint16
	_, err = conn.Write(request)
	require.NoError(t, err)

	var reply [10]byte
	_, err = io.ReadFull(conn, reply[:])
	require.NoError(t, err)
	require.Equal(t, byte(0x05), reply[0])
	return conn, reply[1]
}

// abortedThroughProxy sends a request whose far side is reset before it
// answers, and reads the connection out. The client behaves — it notices the
// end and hangs up — because that is what every real one does, and it is what
// lets the agent's own handler unwind.
func abortedThroughProxy(t *testing.T, proxyAddr, destination string) {
	t.Helper()
	conn := openProxiedConnection(t, proxyAddr, destination)
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write([]byte("a request nobody is going to answer\n"))
	_, _ = io.ReadAll(conn)
}

// resetThroughProxy kills the local client the way ^C or a closed browser tab
// does: a reset rather than a graceful close, so the proxy learns the client is
// gone rather than that it has finished sending.
func resetThroughProxy(t *testing.T, proxyAddr, destination string) {
	t.Helper()
	conn := openRawProxiedConnection(t, proxyAddr, destination)
	require.NoError(t, conn.SetLinger(0))
	_, _ = conn.Write([]byte("a request the client will not wait for\n"))
	require.NoError(t, conn.Close())
}

// refusedThroughProxy asks for a destination the agent's policy refuses. The
// handshake completes and the connection ends on the agent's answer, before
// either pump exists — the shape where a carry returns without ever pumping.
func refusedThroughProxy(t *testing.T, proxyAddr string) {
	t.Helper()
	require.Equal(t, byte(0x02), connectThroughProxy(t, proxyAddr, "203.0.113.9", 443))
}

// dialable reports whether something is accepting at addr, which is how a
// released listener is told from a delisted one.
func dialable(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func hostOf(t *testing.T, address string) string {
	t.Helper()
	host, _, err := net.SplitHostPort(address)
	require.NoError(t, err)
	return host
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	require.NoError(t, err)
	return out
}
