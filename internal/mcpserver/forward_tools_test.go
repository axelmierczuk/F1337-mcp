package mcpserver_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver/tools"
	"github.com/axelmierczuk/fleet-mcp/internal/security/policy"
)

// The agent under test runs in this process, so "the sandbox's loopback" is
// this machine's loopback. That is exactly the topology a forward has to
// handle — a listener on one side, a dialer on the other, bytes in both
// directions — and it lets these tests point a forward at a real HTTP server
// and a real TCP echo server rather than at a mock.

// ------------------------------------------------------------- the basics

func TestForward_ReachesARemoteHTTPServerOverLocalhost(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	const body = "the response body from the sandbox"
	remote := startHTTPServer(t, body)

	out := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{
		"remote_port": remote.port,
	})
	require.NotEmpty(t, out.LocalAddress)
	assert.Positive(t, out.LocalPort, "local_port: 0 must allocate and report a port")
	assert.Equal(t, remote.port, out.RemotePort)

	got := httpGet(t, "http://"+out.LocalAddress+"/")
	assert.Equal(t, body, got, "the body fetched over localhost must match the sandbox's")

	// The result names the forward as `ssh -L` does, because that is the
	// mental model a reader already has.
	assert.Contains(t, out.Note, "ssh -L")
	assert.Contains(t, out.Note, "loopback")

	// And every call lists what is open, so nothing has to be remembered.
	require.Len(t, out.Active, 1)
	assert.Equal(t, out.LocalAddress, out.Active[0].LocalAddress)
	assert.Equal(t, liveSandboxName, out.Active[0].Sandbox)
}

func TestForward_ZeroLocalPortAllocatesAUsablePort(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	remote := startHTTPServer(t, "allocated")

	out := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{
		"remote_port": remote.port,
		"local_port":  0,
	})
	require.Positive(t, out.LocalPort)
	assert.Equal(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(out.LocalPort)), out.LocalAddress)

	// Usable, not merely reported: the number that came back is the number
	// that serves.
	assert.Equal(t, "allocated", httpGet(t, fmt.Sprintf("http://127.0.0.1:%d/", out.LocalPort)))
}

func TestForward_HonoursAnExplicitLocalPort(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	remote := startHTTPServer(t, "explicit")
	want := freePort(t)

	out := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{
		"remote_port": remote.port,
		"local_port":  want,
	})
	assert.Equal(t, want, out.LocalPort)
	assert.Equal(t, "explicit", httpGet(t, fmt.Sprintf("http://127.0.0.1:%d/", want)))
}

// ------------------------------------------------------ concurrency, size

func TestForward_CarriesManyConcurrentConnections(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	remote := startHTTPServer(t, "concurrent")

	out := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{"remote_port": remote.port})
	url := "http://" + out.LocalAddress + "/"

	const n = 24
	var wg sync.WaitGroup
	errs := make([]error, n)
	bodies := make([]string, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := forwardClient().Get(url) //nolint:noctx // the client carries a timeout
			if err != nil {
				errs[i] = err
				return
			}
			defer func() { _ = resp.Body.Close() }()
			b, err := io.ReadAll(resp.Body)
			errs[i], bodies[i] = err, string(b)
		}()
	}
	wg.Wait()

	for i := range n {
		require.NoErrorf(t, errs[i], "connection %d failed", i)
		assert.Equal(t, "concurrent", bodies[i])
	}

	// The forward counts what went through it, so a later call can see it is
	// carrying traffic rather than merely open.
	after := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{"remote_port": remote.port})
	require.Len(t, after.Active, 1)
	assert.GreaterOrEqual(t, after.Active[0].Connections, uint64(n))
	assert.True(t, after.Existing, "a second call for the same port reuses the forward rather than opening another")
}

// A large transfer must stream. The first byte is echoed back before the bulk
// is sent, so an implementation that buffered a whole direction before
// forwarding it would deadlock here rather than merely be slow.
func TestForward_StreamsALargeTransferWithoutBufferingIt(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	remote := startEchoServer(t)

	out := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{"remote_port": remote.port})

	conn, err := net.DialTimeout("tcp", out.LocalAddress, 5*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(60*time.Second)))

	// One byte out, one byte back: proof that bytes move in both directions
	// while both sides are still open.
	_, err = conn.Write([]byte{0x42})
	require.NoError(t, err)
	one := make([]byte, 1)
	_, err = io.ReadFull(conn, one)
	require.NoError(t, err, "the echo must come back before the bulk transfer starts")
	assert.Equal(t, byte(0x42), one[0])

	const size = 8 << 20
	payload := make([]byte, size)
	_, err = rand.Read(payload)
	require.NoError(t, err)

	var readErr error
	got := make([]byte, size)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, readErr = io.ReadFull(conn, got)
	}()

	_, err = conn.Write(payload)
	require.NoError(t, err)
	<-done
	require.NoError(t, readErr)
	assert.True(t, bytes.Equal(payload, got), "8 MiB must arrive byte-identical")
}

// -------------------------------------------------------------- half-close

// A client that has finished sending must still receive the response. This is
// what `curl` does on a request with no keep-alive, and getting it wrong
// produces a forward that works for browsers and hangs for scripts.
func TestForward_HalfCloseInEachDirectionIsIndependent(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	// A server that reads to EOF and only then answers: it cannot reply until
	// the client's write side is closed, so the reply proves the half-close
	// travelled and that the read direction survived it.
	remote := startReadThenReplyServer(t, "answered after EOF")

	out := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{"remote_port": remote.port})

	conn, err := net.DialTimeout("tcp", out.LocalAddress, 5*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))

	_, err = conn.Write([]byte("a request"))
	require.NoError(t, err)
	require.NoError(t, conn.(*net.TCPConn).CloseWrite(), "half-close the local write side")

	reply, err := io.ReadAll(conn)
	require.NoError(t, err, "a client that closed its write side must still receive the response")
	assert.Equal(t, "answered after EOF", string(reply))
}

// The other direction: the sandbox-side server closes first, and the local
// client sees a clean EOF rather than a reset.
func TestForward_RemoteCloseGivesTheLocalClientACleanEOF(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	remote := startGreetThenCloseServer(t, "goodbye")

	out := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{"remote_port": remote.port})

	conn, err := net.DialTimeout("tcp", out.LocalAddress, 5*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))

	got, err := io.ReadAll(conn)
	require.NoError(t, err, "the close must arrive as EOF, not as a connection reset")
	assert.Equal(t, "goodbye", string(got))
}

// And the direction that is easy to get wrong: after the sandbox-side server
// has closed its write half, the client may still be sending, and those bytes
// must still arrive. Shutting the whole connection on a half-close is the bug
// this catches, and it is invisible to every test above.
func TestForward_ClientCanStillSendAfterTheRemoteHalfCloses(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})

	// Buffered, and read until the expected body turns up: the forward's
	// preflight opens a connection of its own before the listener exists, and
	// it contributes an empty body.
	bodies := make(chan string, 8)
	remote := startTCPServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte("greeting"))
		// Half-close: finished writing, still reading.
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		body, _ := io.ReadAll(conn)
		bodies <- string(body)
	})

	out := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{"remote_port": remote.port})

	conn, err := net.DialTimeout("tcp", out.LocalAddress, 5*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))

	greeting, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.Equal(t, "greeting", string(greeting), "the remote's write half closed, so this reads to EOF")

	// The read direction is finished; the write direction is not.
	_, err = conn.Write([]byte("sent after the remote closed"))
	require.NoError(t, err, "the local write side must survive the remote's half-close")
	require.NoError(t, conn.(*net.TCPConn).CloseWrite())

	deadline := time.After(20 * time.Second)
	for {
		select {
		case body := <-bodies:
			if body == "" {
				continue // the preflight connection
			}
			assert.Equal(t, "sent after the remote closed", body)
			return
		case <-deadline:
			t.Fatal("the sandbox-side server never saw the bytes sent after its own half-close")
		}
	}
}

// -------------------------------------------------------------- lifetime

// A forward is owned by the MCP server process, not by the call that opened
// it: it has to still be there after unrelated tool calls.
func TestForward_SurvivesUnrelatedToolCalls(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	remote := startHTTPServer(t, "still here")

	out := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{"remote_port": remote.port})
	url := "http://" + out.LocalAddress + "/"
	assert.Equal(t, "still here", httpGet(t, url))

	// Several unrelated calls, including ones that start and stop processes.
	started := liveOK[tools.ProcessStartResult](f, "fleet_process_start", f.startHelper("unrelated", "silent"))
	liveOK[tools.ProcessListResult](f, "fleet_process_list", map[string]any{})
	liveOK[tools.ProcessLogsResult](f, "fleet_process_logs", map[string]any{"process_id": started.Process.ProcessID})
	stop(t, f, started.Process.ProcessID)

	assert.Equal(t, "still here", httpGet(t, url), "the forward must outlive the call that opened it")
}

func TestForward_StopClosesTheListenerAndDropsConnections(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	remote := startEchoServer(t)

	out := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{"remote_port": remote.port})

	// A connection in flight when the forward is torn down.
	inFlight, err := net.DialTimeout("tcp", out.LocalAddress, 5*time.Second)
	require.NoError(t, err)
	defer func() { _ = inFlight.Close() }()
	_, err = inFlight.Write([]byte("x"))
	require.NoError(t, err)
	echo := make([]byte, 1)
	require.NoError(t, inFlight.SetReadDeadline(time.Now().Add(10*time.Second)))
	_, err = io.ReadFull(inFlight, echo)
	require.NoError(t, err)

	stopped := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{
		"remote_port": remote.port,
		"stop":        true,
	})
	assert.True(t, stopped.Stopped)
	assert.Empty(t, stopped.Active, "the listing must not still show a forward that was stopped")

	// The listener is gone: nothing accepts on that port any more.
	_, err = net.DialTimeout("tcp", out.LocalAddress, 2*time.Second)
	assert.Error(t, err, "the local listener must be released")

	// The connection that was open when it was stopped is dropped, cleanly:
	// EOF or a reset, never an indefinite wait.
	require.NoError(t, inFlight.SetReadDeadline(time.Now().Add(10*time.Second)))
	_, err = inFlight.Read(echo)
	assert.Error(t, err, "an in-flight connection must be dropped rather than left hanging")
}

// The stop call a forward hands back has to be the call that stops it.
// remote_host is part of the forward's identity, so a suggestion that omits it
// looks up the loopback forward of the same port, finds nothing, and fails —
// which reads to a caller as the forward having closed itself.
func TestForward_TheStopCallItSuggestsActuallyStopsIt(t *testing.T) {
	// A host on the allow list, taking the same path a real off-box target
	// takes, while still reaching a server this test can stand up.
	f := newLiveFixture(t, liveAgentOptions{forwardAllowedHosts: []string{"localhost"}})
	remote := startHTTPServer(t, "named host")

	out := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{
		"remote_port": remote.port,
		"remote_host": "localhost",
	})
	require.Equal(t, "named host", httpGet(t, "http://"+out.LocalAddress+"/"))
	assert.Contains(t, out.Note, "remote_host",
		"a forward whose key carries a remote_host must say so in the call that stops it")

	// The suggestion without it does not work, and is not what was suggested.
	msg := f.liveFails("fleet_forward", map[string]any{"remote_port": remote.port, "stop": true})
	assert.Contains(t, msg, "no forward is open")

	// The suggestion as given does.
	stopped := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{
		"remote_port": remote.port,
		"remote_host": "localhost",
		"stop":        true,
	})
	assert.True(t, stopped.Stopped)
	assert.Empty(t, stopped.Active)
}

// Deregistering a sandbox has to take its forwards with it. The pooled channel
// behind them is closed on removal, so what would be left is a local port that
// accepts a connection and drops it — the one outcome a caller cannot diagnose,
// and the reason opening a forward preflights at all.
func TestForward_RemovingTheSandboxClosesItsForwards(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	remote := startHTTPServer(t, "about to go")

	out := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{"remote_port": remote.port})
	require.Equal(t, "about to go", httpGet(t, "http://"+out.LocalAddress+"/"))

	removed := liveOK[tools.RemoveResult](f, "fleet_remove", map[string]any{"name": liveSandboxName})
	assert.Contains(t, removed.ForwardsClosed, out.LocalAddress,
		"the result must name the forwards it closed rather than leaving them to be discovered")
	assert.Contains(t, removed.Note, "forward")

	// The port is released, provably: something else can take it.
	eventually(t, 10*time.Second, "the forward's local port to be released", func() bool {
		lis, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(out.LocalPort)))
		if err != nil {
			return false
		}
		_ = lis.Close()
		return true
	})
}

// And it closes them *before* it drops the channel they run over.
//
// The other order leaves a window in which the listener is still accepting and
// every connection it takes opens a stream on a channel that has just closed:
// the accepts-and-then-drops symptom, produced in the middle of the code that
// exists to prevent it, and reached by every connection that arrives while
// fleet_remove is running. The window is small, which is exactly why it would
// be found by a user and not by a test that only checks the end state.
func TestForward_RemovingTheSandboxClosesForwardsBeforeTheChannel(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	remote := startHTTPServer(t, "ordering")

	out := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{"remote_port": remote.port})
	require.Equal(t, "ordering", httpGet(t, "http://"+out.LocalAddress+"/"))

	// Asked at the moment the channel is dropped: is the port the forward was
	// holding already free? It can only be if the listener was closed first.
	var listenerClosedFirst bool
	f.clients.onRemove = func(string) {
		lis, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(out.LocalPort)))
		if err != nil {
			return
		}
		_ = lis.Close()
		listenerClosedFirst = true
	}

	liveOK[tools.RemoveResult](f, "fleet_remove", map[string]any{"name": liveSandboxName})
	assert.True(t, listenerClosedFirst,
		"the forward's listener was still accepting when its channel was dropped, so a connection arriving then would be accepted onto a dead channel")
}

func TestForward_StopWithNoSuchForwardListsWhatIsOpen(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	remote := startHTTPServer(t, "open")

	opened := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{"remote_port": remote.port})

	msg := f.liveFails("fleet_forward", map[string]any{"remote_port": 65000, "stop": true})
	assert.Contains(t, msg, "65000")
	assert.Contains(t, msg, opened.LocalAddress, "the error must name the forwards that are open")

	empty := newLiveFixture(t, liveAgentOptions{})
	msg = empty.liveFails("fleet_forward", map[string]any{"remote_port": 65000, "stop": true})
	assert.Contains(t, msg, "none are open at all")
}

// The MCP server exiting has to release every local listener. One that
// survived the process would hold its port against the next server, and the
// user would see "address already in use" from a process that is gone.
func TestForward_ServerCloseReleasesEveryLocalListener(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	remote := startHTTPServer(t, "released")
	localPort := freePort(t)

	out := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{
		"remote_port": remote.port,
		"local_port":  localPort,
	})
	require.Equal(t, localPort, out.LocalPort)
	assert.Equal(t, "released", httpGet(t, "http://"+out.LocalAddress+"/"))

	require.NoError(t, f.server.Close())

	// The port is free again, provably: something else can take it.
	eventually(t, 10*time.Second, "the local port to be released", func() bool {
		lis, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)))
		if err != nil {
			return false
		}
		_ = lis.Close()
		return true
	})
}

// ------------------------------------------------------------- the limits

// Binding loopback only is the difference between forwarding a port to
// yourself and publishing a tunnel into the sandbox on a coffee-shop LAN.
func TestForward_LocalListenerIsNotReachableFromAnotherInterface(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	remote := startHTTPServer(t, "loopback only")

	out := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{"remote_port": remote.port})
	host, _, err := net.SplitHostPort(out.LocalAddress)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", host, "the listener must bind loopback, never 0.0.0.0")

	routable := routableAddress(t)
	if routable == "" {
		t.Skip("this host has no non-loopback address to try the forward from")
	}
	_, err = net.DialTimeout("tcp", net.JoinHostPort(routable, strconv.Itoa(out.LocalPort)), 2*time.Second)
	assert.Error(t, err,
		"the forward must not be reachable on %s, which is what another machine on this network would use", routable)
}

// Connecting to a closed remote port has to fail with something readable,
// before a listener exists — not open a local port that accepts and then dies.
func TestForward_ClosedRemotePortIsAClearErrorNotAHangingListener(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	closed := freePort(t) // reserved and released: nothing is listening there

	msg := f.liveFails("fleet_forward", map[string]any{"remote_port": closed})
	assert.Contains(t, msg, strconv.Itoa(closed))
	assert.Contains(t, msg, "could not reach")
	assert.Contains(t, msg, "fleet_process_list",
		"the error should say how to check what is actually listening")

	// And no listener was left behind for the model to connect to.
	after := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{
		"remote_port": startHTTPServer(t, "x").port,
	})
	for _, active := range after.Active {
		assert.NotEqual(t, closed, active.RemotePort, "a failed forward must leave nothing open")
	}
}

// remote_host defaults to the sandbox's loopback, and anything else needs the
// operator to have said so. Without that, every agent is a general-purpose
// pivot into whatever network it sits in.
func TestForward_NonLoopbackRemoteHostIsRefusedByDefault(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})

	// TEST-NET-1, which is reserved and routes nowhere: the point is that the
	// refusal happens before anything is dialed.
	msg := f.liveFails("fleet_forward", map[string]any{
		"remote_port": 8080,
		"remote_host": "192.0.2.1",
	})
	assert.Contains(t, msg, "loopback")
	assert.Contains(t, msg, "allowed_hosts", "the refusal must name the setting that would permit it")
}

func TestForward_NonLoopbackRemoteHostIsPermittedWhenConfigured(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{forwardAllowedHosts: []string{"192.0.2.1"}})

	msg := f.liveFails("fleet_forward", map[string]any{
		"remote_port": 8080,
		"remote_host": "192.0.2.1",
	})
	// It still fails — nothing is there — but on the dial, not on the policy.
	assert.NotContains(t, msg, "allowed_hosts",
		"a host the operator listed must get past the policy check")
	assert.Contains(t, msg, "could not reach")
}

// "localhost" is a name, not an address, and it has to be resolved before it
// is judged: checking the string alone would refuse the most common spelling
// of the default.
func TestForward_LocalhostByNameResolvesToLoopbackAndIsAllowed(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	remote := startHTTPServer(t, "by name")

	out := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{
		"remote_port": remote.port,
		"remote_host": "localhost",
	})
	assert.Equal(t, "by name", httpGet(t, "http://"+out.LocalAddress+"/"))
}

func TestForward_DisabledAgentSaysSo(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{forwardDisabled: true})
	remote := startHTTPServer(t, "unreachable")

	msg := f.liveFails("fleet_forward", map[string]any{"remote_port": remote.port})
	assert.Contains(t, msg, "disabled")
}

func TestForward_RejectsAnOutOfRangePort(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	assert.Contains(t, f.liveFails("fleet_forward", map[string]any{"remote_port": 0}), "1-65535")
	assert.Contains(t, f.liveFails("fleet_forward", map[string]any{"remote_port": 70000}), "1-65535")
	assert.Contains(t, f.liveFails("fleet_forward", map[string]any{
		"remote_port": 3000, "local_port": -1,
	}), "0-65535")
}

func TestForward_ReopeningOnADifferentLocalPortSaysWhatToDo(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	remote := startHTTPServer(t, "already")

	first := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{"remote_port": remote.port})

	msg := f.liveFails("fleet_forward", map[string]any{
		"remote_port": remote.port,
		"local_port":  freePort(t),
	})
	assert.Contains(t, msg, first.LocalAddress)
	assert.Contains(t, msg, "stop=true")
}

// ----------------------------------------------------------- the record

// End to end: a forward the operator permitted to leave the machine produces
// an audit record naming what was asked for, what it became, and how much went
// through — and a forward to the sandbox's own loopback produces none.
func TestForward_NonLoopbackForwardIsAudited(t *testing.T) {
	// "localhost" on the allow list is the operator having listed a host by
	// name. It takes the same path a real off-box target does — listed hosts
	// are dialed by name and audited whatever they resolve to — while still
	// reaching a server this test can stand up.
	f := newLiveFixture(t, liveAgentOptions{forwardAllowedHosts: []string{"localhost"}})
	const body = "audited response"
	remote := startHTTPServer(t, body)

	out := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{
		"remote_port": remote.port,
		"remote_host": "localhost",
	})
	require.Equal(t, body, httpGet(t, "http://"+out.LocalAddress+"/"))

	var rec policy.Record
	eventually(t, 10*time.Second, "the connection's audit record", func() bool {
		for _, candidate := range auditRecords(t, f.agent.auditPath) {
			if candidate.BytesToRemote > 0 {
				rec = candidate
				return true
			}
		}
		return false
	})

	assert.Equal(t, "sandboxd.v1.ForwardService/Forward", rec.RPC)
	assert.Equal(t, policy.OutcomeOK, rec.Outcome)
	assert.Equal(t, liveSandboxName, rec.Sandbox)
	assert.Equal(t, "localhost", rec.RemoteHost, "what the caller asked for")
	assert.Equal(t, uint32(remote.port), rec.RemotePort) //nolint:gosec // a kernel-assigned port is in range

	// What it became, and it has to be an address rather than the name again.
	// A listed host is dialed by name, so this is the one field that can show a
	// name resolving somewhere it should not have — and it can only do that if
	// it comes from the socket.
	resolvedHost, resolvedPort, err := net.SplitHostPort(rec.ResolvedAddress)
	require.NoErrorf(t, err, "resolved_address %q must be an address", rec.ResolvedAddress)
	assert.NotNil(t, net.ParseIP(resolvedHost),
		"resolved_address must name the address the packets went to, not the host that was requested")
	assert.Equal(t, strconv.Itoa(remote.port), resolvedPort)
	assert.NotEmpty(t, rec.LocalAddress)
	assert.Positive(t, rec.BytesToRemote, "the request")
	assert.Positive(t, rec.BytesFromRemote, "the response")

	// The body went through the forward and is nowhere in the log.
	raw, err := os.ReadFile(f.agent.auditPath)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), body)
}

// A refusal is recorded too, from the tool call that caused it.
func TestForward_RefusedNonLoopbackForwardIsAudited(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})

	msg := f.liveFails("fleet_forward", map[string]any{
		"remote_port": 8080,
		"remote_host": "192.0.2.1",
	})
	require.Contains(t, msg, "allowed_hosts")

	var rec policy.Record
	eventually(t, 10*time.Second, "the refusal's audit record", func() bool {
		got := auditRecords(t, f.agent.auditPath)
		if len(got) == 0 {
			return false
		}
		rec = got[0]
		return true
	})
	assert.Equal(t, policy.OutcomeDenied, rec.Outcome)
	assert.Equal(t, "forward.allowed_hosts", rec.Rule)
	assert.Equal(t, "192.0.2.1", rec.RemoteHost)
	assert.Equal(t, uint32(8080), rec.RemotePort)
}

// A loopback forward is a convenience on a host the caller already has exec
// on, and it stays out of the log so the pivots in it remain findable.
func TestForward_LoopbackForwardIsNotAudited(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	remote := startHTTPServer(t, "not audited")

	out := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{"remote_port": remote.port})
	require.Equal(t, "not audited", httpGet(t, "http://"+out.LocalAddress+"/"))

	// Given time to be wrong: the assertion is that nothing arrives, so it
	// has to wait long enough for something to have arrived if it were going
	// to.
	time.Sleep(500 * time.Millisecond)
	assert.Empty(t, auditRecords(t, f.agent.auditPath))
}

// auditRecords reads the agent's audit log.
func auditRecords(t *testing.T, path string) []policy.Record {
	t.Helper()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	require.NoError(t, err)

	var out []policy.Record
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec policy.Record
		require.NoErrorf(t, json.Unmarshal([]byte(line), &rec), "audit line is not JSON: %s", line)
		out = append(out, rec)
	}
	return out
}

// --------------------------------------------------------------- goleak

// One connection is two pump goroutines and a stream. A forward left open for
// hours across many connections is where those accumulate, and the failure is
// invisible until the MCP server is slowly using a gigabyte — so the count has
// to come back down, not merely stay plausible.
//
// This one measures what teardown releases, and only that: it stops the forward
// before it counts, and stopping a forward cancels everything under it. A hold
// that exists only while the forward is running is invisible here by
// construction — see TestForward_ReleasesEveryConnectionWhileItStaysOpen, which
// is the assertion that can see one.
func TestForward_NoGoroutineLeakAcrossManyConnections(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	remote := startEchoServer(t)

	out := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{"remote_port": remote.port})

	// One connection first, so gRPC's own long-lived goroutines are in the
	// baseline rather than counted as a leak.
	roundTrip(t, out.LocalAddress, "warmup")

	baseline := goleak.IgnoreCurrent()

	const connections = 40
	for i := range connections {
		roundTrip(t, out.LocalAddress, fmt.Sprintf("payload-%d", i))
	}

	// Concurrently too: the sequential case can hide a leak that only happens
	// when accepts overlap.
	var wg sync.WaitGroup
	for i := range connections {
		wg.Add(1)
		go func() {
			defer wg.Done()
			roundTrip(t, out.LocalAddress, fmt.Sprintf("parallel-%d", i))
		}()
	}
	wg.Wait()

	stopped := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{
		"remote_port": remote.port,
		"stop":        true,
	})
	require.True(t, stopped.Stopped)

	goleak.VerifyNone(t, baseline)
}

// The measurement the assertion above cannot make.
//
// TestForward_NoGoroutineLeakAcrossManyConnections stops the forward before it
// counts, and stopping a forward cancels everything running under it — so it
// structurally cannot see a hold that exists only while the forward is open,
// which is what both of the connection-lifetime leaks found so far were. This
// one counts with the forward still serving, after enough connections of enough
// shapes that a per-connection hold would be unmistakable rather than plausible:
// completed ones, ones whose far side is reset mid-request, and idle ones that
// never say anything at all.
//
// It counts descriptors as well as goroutines. goleak does not see a socket,
// and a forward that returns every goroutine while keeping every descriptor
// still stops working after a few thousand connections — just with a different
// error message.
func TestForward_ReleasesEveryConnectionWhileItStaysOpen(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	echo := startEchoServer(t)
	// A server that answers nothing and resets the connection instead, which is
	// what a server crashing mid-request looks like from the agent's socket.
	crashing := startResettingServer(t)
	// And a server that will volunteer nothing at all: it never reads, never
	// writes, and never closes. Nothing on the sandbox side will ever end one of
	// these connections, so what ends it has to be this side noticing that its
	// own client is gone.
	parked, releaseParked := startParkedServer(t)
	// And a server that answers the forward's preflight and is then gone, so
	// the sandbox-side dial fails on a forward that is already open and
	// listening. That is the shape where carry ends before either pump starts.
	departing, stopDeparting := startStoppableServer(t)

	echoForward := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{"remote_port": echo.port})
	crashForward := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{"remote_port": crashing.port})
	parkedForward := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{"remote_port": parked.port})
	departedForward := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{"remote_port": departing.port})
	stopDeparting()

	// One of each first, so gRPC's own long-lived goroutines and the pool's own
	// descriptors are in the baseline rather than counted as a hold.
	roundTrip(t, echoForward.LocalAddress, "warmup")
	abortedRoundTrip(t, crashForward.LocalAddress)
	resetRoundTrip(t, parkedForward.LocalAddress)
	refusedRoundTrip(t, departedForward.LocalAddress)
	waitForNoOpenConnections(t, f, echo.port, crashing.port, parked.port, departing.port)

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
		roundTrip(t, echoForward.LocalAddress, fmt.Sprintf("sequential-%d", i))
	}

	// Overlapping, because the sequential case cannot show a hold that only
	// happens when accepts interleave.
	var wg sync.WaitGroup
	for i := range concurrent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			roundTrip(t, echoForward.LocalAddress, fmt.Sprintf("concurrent-%d", i))
		}()
	}
	wg.Wait()

	// The far side killed mid-request. This is the ordinary way a forwarded
	// connection dies, not an exotic one, and it is the path on which the agent
	// has to volunteer that the socket failed — nothing else would ever ask.
	// Concurrently, so that an agent which stopped volunteering that the socket
	// had failed would cost this test one client deadline rather than sixty.
	for range aborted {
		wg.Add(1)
		go func() {
			defer wg.Done()
			abortedRoundTrip(t, crashForward.LocalAddress)
		}()
	}
	wg.Wait()

	// And this side killed mid-request, against a server that will never
	// volunteer anything: ^C on a curl, a closed browser tab, a client process
	// killed. Nothing on the sandbox side ends these, so a connection still
	// counted here is one held for the life of the forward.
	for range killed {
		resetRoundTrip(t, parkedForward.LocalAddress)
	}

	// And connections the sandbox side refuses, on a forward that is open and
	// listening: the local socket is accepted and the connection ends on the
	// agent's answer, before either pump exists.
	for range refused {
		refusedRoundTrip(t, departedForward.LocalAddress)
	}

	// And connections that do nothing, held open. A browser's keep-alive
	// connection through a forward is exactly this: parked, with a send pump
	// parked in conn.Read waiting for a client that has no reason to speak.
	held := make([]net.Conn, 0, idle)
	for range idle {
		conn, err := net.DialTimeout("tcp", echoForward.LocalAddress, 10*time.Second)
		require.NoError(t, err)
		held = append(held, conn)
	}
	eventually(t, 30*time.Second, "the idle connections to be counted as carried", func() bool {
		return openConnections(f, echo.port) == idle
	})
	for _, conn := range held {
		require.NoError(t, conn.Close())
	}

	// Now the count, with every forward still open and still listening.
	waitForNoOpenConnections(t, f, echo.port, crashing.port, parked.port, departing.port)

	// The stand-in server's own sockets go first, and only now: the forward has
	// already been observed releasing every connection, so what is left to count
	// is the forward's, not the fixture's.
	releaseParked()

	goleak.VerifyNone(t, baseline)

	if canCountDescriptors {
		descriptorsAfter, _ := descriptorSnapshot()
		// No growth at all, rather than a tolerance. Everything opened above is
		// a connection that has been observed to end, and the listeners were
		// open before the baseline was taken, so there is nothing left for a
		// tolerance to cover — and a tolerance is where a leak of one descriptor
		// every seven connections hides. This started as a tolerance of sixteen,
		// which was enough to hide twenty-two.
		assert.LessOrEqualf(t, len(descriptorsAfter), len(descriptorsBefore),
			"descriptors grew from %d to %d across %d forwarded connections, and goleak does not see a socket: %s",
			len(descriptorsBefore), len(descriptorsAfter),
			sequential+concurrent+aborted+killed+refused+idle,
			describeNewDescriptors(descriptorsBefore, descriptorsAfter))
	}

	// And the forward still works, so none of the above was achieved by
	// breaking it.
	roundTrip(t, echoForward.LocalAddress, "still serving")
}

// waitForNoOpenConnections waits until every named forward reports nothing in
// flight, asked of the running server rather than of a torn-down one.
func waitForNoOpenConnections(t *testing.T, f *liveFixture, remotePorts ...int) {
	t.Helper()
	for _, port := range remotePorts {
		eventually(t, 60*time.Second, fmt.Sprintf("forward to port %d to release every connection", port), func() bool {
			return openConnections(f, port) == 0
		})
	}
}

// openConnections asks the forward listing how many connections it is carrying
// right now. A repeated call for an open forward reuses it, so this is a
// question rather than an action.
func openConnections(f *liveFixture, remotePort int) int {
	out := liveOK[tools.ForwardResult](f, "fleet_forward", map[string]any{"remote_port": remotePort})
	for _, line := range out.Active {
		if line.RemotePort == remotePort {
			return line.OpenNow
		}
	}
	return -1
}

// descriptorSnapshot lists this process's open descriptors with whatever the
// platform will say about each one, and reports whether the platform can be
// asked at all — Windows cannot, and skipping the count there is better than a
// count that means something else.
//
// Linux resolves each entry to "socket:[inode]", "pipe:[inode]" or a path,
// which is what makes a failure name itself; macOS answers the count only. The
// count is the assertion either way.
func descriptorSnapshot() (map[int]string, bool) {
	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		out := make(map[int]string, len(entries))
		for _, entry := range entries {
			fd, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue
			}
			// Best effort: a descriptor can close underneath this, and macOS
			// does not answer at all.
			target, _ := os.Readlink(filepath.Join(dir, entry.Name()))
			out[fd] = target
		}
		return out, true
	}
	return nil, false
}

// describeNewDescriptors summarises what appeared between two snapshots, so a
// failure names the path that leaked rather than leaving it to be bisected.
// Descriptor numbers are reused, so this is a lower bound on what is new — the
// count is the assertion, and this is the lead.
func describeNewDescriptors(before, after map[int]string) string {
	counts := map[string]int{}
	for fd, target := range after {
		if _, had := before[fd]; had {
			continue
		}
		if target == "" {
			target = "(this platform does not say what it is)"
		}
		counts[target]++
	}
	if len(counts) == 0 {
		return "no descriptor is new by number, so the growth is in descriptors that replaced closed ones"
	}
	lines := make([]string, 0, len(counts))
	for target, n := range counts {
		lines = append(lines, fmt.Sprintf("%d x %s", n, target))
	}
	sort.Strings(lines)
	return strings.Join(lines, "; ")
}

// ---------------------------------------------------------------- helpers

type remoteServer struct{ port int }

// startHTTPServer runs an HTTP server on the sandbox's loopback.
func startHTTPServer(t *testing.T, body string) remoteServer {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)
	n, err := strconv.Atoi(port)
	require.NoError(t, err)
	return remoteServer{port: n}
}

// startEchoServer runs a TCP echo server on loopback.
//
// Copied by hand rather than with io.Copy, and that is not a style choice.
// io.Copy between two TCP connections takes Linux's splice(2) path, which
// borrows a pipe from a runtime-wide pool for as long as the copy is running
// and returns it to a sync.Pool afterwards — so the pipes survive until a
// garbage collection, and their number tracks how many copies were in flight at
// once. That is invisible on macOS, which has no splice, and it put twenty-two
// descriptors belonging to *this stand-in server* into
// TestForward_ReleasesEveryConnectionWhileItStaysOpen's count of what the
// forward was holding. A measurement of the forward must not be paid for by the
// fixture it forwards to.
func startEchoServer(t *testing.T) remoteServer {
	return startTCPServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if _, writeErr := conn.Write(buf[:n]); writeErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	})
}

// startReadThenReplyServer answers only once the client has closed its write
// side, so a reply proves the half-close arrived.
func startReadThenReplyServer(t *testing.T, reply string) remoteServer {
	return startTCPServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		if _, err := io.Copy(io.Discard, conn); err != nil {
			return
		}
		_, _ = conn.Write([]byte(reply))
	})
}

// startStoppableServer answers and closes, and can be stopped mid-test so that
// the sandbox-side dial starts failing on a forward that is already open. That
// is the path where carry returns before either pump has started — the local
// socket is accepted, the stream is opened, and the connection ends on the
// agent's answer — and it is a real state: a forward preflights successfully
// and the dev server behind it exits a minute later.
func startStoppableServer(t *testing.T) (remoteServer, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var accept sync.WaitGroup
	accept.Add(1)
	go func() {
		defer accept.Done()
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = lis.Close()
			accept.Wait()
		})
	}
	t.Cleanup(stop)
	return remoteServer{port: lis.Addr().(*net.TCPAddr).Port}, stop
}

// startResettingServer reads a request and then resets the connection instead
// of answering it, which is what a server crashing mid-request does to its
// socket. Whether the agent sees that as ECONNRESET or as a tidy EOF is the
// platform's choice; both have to end the forwarded connection.
func startResettingServer(t *testing.T) remoteServer {
	return startTCPServer(t, func(conn net.Conn) {
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		if tcp, ok := conn.(*net.TCPConn); ok {
			// Linger zero makes Close send an RST rather than a FIN.
			_ = tcp.SetLinger(0)
		}
		_ = conn.Close()
	})
}

// startParkedServer accepts and holds: it never reads, never writes and never
// closes. It is the sandbox-side server that has not got a complete request yet
// — a database connection, anything framed — and it is what makes a local
// client's own death the only thing that can end the forwarded connection.
//
// Deliberately not built on startTCPServer: one accept goroutine and no
// goroutine per connection, so this fixture's own goroutines and descriptors
// are a constant rather than something a leak count has to allow for. The
// returned function releases the sockets it is holding, for the same reason.
func startParkedServer(t *testing.T) (remoteServer, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var (
		mu     sync.Mutex
		held   []net.Conn
		accept sync.WaitGroup
	)
	accept.Add(1)
	go func() {
		defer accept.Done()
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
		}
	}()

	release := func() {
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range held {
			_ = conn.Close()
		}
		held = nil
	}
	t.Cleanup(func() {
		_ = lis.Close()
		accept.Wait()
		release()
	})
	return remoteServer{port: lis.Addr().(*net.TCPAddr).Port}, release
}

// startGreetThenCloseServer writes and closes immediately, so the local client
// must see the close as an EOF.
func startGreetThenCloseServer(t *testing.T, greeting string) remoteServer {
	return startTCPServer(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte(greeting))
		_ = conn.Close()
	})
}

func startTCPServer(t *testing.T, handle func(net.Conn)) remoteServer {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				handle(conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = lis.Close()
		wg.Wait()
	})
	return remoteServer{port: lis.Addr().(*net.TCPAddr).Port}
}

// forwardClient is an HTTP client that opens a fresh connection per request,
// so a test asserting on concurrent connections gets them.
func forwardClient() *http.Client {
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
}

func httpGet(t *testing.T, url string) string {
	t.Helper()
	client := forwardClient()
	defer client.CloseIdleConnections()

	resp, err := client.Get(url) //nolint:noctx // the client carries a timeout
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

// roundTrip opens a connection, sends payload, reads it back, and closes.
func roundTrip(t *testing.T, address, payload string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))

	_, err = conn.Write([]byte(payload))
	require.NoError(t, err)
	require.NoError(t, conn.(*net.TCPConn).CloseWrite())

	got, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.Equal(t, payload, string(got))
}

// refusedRoundTrip opens a connection through a forward whose sandbox-side
// target has gone away. The local socket is accepted and the stream is opened;
// the agent's dial fails, and the connection ends on that answer rather than on
// anything either pump did.
func refusedRoundTrip(t *testing.T, address string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	require.NoError(t, err, "the listener is still there even when its target is not")
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))

	// Dropped rather than answered, and either an EOF or a reset is a drop.
	_, _ = conn.Write([]byte("a request with nothing behind it"))
	_, _ = io.ReadAll(conn)
}

// abortedRoundTrip sends a request whose far side is reset before it answers,
// and reads the connection out. The local client behaves — it notices the end
// and hangs up — because that is what every real one does, and it is what lets
// the agent's own handler unwind.
func abortedRoundTrip(t *testing.T, address string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))

	// Both are allowed to fail: the point is that the connection ends, not how.
	_, _ = conn.Write([]byte("a request nobody is going to answer"))
	_, _ = io.ReadAll(conn)
}

// resetRoundTrip opens a connection through the forward, sends a request, and
// then kills the local client the way ^C or a closed browser tab does: a reset
// rather than a graceful close, so the forward learns the client is gone rather
// than that it has finished sending.
func resetRoundTrip(t *testing.T, address string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	require.NoError(t, err)

	tcp, ok := conn.(*net.TCPConn)
	require.True(t, ok)
	// Linger zero makes Close send an RST, which the forward's read of this
	// socket sees as a failure rather than as the EOF a half-close produces.
	require.NoError(t, tcp.SetLinger(0))

	_, _ = conn.Write([]byte("a request the client will not wait for"))
	require.NoError(t, conn.Close())
}

// routableAddress returns a non-loopback IPv4 address of this host, or "" if
// there is none — which is what another machine on the network would dial.
func routableAddress(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() || ipnet.IP.To4() == nil {
			continue
		}
		return ipnet.IP.String()
	}
	return ""
}
