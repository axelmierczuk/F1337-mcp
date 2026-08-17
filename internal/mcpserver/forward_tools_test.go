package mcpserver_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/axelmierczuk/sandboxd-mcp/internal/mcpserver/tools"
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

	out := liveOK[tools.ForwardResult](f, "sandbox_forward", map[string]any{
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

	out := liveOK[tools.ForwardResult](f, "sandbox_forward", map[string]any{
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

	out := liveOK[tools.ForwardResult](f, "sandbox_forward", map[string]any{
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

	out := liveOK[tools.ForwardResult](f, "sandbox_forward", map[string]any{"remote_port": remote.port})
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
	after := liveOK[tools.ForwardResult](f, "sandbox_forward", map[string]any{"remote_port": remote.port})
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

	out := liveOK[tools.ForwardResult](f, "sandbox_forward", map[string]any{"remote_port": remote.port})

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

	out := liveOK[tools.ForwardResult](f, "sandbox_forward", map[string]any{"remote_port": remote.port})

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

	out := liveOK[tools.ForwardResult](f, "sandbox_forward", map[string]any{"remote_port": remote.port})

	conn, err := net.DialTimeout("tcp", out.LocalAddress, 5*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))

	got, err := io.ReadAll(conn)
	require.NoError(t, err, "the close must arrive as EOF, not as a connection reset")
	assert.Equal(t, "goodbye", string(got))
}

// -------------------------------------------------------------- lifetime

// A forward is owned by the MCP server process, not by the call that opened
// it: it has to still be there after unrelated tool calls.
func TestForward_SurvivesUnrelatedToolCalls(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	remote := startHTTPServer(t, "still here")

	out := liveOK[tools.ForwardResult](f, "sandbox_forward", map[string]any{"remote_port": remote.port})
	url := "http://" + out.LocalAddress + "/"
	assert.Equal(t, "still here", httpGet(t, url))

	// Several unrelated calls, including ones that start and stop processes.
	started := liveOK[tools.ProcessStartResult](f, "sandbox_process_start", f.startHelper("unrelated", "silent"))
	liveOK[tools.ProcessListResult](f, "sandbox_process_list", map[string]any{})
	liveOK[tools.ProcessLogsResult](f, "sandbox_process_logs", map[string]any{"process_id": started.Process.ProcessID})
	stop(t, f, started.Process.ProcessID)

	assert.Equal(t, "still here", httpGet(t, url), "the forward must outlive the call that opened it")
}

func TestForward_StopClosesTheListenerAndDropsConnections(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	remote := startEchoServer(t)

	out := liveOK[tools.ForwardResult](f, "sandbox_forward", map[string]any{"remote_port": remote.port})

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

	stopped := liveOK[tools.ForwardResult](f, "sandbox_forward", map[string]any{
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

func TestForward_StopWithNoSuchForwardListsWhatIsOpen(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	remote := startHTTPServer(t, "open")

	opened := liveOK[tools.ForwardResult](f, "sandbox_forward", map[string]any{"remote_port": remote.port})

	msg := f.liveFails("sandbox_forward", map[string]any{"remote_port": 65000, "stop": true})
	assert.Contains(t, msg, "65000")
	assert.Contains(t, msg, opened.LocalAddress, "the error must name the forwards that are open")

	empty := newLiveFixture(t, liveAgentOptions{})
	msg = empty.liveFails("sandbox_forward", map[string]any{"remote_port": 65000, "stop": true})
	assert.Contains(t, msg, "none are open at all")
}

// The MCP server exiting has to release every local listener. One that
// survived the process would hold its port against the next server, and the
// user would see "address already in use" from a process that is gone.
func TestForward_ServerCloseReleasesEveryLocalListener(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	remote := startHTTPServer(t, "released")
	localPort := freePort(t)

	out := liveOK[tools.ForwardResult](f, "sandbox_forward", map[string]any{
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

	out := liveOK[tools.ForwardResult](f, "sandbox_forward", map[string]any{"remote_port": remote.port})
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

	msg := f.liveFails("sandbox_forward", map[string]any{"remote_port": closed})
	assert.Contains(t, msg, strconv.Itoa(closed))
	assert.Contains(t, msg, "could not reach")
	assert.Contains(t, msg, "sandbox_process_list",
		"the error should say how to check what is actually listening")

	// And no listener was left behind for the model to connect to.
	after := liveOK[tools.ForwardResult](f, "sandbox_forward", map[string]any{
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
	msg := f.liveFails("sandbox_forward", map[string]any{
		"remote_port": 8080,
		"remote_host": "192.0.2.1",
	})
	assert.Contains(t, msg, "loopback")
	assert.Contains(t, msg, "allowed_hosts", "the refusal must name the setting that would permit it")
}

func TestForward_NonLoopbackRemoteHostIsPermittedWhenConfigured(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{forwardAllowedHosts: []string{"192.0.2.1"}})

	msg := f.liveFails("sandbox_forward", map[string]any{
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

	out := liveOK[tools.ForwardResult](f, "sandbox_forward", map[string]any{
		"remote_port": remote.port,
		"remote_host": "localhost",
	})
	assert.Equal(t, "by name", httpGet(t, "http://"+out.LocalAddress+"/"))
}

func TestForward_DisabledAgentSaysSo(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{forwardDisabled: true})
	remote := startHTTPServer(t, "unreachable")

	msg := f.liveFails("sandbox_forward", map[string]any{"remote_port": remote.port})
	assert.Contains(t, msg, "disabled")
}

func TestForward_RejectsAnOutOfRangePort(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	assert.Contains(t, f.liveFails("sandbox_forward", map[string]any{"remote_port": 0}), "1-65535")
	assert.Contains(t, f.liveFails("sandbox_forward", map[string]any{"remote_port": 70000}), "1-65535")
	assert.Contains(t, f.liveFails("sandbox_forward", map[string]any{
		"remote_port": 3000, "local_port": -1,
	}), "0-65535")
}

func TestForward_ReopeningOnADifferentLocalPortSaysWhatToDo(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	remote := startHTTPServer(t, "already")

	first := liveOK[tools.ForwardResult](f, "sandbox_forward", map[string]any{"remote_port": remote.port})

	msg := f.liveFails("sandbox_forward", map[string]any{
		"remote_port": remote.port,
		"local_port":  freePort(t),
	})
	assert.Contains(t, msg, first.LocalAddress)
	assert.Contains(t, msg, "stop=true")
}

// --------------------------------------------------------------- goleak

// One connection is two pump goroutines and a stream. A forward left open for
// hours across many connections is where those accumulate, and the failure is
// invisible until the MCP server is slowly using a gigabyte — so the count has
// to come back down, not merely stay plausible.
func TestForward_NoGoroutineLeakAcrossManyConnections(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	remote := startEchoServer(t)

	out := liveOK[tools.ForwardResult](f, "sandbox_forward", map[string]any{"remote_port": remote.port})

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

	stopped := liveOK[tools.ForwardResult](f, "sandbox_forward", map[string]any{
		"remote_port": remote.port,
		"stop":        true,
	})
	require.True(t, stopped.Stopped)

	goleak.VerifyNone(t, baseline)
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
func startEchoServer(t *testing.T) remoteServer {
	return startTCPServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		_, _ = io.Copy(conn, conn)
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
