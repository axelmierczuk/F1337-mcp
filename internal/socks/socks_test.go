package socks

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"golang.org/x/net/proxy"

	"github.com/axelmierczuk/fleet-mcp/internal/tunnel"
)

// These drive the proxy over a real loopback listener with a real client on the
// other end, because everything worth asserting here is about bytes on a wire:
// which reply code a refusal produces, whether a name survived unresolved, and
// whether a half-close in one direction left the other one working.
//
// Two kinds of client are used deliberately. The hand-written one below asserts
// on the bytes, which is the only way to check a reply code or a malformed
// request. golang.org/x/net/proxy is an implementation nobody here wrote, and
// it is what makes "this is SOCKS5" a claim rather than an agreement between
// two halves of the same author's misunderstanding.

// ------------------------------------------------------------- fixtures

// destinationServer is a TCP server standing in for something on the sandbox's
// network. It reads one newline-terminated request and answers it upper-cased,
// so a response is distinguishable from a request that was reflected by
// accident.
//
// Request-and-response rather than echo-at-EOF, because a client that cannot
// half-close has to be able to drive it: golang.org/x/net/proxy hands back its
// own connection type rather than a *net.TCPConn, and a fixture that needed
// CloseWrite would have excluded the one client here that this package's author
// did not write.
func destinationServer(t *testing.T) string {
	t.Helper()
	return tcpServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte(strings.ToUpper(line)))
	})
}

// readThenReplyServer answers only once the client has closed its write side,
// so a reply proves the half-close arrived through the proxy.
func readThenReplyServer(t *testing.T, reply string) string {
	t.Helper()
	return tcpServer(t, func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		if _, err := io.Copy(io.Discard, conn); err != nil {
			return
		}
		_, _ = conn.Write([]byte(reply))
	})
}

func tcpServer(t *testing.T, handle func(net.Conn)) string {
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
	return lis.Addr().String()
}

// dialingConnector is the simplest possible [Connect]: it opens a real TCP
// connection and copies. It stands in for the forward stream, so the protocol
// can be tested without an agent.
//
// It records every destination it was asked for, which is how the tests check
// that a name arrived as a name.
type dialingConnector struct {
	mu   sync.Mutex
	seen []Destination
	// failWith, when set, is returned instead of connecting.
	failWith error
}

func (d *dialingConnector) destinations() []Destination {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]Destination, len(d.seen))
	copy(out, d.seen)
	return out
}

func (d *dialingConnector) connect(ctx context.Context, conn net.Conn, dst Destination, accepted func() error) error {
	d.mu.Lock()
	d.seen = append(d.seen, dst)
	failWith := d.failWith
	d.mu.Unlock()

	// Deliberately not closed here: the contract on [Connect] gives the socket
	// to the proxy on every path, so that a failure still has somewhere to put
	// its reply code.
	if failWith != nil {
		return failWith
	}

	// The destination is dialed here rather than in the proxy, which is the
	// split the package is built on: a name reaches this function unresolved
	// and whatever is on this side of it decides what to do about that.
	upstream, err := (&net.Dialer{}).DialContext(ctx, "tcp", dst.Label())
	if err != nil {
		return err
	}
	defer func() { _ = upstream.Close() }()

	if err := accepted(); err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, conn)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, upstream)
		_ = tunnel.CloseLocalWrite(conn)
	}()
	wg.Wait()
	return nil
}

// startProxy opens a proxy on a free port and serves it for the test's
// lifetime.
//
// tune, when given, runs between Listen and Serve. That window is the only
// place a test may touch a Server's unexported state: once the accept loop is
// running, a connection may be reading it, and -race says so.
func startProxy(t *testing.T, opts Options, tune ...func(*Server)) *Server {
	t.Helper()
	server, err := Listen(0, opts)
	require.NoError(t, err)
	for _, apply := range tune {
		apply(server)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.Serve(t.Context())
	}()
	t.Cleanup(func() {
		require.NoError(t, server.Close())
		wg.Wait()
	})
	return server
}

// ------------------------------------------------- a real client's view

// The interop assertion: an implementation nobody here wrote speaks to this
// one, over a name it never resolves.
func TestSocks_ARealClientReachesADestinationByName(t *testing.T) {
	destination := destinationServer(t)
	_, port, err := net.SplitHostPort(destination)
	require.NoError(t, err)

	connector := &dialingConnector{}
	server := startProxy(t, Options{Connect: connector.connect})

	dialer, err := proxy.SOCKS5("tcp", server.Addr(), nil, proxy.Direct)
	require.NoError(t, err)

	// A name, not an address, and one this machine's resolver has never heard
	// of. x/net/proxy sends it as a name because that is what SOCKS5 is for;
	// this proxy passes it through untouched; the connector above is the only
	// thing that resolves anything. Reversing any of those three is the bug
	// --socks5-hostname exists to avoid.
	conn, err := dialer.(proxy.ContextDialer).DialContext(t.Context(), "tcp", net.JoinHostPort("localhost", port))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))
	_, err = conn.Write([]byte("hello through the proxy\n"))
	require.NoError(t, err)

	got, err := io.ReadAll(conn)
	require.NoError(t, err)
	assert.Equal(t, "HELLO THROUGH THE PROXY\n", string(got))

	seen := connector.destinations()
	require.Len(t, seen, 1)
	assert.Equal(t, "localhost", seen[0].Host,
		"the destination must arrive as the name the client sent, unresolved")
	assert.True(t, seen[0].Name, "and be marked as a name, which is what makes remote resolution checkable")
}

// ------------------------------------------------------- the handshake

// socksClient is a hand-written SOCKS5 client, for the assertions that are
// about bytes.
type socksClient struct {
	conn net.Conn
}

func dialProxy(t *testing.T, address string) *socksClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))
	return &socksClient{conn: conn}
}

// greet offers the given methods and returns the one the proxy selected.
func (c *socksClient) greet(t *testing.T, methods ...byte) byte {
	t.Helper()
	msg := append([]byte{version5, byte(len(methods))}, methods...)
	_, err := c.conn.Write(msg)
	require.NoError(t, err)

	var reply [2]byte
	_, err = io.ReadFull(c.conn, reply[:])
	require.NoError(t, err)
	require.Equal(t, byte(version5), reply[0])
	return reply[1]
}

// request sends one request and returns the reply code.
func (c *socksClient) request(t *testing.T, cmd byte, addrType byte, addr []byte, port int) byte {
	t.Helper()
	msg := []byte{version5, cmd, 0x00, addrType}
	if addrType == addrDomain {
		msg = append(msg, byte(len(addr)))
	}
	msg = append(msg, addr...)
	msg = binary.BigEndian.AppendUint16(msg, uint16(port)) //nolint:gosec // a port in a test is well inside uint16

	_, err := c.conn.Write(msg)
	require.NoError(t, err)

	var reply [10]byte
	_, err = io.ReadFull(c.conn, reply[:])
	require.NoError(t, err)
	require.Equal(t, byte(version5), reply[0])
	return reply[1]
}

// connectByName is the ordinary case: greet, then CONNECT to a name.
func (c *socksClient) connectByName(t *testing.T, host string, port int) byte {
	t.Helper()
	require.Equal(t, byte(authNone), c.greet(t, authNone))
	return c.request(t, cmdConnect, addrDomain, []byte(host), port)
}

// CONNECT is all this implements. BIND and UDP ASSOCIATE are refused with the
// code the RFC has for it — cleanly, rather than half-implemented, because a
// UDP association that appears to be accepted and carries nothing is a client
// debugging the wrong layer.
func TestSocks_RefusesEverythingButConnect(t *testing.T) {
	connector := &dialingConnector{}
	server := startProxy(t, Options{Connect: connector.connect})

	for _, tc := range []struct {
		name string
		cmd  byte
	}{
		{"BIND", cmdBind},
		{"UDP ASSOCIATE", cmdUDPAssociate},
		{"an unassigned command", 0x09},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := dialProxy(t, server.Addr())
			require.Equal(t, byte(authNone), c.greet(t, authNone))
			assert.Equal(t, byte(replyCommandNotSupported), c.request(t, tc.cmd, addrIPv4, net.IPv4(10, 0, 4, 7).To4(), 80))
		})
	}
	assert.Empty(t, connector.destinations(),
		"a refused command must not reach the connector at all")
}

// And it refuses them with that code for the request a conformant client
// actually sends.
//
// RFC 1928 §4: a client that does not yet know the address it will send
// datagrams from "MUST use a port number and address of all zeros" in its UDP
// ASSOCIATE. That is the ordinary spelling of the one command this proxy most
// expects to be asked for, and it arrives with port 0 — so a proxy that judged
// the destination fields before the command answered it "general failure",
// which sends its operator to look at a destination that was never the
// subject. The case above never sees it: it names a real address and a real
// port, which no client asking for UDP ASSOCIATE has to have.
func TestSocks_RefusesUDPAssociateSpelledTheWayTheRFCSpellsIt(t *testing.T) {
	connector := &dialingConnector{}
	server := startProxy(t, Options{Connect: connector.connect})

	for _, tc := range []struct {
		name string
		cmd  byte
	}{
		{"UDP ASSOCIATE", cmdUDPAssociate},
		{"BIND", cmdBind},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := dialProxy(t, server.Addr())
			require.Equal(t, byte(authNone), c.greet(t, authNone))
			assert.Equal(t, byte(replyCommandNotSupported),
				c.request(t, tc.cmd, addrIPv4, net.IPv4zero.To4(), 0),
				"the answer is about the command, not about the all-zero destination the RFC told the client to send")
		})
	}
	assert.Empty(t, connector.destinations(),
		"a refused command must not reach the connector at all")
}

// An address family this does not implement is refused with the code for it,
// rather than dropped: a client that gets a reply reports something useful.
func TestSocks_RefusesAnUnknownAddressType(t *testing.T) {
	server := startProxy(t, Options{Connect: (&dialingConnector{}).connect})

	c := dialProxy(t, server.Addr())
	require.Equal(t, byte(authNone), c.greet(t, authNone))
	assert.Equal(t, byte(replyAddressNotSupported), c.request(t, cmdConnect, 0x07, []byte{1, 2, 3, 4}, 80))
}

// Both address families are carried, and an address arrives as an address
// rather than as a name.
func TestSocks_CarriesBothAddressFamilies(t *testing.T) {
	connector := &dialingConnector{failWith: errors.New("not dialed in this test")}
	server := startProxy(t, Options{Connect: connector.connect})

	c := dialProxy(t, server.Addr())
	require.Equal(t, byte(authNone), c.greet(t, authNone))
	c.request(t, cmdConnect, addrIPv4, net.IPv4(10, 0, 4, 7).To4(), 5432)

	c6 := dialProxy(t, server.Addr())
	require.Equal(t, byte(authNone), c6.greet(t, authNone))
	c6.request(t, cmdConnect, addrIPv6, net.ParseIP("2001:db8::1").To16(), 443)

	seen := connector.destinations()
	require.Len(t, seen, 2)
	assert.Equal(t, "10.0.4.7", seen[0].Host)
	assert.Equal(t, 5432, seen[0].Port)
	assert.False(t, seen[0].Name)
	assert.Equal(t, "2001:db8::1", seen[1].Host)
	assert.Equal(t, 443, seen[1].Port)
	assert.False(t, seen[1].Name)
}

// This proxy offers no authentication, because there is nobody to
// authenticate: it is on loopback. A client that insists on some is told so in
// the protocol's own terms rather than left waiting.
func TestSocks_TellsAClientThatDemandsAuthenticationThereIsNone(t *testing.T) {
	server := startProxy(t, Options{Connect: (&dialingConnector{}).connect})

	c := dialProxy(t, server.Addr())
	assert.Equal(t, byte(authNoAcceptable), c.greet(t, 0x02 /* username/password */))
}

// A client speaking something else entirely gets silence rather than a reply in
// a grammar it does not read.
func TestSocks_DropsANonSocks5Client(t *testing.T) {
	server := startProxy(t, Options{Connect: (&dialingConnector{}).connect})

	conn, err := net.DialTimeout("tcp", server.Addr(), 10*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))

	// A SOCKS4 CONNECT, which begins with version 4.
	_, err = conn.Write([]byte{0x04, 0x01, 0x00, 0x50, 127, 0, 0, 1, 0})
	require.NoError(t, err)

	// Whether the drop arrives as a clean EOF or as a reset is the kernel's
	// choice — closing a socket with unread bytes in its receive queue sends an
	// RST — and both are a drop. What is asserted is that nothing was said: a
	// reply in SOCKS5's grammar would be meaningless to a client that is not
	// speaking it.
	got, _ := io.ReadAll(conn)
	assert.Empty(t, got, "a client speaking another protocol is dropped, not answered in SOCKS5")
}

// ------------------------------------------------------- reply codes

// replyingError is a [Connect] failure that names its own reply code, which is
// how the forward connector classifies a refusal by the agent's policy.
type replyingError struct {
	code byte
	msg  string
}

func (e replyingError) Error() string    { return e.msg }
func (e replyingError) SOCKSReply() byte { return e.code }

// A destination refused by policy is not a fact about the network, and the code
// says so. A client shown "connection refused" for a destination its operator
// never permitted goes looking at the destination, which is up.
func TestSocks_ReportsAPolicyRefusalAsNotAllowed(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want byte
	}{
		{"refused by policy", replyingError{code: ReplyNotAllowed, msg: "not on the allow list"}, replyNotAllowed},
		{"nothing listening", replyingError{code: ReplyConnectionRefused, msg: "connection refused"}, replyConnectionRefused},
		{"no such host", replyingError{code: ReplyHostUnreachable, msg: "no such host"}, replyHostUnreachable},
		{"anything else", errors.New("something went wrong"), replyGeneralFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			connector := &dialingConnector{failWith: tc.err}
			server := startProxy(t, Options{Connect: connector.connect})

			c := dialProxy(t, server.Addr())
			assert.Equal(t, tc.want, c.connectByName(t, "db.internal", 5432))
		})
	}
}

// A connection that failed *after* it was answered gets no second reply.
//
// This is the sharpest failure this package has, and the least visible: the
// reply is ten bytes, and appending them to a response body that was already
// flowing corrupts exactly the transfers a proxy exists to carry — a truncated
// tarball, a JSON document with a decoding error nobody can place, a checksum
// that fails once in a hundred runs. Nothing about it looks like a proxy bug
// from the client's side.
//
// A connection can fail after the reply for entirely ordinary reasons: the
// agent restarting under it, the destination resetting mid-response, the
// stream ending. So this is the common case rather than an exotic one, and the
// client has already learned what it needs from the connection ending.
func TestSocks_DoesNotAppendAReplyToAConnectionAlreadyAnswered(t *testing.T) {
	const body = "a response body that must arrive exactly as it was written"

	// Answers the handshake, writes a body, and then fails the way a stream
	// that died mid-response does.
	server := startProxy(t, Options{
		Connect: func(_ context.Context, conn net.Conn, _ Destination, accepted func() error) error {
			if err := accepted(); err != nil {
				return err
			}
			if _, err := conn.Write([]byte(body)); err != nil {
				return err
			}
			return replyingError{code: ReplyConnectionRefused, msg: "the stream died mid-response"}
		},
	})

	c := dialProxy(t, server.Addr())
	require.Equal(t, byte(authNone), c.greet(t, authNone))
	require.Equal(t, byte(replySuccess), c.request(t, cmdConnect, addrDomain, []byte("db.internal"), 5432))

	got, err := io.ReadAll(c.conn)
	require.NoError(t, err)
	assert.Equal(t, body, string(got),
		"a reply code written into a response body corrupts it; the client learns about a connection that died from it ending")
}

// ------------------------------------------------------- the allow list

// --allow narrows destinations before the connection is opened. It is a
// convenience and not a boundary — it runs on this side of the tunnel — but a
// misaimed client should learn that locally and immediately rather than after a
// round trip.
func TestSocks_AllowListRefusesLocally(t *testing.T) {
	narrow, err := ParseAllowList([]string{"db.internal", "10.0.4.0/24", "cache.internal:6379"})
	require.NoError(t, err)
	require.NotNil(t, narrow)

	connector := &dialingConnector{failWith: errors.New("not reached")}
	server := startProxy(t, Options{Connect: connector.connect, Allow: narrow})

	for _, tc := range []struct {
		name    string
		host    string
		port    int
		allowed bool
	}{
		{"a listed name on any port", "db.internal", 5432, true},
		{"a listed name on another port", "db.internal", 9999, true},
		{"an address inside a listed block", "10.0.4.7", 443, true},
		{"a listed name on its listed port", "cache.internal", 6379, true},
		{"a listed name on a port it was not listed for", "cache.internal", 5432, false},
		{"an address outside every block", "203.0.113.9", 443, false},
		{"a name nobody listed", "elsewhere.example", 443, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := dialProxy(t, server.Addr())
			require.Equal(t, byte(authNone), c.greet(t, authNone))
			code := c.request(t, cmdConnect, addrDomain, []byte(tc.host), tc.port)
			if tc.allowed {
				// It got past the allow list and failed at the connector, which
				// is the next step: what is asserted here is which of the two
				// refused it.
				assert.NotEqual(t, byte(replyNotAllowed), code)
				return
			}
			assert.Equal(t, byte(replyNotAllowed), code)
		})
	}

	// Nothing the allow list refused reached the connector.
	for _, dst := range connector.destinations() {
		assert.NotEqual(t, "elsewhere.example", dst.Host)
		assert.NotEqual(t, "203.0.113.9", dst.Host)
	}
}

// No entries is no narrowing, which is the documented default rather than a
// list that permits nothing.
func TestParseAllowList_EmptyMeansNoNarrowing(t *testing.T) {
	narrow, err := ParseAllowList(nil)
	require.NoError(t, err)
	assert.Nil(t, narrow)

	narrow, err = ParseAllowList([]string{})
	require.NoError(t, err)
	assert.Nil(t, narrow)
}

// But an entry that is present and empty is refused, rather than skipped into
// the same answer.
//
// The two look alike and are opposite requests. `--allow "$NARROW"` with the
// variable unset arrives here as one blank entry; skipping it leaves no rules,
// which leaves no narrowing — so an operator who asked for a narrower proxy
// gets the widest one, and nothing says so. The same for an entry that names a
// port and no host: it builds a rule that can never match, which reads as
// narrowing and narrows nothing.
func TestParseAllowList_RefusesAnEntryThatNarrowsNothing(t *testing.T) {
	for _, entries := range [][]string{{""}, {"   "}, {"db.internal", ""}} {
		narrow, err := ParseAllowList(entries)
		require.Errorf(t, err, "%q must not be read as no narrowing at all", entries)
		assert.Nil(t, narrow)
		assert.Contains(t, err.Error(), "empty")
	}

	narrow, err := ParseAllowList([]string{":8080"})
	require.Error(t, err)
	assert.Nil(t, narrow)
	assert.Contains(t, err.Error(), "no host")
}

func TestParseAllowList_RejectsWhatItCannotParse(t *testing.T) {
	_, err := ParseAllowList([]string{"10.0.0.0/33"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "10.0.0.0/33")

	_, err = ParseAllowList([]string{"db.internal:not-a-port"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a port")
}

// ------------------------------------------------------------ the listener

// The listener binds loopback and nothing else. Binding every interface would
// publish an unauthenticated route into the sandbox's network to everyone on
// the workstation's own network, including one the user did not choose.
func TestSocks_ListenerIsNotReachableFromAnotherMachine(t *testing.T) {
	server := startProxy(t, Options{Connect: (&dialingConnector{}).connect})

	host, port, err := net.SplitHostPort(server.Addr())
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", host, "the reported address is the one it bound")

	routable := routableAddress(t)
	if routable == "" {
		t.Skip("this machine has no non-loopback IPv4 address to dial, so there is nothing another machine could try")
	}
	// What a machine on the same network would do. Loopback-bound means the
	// kernel does not answer here at all.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(routable, port), 3*time.Second)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("the proxy answered on %s, so it is reachable from any machine that can route to this one", routable)
	}
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

// An explicit port is honoured, and port 0 allocates one and reports it.
func TestSocks_PortSelection(t *testing.T) {
	allocated := startProxy(t, Options{Connect: (&dialingConnector{}).connect})
	require.Positive(t, allocated.Port())
	assert.Equal(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(allocated.Port())), allocated.Addr())

	// And a port already taken fails with a message that says what to do,
	// rather than a bare EADDRINUSE.
	_, err := Listen(allocated.Port(), Options{Connect: (&dialingConnector{}).connect})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "port 0")
}

func TestSocks_RefusesToListenWithoutAConnector(t *testing.T) {
	_, err := Listen(0, Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Connect")
}

// A client that connects and says nothing must not hold a goroutine and a
// descriptor for the life of the proxy. Opening connections and saying nothing
// is the cheapest thing a process on this machine can do.
//
// The deadline is watched biting, on a proxy whose copy of it has been
// shortened, rather than inferred from the constant existing. Asserting that
// handshakeTimeout is positive and that the connection was accepted is true of
// a proxy with no deadline at all: both halves of that hold whether or not
// conn.SetDeadline is ever called, so the assertion could not fail for the
// reason it was written for — and deleting the SetDeadline outright left it,
// and every other test in this tree, green.
func TestSocks_DropsAClientThatNeverSpeaks(t *testing.T) {
	require.Positive(t, handshakeTimeout, "the handshake must be bounded")
	require.LessOrEqual(t, handshakeTimeout, time.Minute,
		"a handshake deadline long enough to be worth leaking is not a bound")

	// Set before the accept loop starts: a connection reads this, so writing it
	// afterwards is a race, and -race is what says so.
	server := startProxy(t, Options{Connect: (&dialingConnector{}).connect}, func(s *Server) {
		// Short enough to watch, long enough that a loaded machine cannot trip
		// it between the dial and the write below.
		s.handshakeTimeout = 250 * time.Millisecond
	})

	conn, err := net.DialTimeout("tcp", server.Addr(), 10*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Half a greeting: enough to be accepted, not enough to finish. This is
	// what the deadline is for.
	_, err = conn.Write([]byte{version5})
	require.NoError(t, err)

	eventually(t, 10*time.Second, "the connection to be counted", func() bool {
		return server.Stats().Accepted == 1
	})

	// The proxy drops it: the goroutine and the descriptor come back without
	// the client having said anything more, and without the proxy being torn
	// down — which is the whole point, since tearing a listener down releases
	// everything under it whether or not any of this exists.
	eventually(t, 10*time.Second, "the parked handshake to be dropped", func() bool {
		return server.Stats().OpenNow == 0
	})

	// And the client's own socket is closed rather than merely forgotten: a
	// proxy that returned the goroutine and kept the socket still runs out of
	// descriptors, just more slowly.
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	var discard [1]byte
	_, err = conn.Read(discard[:])
	require.Error(t, err, "the proxy must close a handshake that timed out, not leave it open")
	assert.NotErrorIs(t, err, os.ErrDeadlineExceeded,
		"the read hit this test's own deadline, so the proxy had not closed the connection")
}

// And tearing the proxy down must not wait for that deadline.
//
// A handshake parked in a read is not waiting on a context, so cancelling one
// does not end it. Close is what the MCP server's shutdown and `fleetctl
// socks`'s Ctrl-C both go through, and half a greeting from any process on this
// machine would otherwise have been enough to make stopping the proxy take the
// whole handshake timeout.
func TestSocks_CloseDoesNotWaitForAParkedHandshake(t *testing.T) {
	server, err := Listen(0, Options{Connect: (&dialingConnector{}).connect})
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.Serve(context.Background())
	}()

	conn, err := net.DialTimeout("tcp", server.Addr(), 10*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte{version5})
	require.NoError(t, err)

	eventually(t, 10*time.Second, "the half-greeted connection to be counted", func() bool {
		return server.Stats().OpenNow == 1
	})

	// Comfortably under the handshake deadline, and comfortably over anything a
	// loopback teardown needs: a failure here is a Close that waited for the
	// deadline, not a slow machine.
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		require.NoError(t, server.Close())
	}()
	select {
	case <-closed:
	case <-time.After(handshakeTimeout / 3):
		t.Fatalf("Close waited for a parked handshake; it must close the socket rather than only cancelling the context")
	}
	wg.Wait()
}

// ------------------------------------------------------------- teardown

// Close releases the listener, the connections through it, and the goroutines
// carrying them — and returns only once it has, because a Close that returned
// early would leave this proxy's goroutines running under a process that
// believes it has stopped.
func TestSocks_CloseReleasesEverythingAndIsIdempotent(t *testing.T) {
	destination := destinationServer(t)
	connector := &dialingConnector{}

	server, err := Listen(0, Options{Connect: connector.connect})
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.Serve(context.Background())
	}()

	// One connection first, so the baseline holds whatever a single round trip
	// starts for good.
	roundTripThrough(t, server.Addr(), destination, "warmup")

	baseline := goleak.IgnoreCurrent()

	for i := range 25 {
		roundTripThrough(t, server.Addr(), destination, fmt.Sprintf("payload-%d", i))
	}
	// And connections held open with nothing happening on them, which is what a
	// keep-alive through a proxy is. Nothing on either side will end these:
	// closing the proxy has to.
	held := make([]net.Conn, 0, 10)
	for range 10 {
		conn, err := net.DialTimeout("tcp", server.Addr(), 10*time.Second)
		require.NoError(t, err)
		held = append(held, conn)
	}
	eventually(t, 30*time.Second, "the idle connections to be counted", func() bool {
		return server.Stats().OpenNow == len(held)
	})

	require.NoError(t, server.Close())
	require.NoError(t, server.Close(), "Close is idempotent")
	wg.Wait()

	// The listener is genuinely released, not merely delisted: the port is free
	// for the next process to want it.
	_, port, err := net.SplitHostPort(server.Addr())
	require.NoError(t, err)
	lis, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", port))
	require.NoError(t, err, "the port was not released")
	require.NoError(t, lis.Close())

	for _, conn := range held {
		_ = conn.Close()
	}
	goleak.VerifyNone(t, baseline)
}

// Closing before serving begins must stop the proxy rather than racing it.
func TestSocks_CloseBeforeServeStopsIt(t *testing.T) {
	server, err := Listen(0, Options{Connect: (&dialingConnector{}).connect})
	require.NoError(t, err)
	require.NoError(t, server.Close())

	done := make(chan struct{})
	go func() {
		defer close(done)
		server.Serve(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("Serve did not return on a proxy that was already closed")
	}
	assert.False(t, dialable(server.Addr()), "a closed proxy must not be accepting")
}

// roundTripThrough opens a proxied connection, sends payload, and reads the
// upper-cased echo back.
func roundTripThrough(t *testing.T, proxyAddr, destination, payload string) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(destination)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	c := dialProxy(t, proxyAddr)
	require.Equal(t, byte(authNone), c.greet(t, authNone))
	require.Equal(t, byte(replySuccess), c.request(t, cmdConnect, addrDomain, []byte(host), port))

	_, err = c.conn.Write([]byte(payload + "\n"))
	require.NoError(t, err)
	require.NoError(t, c.conn.(*net.TCPConn).CloseWrite())

	got, err := io.ReadAll(c.conn)
	require.NoError(t, err)
	require.Equal(t, strings.ToUpper(payload)+"\n", string(got))
}

// A client that has finished sending is still waiting to receive. Shutting the
// whole connection at a half-close is the bug that makes `curl` hang, and it is
// invisible against a server that answers before the request is complete — so
// this one answers only at EOF.
func TestSocks_HalfCloseLetsTheResponseComeBack(t *testing.T) {
	const reply = "the response arrived after the client had finished sending"
	destination := readThenReplyServer(t, reply)
	host, portStr, err := net.SplitHostPort(destination)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	server := startProxy(t, Options{Connect: (&dialingConnector{}).connect})

	c := dialProxy(t, server.Addr())
	require.Equal(t, byte(authNone), c.greet(t, authNone))
	require.Equal(t, byte(replySuccess), c.request(t, cmdConnect, addrDomain, []byte(host), port))

	_, err = c.conn.Write([]byte("a request the server will not answer until it ends"))
	require.NoError(t, err)
	require.NoError(t, c.conn.(*net.TCPConn).CloseWrite())

	got, err := io.ReadAll(c.conn)
	require.NoError(t, err)
	assert.Equal(t, reply, string(got),
		"a client that closed its write side must still receive the response")
}

// A large body streams rather than accumulating. Asserted on arrival order
// rather than on memory: the first chunk has to reach the client while the
// server is still writing the rest, which a proxy that buffered the whole body
// could not do.
func TestSocks_StreamsALargeResponseRatherThanBufferingIt(t *testing.T) {
	const (
		chunk  = 64 * 1024
		chunks = 64
	)
	// Written in chunks with the writer holding until the reader has taken the
	// first one. A proxy that buffered the whole body would deadlock here
	// rather than merely be slow, which is a failure that cannot be flaky.
	firstChunkRead := make(chan struct{})
	destination := tcpServer(t, func(conn net.Conn) {
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
		case <-time.After(30 * time.Second):
			return
		}
		for range chunks - 1 {
			if _, err := conn.Write(body); err != nil {
				return
			}
		}
	})
	host, portStr, err := net.SplitHostPort(destination)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	server := startProxy(t, Options{Connect: (&dialingConnector{}).connect})

	c := dialProxy(t, server.Addr())
	require.Equal(t, byte(authNone), c.greet(t, authNone))
	require.Equal(t, byte(replySuccess), c.request(t, cmdConnect, addrDomain, []byte(host), port))

	// The first chunk, read before the server has written anything else.
	first := make([]byte, chunk)
	_, err = io.ReadFull(c.conn, first)
	require.NoError(t, err, "the first chunk must arrive before the body is complete")
	close(firstChunkRead)

	rest, err := io.ReadAll(c.conn)
	require.NoError(t, err)
	assert.Equal(t, chunk*chunks, len(first)+len(rest), "and the whole body still arrives")
}

func eventually(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, what)
}

func dialable(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
