// Package socks implements the SOCKS5 server half of `fleetctl socks` and
// fleet_socks.
//
// It speaks the protocol and nothing else: what a destination means, and how
// bytes reach it, is [Connect]'s business. That split is what lets one
// implementation serve both the operator CLI and the MCP tool, and it is what
// lets the protocol be tested against a connector that goes nowhere.
//
// # What is implemented
//
// CONNECT, with no authentication, over a listener bound to loopback.
//
// BIND and UDP ASSOCIATE are refused with the code the RFC has for it (0x07,
// "command not supported"). Neither is a gap to fill later: BIND is a
// reverse-connection mechanism almost nothing uses, and UDP would need a
// datagram path the transport under this does not have — ForwardService carries
// a TCP connection. Half-implementing either would be worse than refusing:
// a client whose UDP association appears to be accepted and then silently
// carries nothing is a client debugging the wrong layer.
//
// No authentication because there is nobody to authenticate. The listener is on
// loopback, so its reachable population is "processes on this machine", and a
// username and password held in a config file next to it would add a step
// without adding a boundary. The boundary is the agent's, and it is applied per
// connection, on the far side, where a caller cannot skip it.
package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The protocol's own constants, spelled out rather than inlined: a reader
// checking this against RFC 1928 should be able to do it by name.
const (
	version5 = 0x05
	// authNone is the only method offered. See the package comment.
	authNone         = 0x00
	authNoAcceptable = 0xFF

	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03

	addrIPv4   = 0x01
	addrDomain = 0x03
	addrIPv6   = 0x04
)

// Reply codes, from RFC 1928 §6.
const (
	replySuccess             = 0x00
	replyGeneralFailure      = 0x01
	replyNotAllowed          = 0x02
	replyHostUnreachable     = 0x04
	replyConnectionRefused   = 0x05
	replyCommandNotSupported = 0x07
	replyAddressNotSupported = 0x08
)

// handshakeTimeout bounds the exchange before any bytes are carried.
//
// It is not a policy, it is a leak fix: a client that connects and says nothing
// would otherwise hold a goroutine and a descriptor for as long as the proxy
// lives, and opening connections and saying nothing is the cheapest thing a
// process on this machine can do. It is cleared before the connection is
// carried — a proxied connection may be idle for hours and that is ordinary.
//
// Not an [Options] field: there is no version of this an operator should be
// choosing, and one that could set it to zero would be choosing the leak. It is
// copied onto each [Server] instead, so a test can shorten it and watch a
// parked handshake actually be dropped. Asserting that this constant is a
// sensible number is not the same claim, and it held while nothing applied it:
// deleting the SetDeadline below left every test in this tree green.
const handshakeTimeout = 30 * time.Second

// Destination is where a client asked to be connected.
type Destination struct {
	// Host is the destination as the client spelled it: a name when the client
	// sent one, otherwise an IP address in string form.
	//
	// A name is passed on as a name, never resolved here. That is the whole
	// point of `curl --socks5-hostname`: the name is resolved by whatever is at
	// the far end of the tunnel, which is the only resolver that knows what a
	// private name means. Resolving it on this side reaches a different host or
	// fails outright.
	Host string
	// Port is the destination port.
	Port int
	// Name reports that the client sent a domain name rather than an address,
	// which is what a caller checking that resolution happened remotely needs.
	Name bool
}

// Label renders a destination for a log line or an error.
func (d Destination) Label() string { return net.JoinHostPort(d.Host, strconv.Itoa(d.Port)) }

// Connect carries one accepted connection to its destination.
//
// It must call accepted once the destination is connected and before any bytes
// move, and must not call it if the destination was not connected. That
// ordering is the protocol's, not this package's: a SOCKS client sends nothing
// until the reply arrives, so pumping before the reply deadlocks — and replying
// before the far side is connected reports a success that may not happen, which
// costs the client its own error handling.
//
// accepted returns the error from writing the reply. A Connect that ignores it
// pumps into a socket that is already gone.
//
// It must **not** close conn. This package owns the socket on every path,
// because a connection whose open failed still has a reply code to carry and a
// socket the connector had already closed could not carry it.
//
// An error returned *before* accepted decides the reply code, through
// [ReplyCode]. An error returned after it is a connection that failed while it
// was being carried, which the client learns from the connection ending — a
// reply code written into a response body would corrupt it.
type Connect func(ctx context.Context, conn net.Conn, dst Destination, accepted func() error) error

// Options configure a proxy.
type Options struct {
	// Connect carries each accepted connection. Required.
	Connect Connect
	// Allow optionally narrows destinations before the connection is opened.
	//
	// It is a convenience for the operator running the proxy, never a boundary:
	// it runs in this process, on this side of the tunnel, and the agent's own
	// policy is applied to every connection regardless. Its value is stopping a
	// misaimed client early and locally, with a clear message, rather than
	// after a round trip.
	Allow func(dst Destination) bool
	// Log receives per-connection detail. Nil discards.
	Log *slog.Logger
}

// Stats is what a proxy has carried.
type Stats struct {
	// Accepted is every connection since the listener opened.
	Accepted uint64
	// OpenNow is how many are in flight.
	OpenNow int
	// LastError is the most recent per-connection failure. A proxy whose
	// listener is fine but whose destinations all refuse looks healthy from the
	// outside; this is where that shows.
	LastError string
}

// Server is a SOCKS5 proxy on a loopback listener.
type Server struct {
	listener net.Listener
	opts     Options
	log      *slog.Logger

	// handshakeTimeout is [handshakeTimeout], per server so a test can shorten
	// it. Never zero: Listen is the only constructor and always sets it.
	handshakeTimeout time.Duration

	cancel context.CancelFunc
	// wg covers the accept loop and every per-connection goroutine, so Close
	// returns only once nothing is still running. Two pumps and a stream per
	// connection is exactly where a long-lived proxy leaks goroutines, and
	// joining them here is what makes the goleak assertion pass rather than
	// merely usually pass.
	wg sync.WaitGroup

	mu       sync.Mutex
	closed   bool
	accepted uint64
	open     int
	lastErr  string

	closeOnce sync.Once
}

// Listen opens a loopback listener on port and returns a proxy that is not yet
// serving. Port 0 picks a free one; read it back from [Server.Addr].
//
// Loopback explicitly, and it is the reason this takes a port rather than an
// address: binding every interface would publish an unauthenticated route into
// the sandbox's network to everyone on the workstation's own network, including
// a network the user did not choose. There is no flag for it because there is
// no version of this that should be reachable from another machine — an
// operator who wants that has ssh.
func Listen(port int, opts Options) (*Server, error) {
	if opts.Connect == nil {
		return nil, errors.New("socks: Options.Connect is required")
	}
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("socks: port %d is out of range; expected 0-65535, where 0 picks a free port", port)
	}

	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		if port != 0 {
			return nil, fmt.Errorf("could not listen on 127.0.0.1:%d (something else is using that port; pass port 0 to have one picked): %w", port, err)
		}
		return nil, fmt.Errorf("could not open a local listener: %w", err)
	}

	log := opts.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Server{listener: listener, opts: opts, log: log, handshakeTimeout: handshakeTimeout}, nil
}

// Addr is the address the listener took, e.g. 127.0.0.1:1080.
func (s *Server) Addr() string { return s.listener.Addr().String() }

// Port is the local half of [Server.Addr].
func (s *Server) Port() int {
	if addr, ok := s.listener.Addr().(*net.TCPAddr); ok {
		return addr.Port
	}
	return 0
}

// Stats reports what this proxy has carried.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Stats{Accepted: s.accepted, OpenNow: s.open, LastError: s.lastErr}
}

func (s *Server) note(err string) {
	s.mu.Lock()
	s.lastErr = err
	s.mu.Unlock()
}

// Serve accepts connections until the proxy is closed. It returns when the
// accept loop ends; per-connection goroutines are joined by [Server.Close].
//
// ctx bounds every connection this proxy carries, so cancelling it is the other
// way to end the proxy — but it is not a substitute for Close, which is what
// releases the listener and joins.
func (s *Server) Serve(ctx context.Context) {
	// The proxy's own context, so Close ends connections that Serve's caller
	// has no handle on.
	serveCtx, cancel := context.WithCancel(ctx)

	s.mu.Lock()
	if s.closed {
		// Closed before serving began. Without this the cancel installed here
		// would be one nothing ever calls, and the accept loop below would run
		// under a live context on a listener that has already been closed —
		// which ends it, but only by luck of the ordering. Losing that race
		// leaves a proxy the caller believes it stopped.
		s.mu.Unlock()
		cancel()
		return
	}
	s.cancel = cancel
	// Registered under the same lock that decided this proxy is not closed, so
	// that a Close arriving now either sees closed=false and joins this loop, or
	// runs first and is seen above. Adding after the unlock leaves a window in
	// which Close finds an empty group and returns while the accept loop is
	// starting — which is a Close that has not joined what it documents joining,
	// and which nothing here would notice because both callers happen to hold
	// the goroutine some other way.
	s.wg.Add(1)
	s.mu.Unlock()

	s.acceptLoop(serveCtx)
}

// Bounds on how fast a failing listener is retried.
const (
	minAcceptBackoff = 5 * time.Millisecond
	maxAcceptBackoff = time.Second
)

func (s *Server) acceptLoop(ctx context.Context) {
	defer s.wg.Done()

	backoff := time.Duration(0)
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			// A closed listener, or a torn-down proxy, is how this ends.
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			// Anything else is transient until proven otherwise, and giving up
			// on it would leave a proxy that is still listed as open, still
			// holding its port, and permanently deaf. A workstation that hits
			// its descriptor limit for a second — which is what EMFILE is, and
			// the kernel hands it straight back here — must not silently cost
			// the caller the proxy it is working through. Backed off so a
			// listener that is genuinely broken costs one syscall a second
			// rather than a spin.
			backoff = nextAcceptBackoff(backoff)
			s.note("accepting a local connection: " + err.Error())
			s.log.Warn("socks accept failed, retrying",
				"local", s.Addr(), "retry_in", backoff, "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
				continue
			}
		}
		backoff = 0

		s.mu.Lock()
		s.accepted++
		s.open++
		s.mu.Unlock()

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				s.open--
				s.mu.Unlock()
			}()
			if err := s.handle(ctx, conn); err != nil {
				s.note(err.Error())
				s.log.Debug("proxied connection failed", "local", s.Addr(), "error", err)
			}
		}()
	}
}

// nextAcceptBackoff doubles a retry delay up to the cap.
func nextAcceptBackoff(current time.Duration) time.Duration {
	switch {
	case current <= 0:
		return minAcceptBackoff
	case current >= maxAcceptBackoff:
		return maxAcceptBackoff
	default:
		return min(current*2, maxAcceptBackoff)
	}
}

// Close releases the listener and every connection through it, and joins. It is
// idempotent.
//
// The order matters: the listener first, so nothing new is accepted, then the
// connections in flight, then the join. Returning before the join would leave
// this proxy's goroutines running under a process that believes it has stopped.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		_ = s.listener.Close()
		s.mu.Lock()
		s.closed = true
		cancel := s.cancel
		s.mu.Unlock()
		if cancel != nil {
			cancel()
		}
	})
	s.wg.Wait()
	return nil
}

// handle runs one accepted connection: the handshake, then the carry.
func (s *Server) handle(ctx context.Context, conn net.Conn) error {
	// This function owns the socket on every path, including the one through
	// Connect. That is why [Connect] is documented as not closing it: a
	// connection whose open failed still has a reply code to carry, and a socket
	// the connector had already closed could not carry it.
	defer func() { _ = conn.Close() }()

	// Tearing the proxy down has to close this socket, not merely cancel the
	// context. A handshake parked in io.ReadFull is not waiting on a context, so
	// without this a client that connected and went quiet would hold Close for
	// the whole handshake deadline — and Close is what the MCP server's shutdown
	// and `fleetctl socks`'s Ctrl-C both go through. Half a greeting from one
	// process on this machine would have been enough to make stopping the proxy
	// take thirty seconds.
	stopOnCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopOnCancel()

	// Bounded, because a client that connects and says nothing must not hold a
	// goroutine for the life of the proxy. Cleared below before any bytes are
	// carried: an idle proxied connection is ordinary and must not be killed
	// for being quiet.
	if err := conn.SetDeadline(time.Now().Add(s.handshakeTimeout)); err != nil {
		return fmt.Errorf("setting the handshake deadline: %w", err)
	}

	if err := negotiate(conn); err != nil {
		return err
	}

	dst, err := readRequest(conn)
	if err != nil {
		var reqErr *requestError
		if errors.As(err, &reqErr) {
			// Answered rather than dropped: a client that gets a reply code
			// reports something useful, and one whose socket simply closes
			// reports "connection reset by peer" and nothing about why.
			_ = writeReply(conn, reqErr.code)
		}
		return err
	}

	if s.opts.Allow != nil && !s.opts.Allow(dst) {
		_ = writeReply(conn, replyNotAllowed)
		return fmt.Errorf("%s is not permitted by this proxy's --allow list", dst.Label())
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clearing the handshake deadline: %w", err)
	}

	s.log.Debug("proxying", "destination", dst.Label(), "resolved_remotely", dst.Name)

	// Whether the handshake was answered, which decides whether a failure gets a
	// reply code or nothing at all. Atomic because the contract lets a connector
	// call accepted from a goroutine of its own; the answer is read only after
	// Connect has returned, so this is about visibility rather than ordering.
	var replied atomic.Bool
	err = s.opts.Connect(ctx, conn, dst, func() error {
		replied.Store(true)
		return writeReply(conn, replySuccess)
	})
	switch {
	case err == nil:
		return nil
	case replied.Load():
		// The connection opened and then failed while it was being carried. The
		// client has had its reply and is reading a response body; ten more
		// bytes of handshake appended to it would corrupt exactly the transfers
		// this proxy exists to carry. The client learns about this the way it
		// learns about any connection that dies mid-response — from the
		// connection ending.
		return fmt.Errorf("%s: %w", dst.Label(), err)
	default:
		// A connection that never opened, answered with the code for why.
		// Writing it here rather than inside Connect keeps the protocol in this
		// package: a connector should not have to know that 0x05 means
		// "refused".
		_ = writeReply(conn, ReplyCode(err))
		return fmt.Errorf("%s: %w", dst.Label(), err)
	}
}

// negotiate runs the method-selection exchange.
//
// Every fixed-length field below is read into an array rather than a slice, so
// that its length is part of its type. io.ReadFull guarantees a full read or an
// error, but only the array makes that guarantee legible to a reader — and to
// the static analysis, which cannot otherwise tell a two-byte header from an
// empty one.
func negotiate(conn net.Conn) error {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return fmt.Errorf("reading the SOCKS greeting: %w", err)
	}
	//nolint:gosec // G602 cannot see that a [2]byte read through header[:] still has two elements; both indexes are in range by the array's type
	version, methodCount := header[0], header[1]

	if version != version5 {
		// No reply: the client is not speaking a protocol this understands, so
		// there is no reply shape that means anything to it. A SOCKS4 client
		// arrives here, and telling it something in SOCKS5's grammar would be
		// worse than silence.
		return fmt.Errorf("this proxy speaks SOCKS5; the client offered version %d", version)
	}

	count := int(methodCount)
	if count == 0 {
		_ = writeMethod(conn, authNoAcceptable)
		return errors.New("the client offered no authentication methods")
	}
	methods := make([]byte, count)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("reading the client's authentication methods: %w", err)
	}
	for _, method := range methods {
		if method == authNone {
			return writeMethod(conn, authNone)
		}
	}
	_ = writeMethod(conn, authNoAcceptable)
	return errors.New("the client would not proxy without authentication, and this proxy has none to offer: it is bound to loopback, so its reachable population is processes on this machine")
}

func writeMethod(conn net.Conn, method byte) error {
	if _, err := conn.Write([]byte{version5, method}); err != nil {
		return fmt.Errorf("answering the SOCKS greeting: %w", err)
	}
	return nil
}

// requestError is a malformed or unsupported request that has a reply code.
type requestError struct {
	code byte
	msg  string
}

func (e *requestError) Error() string { return e.msg }

// readRequest parses one CONNECT request and returns where it points.
//
// It reads the whole request whatever it turns out to be, and judges it at the
// end. Answering before the destination fields have been consumed would leave
// them unread in the receive buffer, and closing a socket with unread data
// sends a reset rather than a FIN — which can discard the reply that was just
// written, leaving the client with exactly the bare "connection reset" this
// package answers reply codes in order to avoid. That applies to every request
// this answers, not only to the unsupported command it was first noticed for:
// an empty destination name is a well-formed request with a port still on the
// wire behind it.
//
// Two things cannot be read past, and are answered where they are found: a
// version this does not speak, whose remaining fields are not this grammar's,
// and an address type this does not implement, because nothing says how long
// that address is.
func readRequest(conn net.Conn) (Destination, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return Destination{}, fmt.Errorf("reading the SOCKS request: %w", err)
	}
	// Byte 2 is the protocol's reserved field, which is ignored deliberately:
	// clients do write things there, and refusing over it would break them for
	// no gain.
	//nolint:gosec // G602 cannot see that a [4]byte read through header[:] still has four elements; every index is in range by the array's type
	version, cmd, addrType := header[0], header[1], header[3]

	if version != version5 {
		return Destination{}, &requestError{
			code: replyGeneralFailure,
			msg:  fmt.Sprintf("the SOCKS request named version %d, not 5", version),
		}
	}

	var dst Destination
	switch addrType {
	case addrIPv4:
		raw := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return Destination{}, fmt.Errorf("reading the destination address: %w", err)
		}
		dst.Host = net.IP(raw).String()
	case addrIPv6:
		raw := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return Destination{}, fmt.Errorf("reading the destination address: %w", err)
		}
		dst.Host = net.IP(raw).String()
	case addrDomain:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return Destination{}, fmt.Errorf("reading the destination name length: %w", err)
		}
		// A zero length is judged below with everything else, rather than
		// answered here: the port is still on the wire behind it, and a reply
		// written over an unread port is the reset this function reads the whole
		// request to avoid.
		raw := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, raw); err != nil {
			return Destination{}, fmt.Errorf("reading the destination name: %w", err)
		}
		dst.Host, dst.Name = string(raw), true
	default:
		return Destination{}, &requestError{
			code: replyAddressNotSupported,
			msg:  fmt.Sprintf("the SOCKS request used address type 0x%02x, which this proxy does not implement", addrType),
		}
	}

	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return Destination{}, fmt.Errorf("reading the destination port: %w", err)
	}
	dst.Port = int(binary.BigEndian.Uint16(port[:]))

	// The command is judged before the destination fields are, because a
	// request for a command this proxy does not implement is unsupported
	// whatever they hold. RFC 1928 §4 tells a client that does not yet know
	// the address it will send datagrams from to put all zeros in a UDP
	// ASSOCIATE — so the conformant spelling of the one request this proxy
	// most expects to refuse arrives with port 0, and judging the port first
	// answered it with "general failure". A client told that goes looking at
	// its destination instead of at the command it asked for, which is the
	// wrong layer, and is the outcome refusing cleanly exists to avoid.
	if cmd != cmdConnect {
		return Destination{}, &requestError{
			code: replyCommandNotSupported,
			msg:  fmt.Sprintf("this proxy implements CONNECT only; the client asked for %s", commandName(cmd)),
		}
	}

	// An empty name is judged after the command, for the same reason the port
	// is: a client asking for a command this does not implement is answered
	// about the command whatever its destination fields hold.
	if dst.Name && dst.Host == "" {
		return Destination{}, &requestError{
			code: replyAddressNotSupported,
			msg:  "the SOCKS request carried an empty destination name",
		}
	}

	if dst.Port == 0 {
		return Destination{}, &requestError{
			code: replyGeneralFailure,
			msg:  "the SOCKS request named port 0",
		}
	}
	return dst, nil
}

// writeReply answers a request.
//
// The bound address is reported as 0.0.0.0:0. The field is meant to be the
// address the proxy took on the client's behalf, and there isn't one: the
// socket that reaches the destination is opened on the sandbox, on a network
// this client cannot address. Reporting the agent's local address would put a
// meaningless address in front of anyone debugging, and every client that
// matters ignores the field — `ssh -D` answers the same way.
func writeReply(conn net.Conn, code byte) error {
	reply := []byte{version5, code, 0x00, addrIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(reply); err != nil {
		return fmt.Errorf("answering the SOCKS request: %w", err)
	}
	return nil
}

// ReplyCoder is implemented by an error that knows which SOCKS reply code it
// is, so a [Connect] can classify its own failures without this package
// knowing what a forward stream is.
type ReplyCoder interface {
	// SOCKSReply is the RFC 1928 §6 reply code for this failure.
	SOCKSReply() byte
}

// ReplyCode is the code a failed [Connect] is answered with.
func ReplyCode(err error) byte {
	var coder ReplyCoder
	if errors.As(err, &coder) {
		return coder.SOCKSReply()
	}
	return replyGeneralFailure
}

// The reply codes a [Connect] implementation classifies its failures into.
// Exported so that a connector can name the outcome without this package
// exporting the whole protocol.
const (
	// ReplyNotAllowed is a destination policy refused.
	ReplyNotAllowed = replyNotAllowed
	// ReplyHostUnreachable is a name that did not resolve, or a network with no
	// route to it.
	ReplyHostUnreachable = replyHostUnreachable
	// ReplyConnectionRefused is a destination that resolved and routed but did
	// not answer.
	ReplyConnectionRefused = replyConnectionRefused
	// ReplyGeneralFailure is everything else.
	ReplyGeneralFailure = replyGeneralFailure
)

func commandName(cmd byte) string {
	switch cmd {
	case cmdBind:
		return "BIND, which is a reverse-connection mechanism this does not implement"
	case cmdUDPAssociate:
		return "UDP ASSOCIATE, which would need a datagram path the transport under this proxy does not have"
	default:
		return fmt.Sprintf("command 0x%02x", cmd)
	}
}

// ParseAllowList builds an [Options.Allow] from operator-supplied entries.
//
// An entry is a host, a host:port, or a CIDR block, optionally with a port. A
// bare host permits every port on it. Matching a name is literal and
// case-insensitive; matching an address or block is by address, and a name is
// *not* resolved to compare it — resolving here is exactly what a SOCKS proxy
// exists not to do.
//
// No entries at all is no narrowing, which is the documented default. An entry
// that is *present but empty* is an error rather than a skipped line, and the
// difference matters: `--allow "$NARROW"` with the variable unset would
// otherwise leave a list of one blank entry, which parses to nothing, which
// means no narrowing — an operator who asked for a narrower proxy and got the
// widest one, silently. An entry with no host ("`:8080`") is refused for the
// same reason: it builds a rule nothing can ever match, so it reads as
// narrowing and narrows nothing.
func ParseAllowList(entries []string) (func(Destination) bool, error) {
	type rule struct {
		host  string
		block *net.IPNet
		ip    net.IP
		port  int
	}
	rules := make([]rule, 0, len(entries))
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			return nil, fmt.Errorf("--allow %q is empty; drop the flag to narrow nothing, which is the default", raw)
		}
		r := rule{}
		// A port is only split off when what remains still parses as something
		// addressable: "::1" has colons and no port, and "10.0.0.0/8" has none
		// either.
		if host, port, err := net.SplitHostPort(entry); err == nil {
			n, convErr := strconv.Atoi(port)
			if convErr != nil || n < 1 || n > 65535 {
				return nil, fmt.Errorf("--allow %q: %q is not a port", raw, port)
			}
			if strings.TrimSpace(host) == "" {
				return nil, fmt.Errorf("--allow %q names a port but no host; write the host too, or drop the flag to narrow nothing", raw)
			}
			entry, r.port = host, n
		}
		switch {
		case strings.Contains(entry, "/"):
			_, block, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, fmt.Errorf("--allow %q: %w", raw, err)
			}
			r.block = block
		default:
			if ip := net.ParseIP(entry); ip != nil {
				r.ip = ip
			} else {
				r.host = strings.ToLower(entry)
			}
		}
		rules = append(rules, r)
	}
	if len(rules) == 0 {
		// Only reachable for an empty slice: every entry that got this far
		// produced a rule.
		return nil, nil //nolint:nilnil // no entries is no narrowing, which is the documented default rather than a failure
	}

	return func(dst Destination) bool {
		ip := net.ParseIP(dst.Host)
		for _, r := range rules {
			if r.port != 0 && r.port != dst.Port {
				continue
			}
			switch {
			case r.host != "":
				if strings.EqualFold(r.host, dst.Host) {
					return true
				}
			case r.ip != nil:
				if ip != nil && r.ip.Equal(ip) {
					return true
				}
			case r.block != nil:
				if ip != nil && r.block.Contains(ip) {
					return true
				}
			}
		}
		return false
	}, nil
}

// DescribeAllowList renders entries for a banner or a result, sorted so two
// runs of the same command read the same.
func DescribeAllowList(entries []string) string {
	if len(entries) == 0 {
		return ""
	}
	out := make([]string, len(entries))
	copy(out, entries)
	sort.Strings(out)
	return strings.Join(out, ", ")
}
