package tools

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
)

// The pump these tests drive lives in internal/tunnel, shared with the SOCKS
// proxy, and its own half-close contract is pinned there. What is left here is
// what belongs to fleet_forward: the accept loop, the listing, and the
// connection lifetimes carry has to end.

// tcpPair returns the server end of a real loopback connection. A net.Pipe
// would not do: the pump half-closes a *net.TCPConn and closes anything else
// outright, and the difference is the whole subject here.
//
// The client end is not returned because no test here speaks on it — the point
// of every one of them is a client that says nothing. It is held open by the
// cleanup that closes it, which is what makes "the peer is still there and
// still silent" the state under test rather than a socket the runtime happened
// not to have collected.
func tcpPair(t *testing.T) net.Conn {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = lis.Close() }()

	type accepted struct {
		conn net.Conn
		err  error
	}
	done := make(chan accepted, 1)
	go func() {
		conn, err := lis.Accept()
		done <- accepted{conn: conn, err: err}
	}()

	client, err := net.DialTimeout("tcp", lis.Addr().String(), 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	got := <-done
	require.NoError(t, got.err)
	t.Cleanup(func() { _ = got.conn.Close() })
	return got.conn
}

// ------------------------------------------------- the end of a connection

// carriedStream is one gRPC stream's worth of scripted behaviour: an open, then
// whatever Recv is told to end with. Send never fails, standing in for a
// transport that has not noticed anything yet.
type carriedStream struct {
	grpc.ClientStream
	opened bool
	// endWith is returned by the second Recv. io.EOF is the agent's handler
	// having returned; anything else is the RPC failing under the connection.
	endWith error
}

func (s *carriedStream) Send(*sandboxdv1.ForwardRequest) error { return nil }
func (s *carriedStream) CloseSend() error                      { return nil }

func (s *carriedStream) Recv() (*sandboxdv1.ForwardResponse, error) {
	if !s.opened {
		s.opened = true
		return &sandboxdv1.ForwardResponse{
			Event: &sandboxdv1.ForwardResponse_Opened{Opened: &sandboxdv1.ForwardOpened{Success: true}},
		}, nil
	}
	return nil, s.endWith
}

type carriedClient struct{ stream *carriedStream }

func (c *carriedClient) Forward(context.Context, ...grpc.CallOption) (grpc.BidiStreamingClient[sandboxdv1.ForwardRequest, sandboxdv1.ForwardResponse], error) {
	return c.stream, nil
}

// A connection whose stream has ended must be released even when the local
// client has nothing more to say.
//
// The local client here is idle, which is what a browser holding a keep-alive
// connection through a forward is: it is parked waiting to be spoken to, and
// the send pump is parked in conn.Read waiting for it. Nothing in that pair
// ever unblocks on its own, so a carry that joins both without ending the
// connection holds one goroutine, one descriptor and one stream for the life of
// the forward — per connection, on exactly the long-lived forward where they
// accumulate. An agent restart under an idle connection is all it takes.
func TestCarry_ReleasesAConnectionWhoseStreamEnded(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  error
	}{
		{"the stream failed", errors.New("the agent went away mid-connection")},
		{"the stream ended", io.EOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The local client end is held open and read from by nobody: the
			// point is that this side gives up without it.
			server := tcpPair(t)

			r := NewRegistrar(nil, Deps{})
			f := &activeForward{key: forwardKey{sandbox: "build-box", remotePort: 3000}, localAddr: "127.0.0.1:1"}

			done := make(chan error, 1)
			go func() {
				done <- r.carry(t.Context(), f, &carriedClient{stream: &carriedStream{endWith: tc.end}}, server)
			}()

			select {
			case <-done:
			case <-time.After(20 * time.Second):
				t.Fatal("carry never returned: the connection, its socket and both its goroutines are held until the whole forward is torn down")
			}
		})
	}
}

// quietStream is a stream that opens and then says nothing until its RPC
// context is cancelled, which is what a real one does while the sandbox-side
// server sits idle. It is the other half of the pair: carriedStream ends on its
// own, this one never does.
type quietStream struct {
	grpc.ClientStream
	ctx    context.Context //nolint:containedctx // it stands in for the RPC context a real stream carries
	opened bool
}

func (s *quietStream) Send(*sandboxdv1.ForwardRequest) error { return nil }
func (s *quietStream) CloseSend() error                      { return nil }

func (s *quietStream) Recv() (*sandboxdv1.ForwardResponse, error) {
	if !s.opened {
		s.opened = true
		return &sandboxdv1.ForwardResponse{
			Event: &sandboxdv1.ForwardResponse_Opened{Opened: &sandboxdv1.ForwardOpened{Success: true}},
		}, nil
	}
	<-s.ctx.Done()
	return nil, s.ctx.Err()
}

type quietClient struct{}

func (quietClient) Forward(ctx context.Context, _ ...grpc.CallOption) (grpc.BidiStreamingClient[sandboxdv1.ForwardRequest, sandboxdv1.ForwardResponse], error) {
	return &quietStream{ctx: ctx}, nil
}

// resetConn is a local connection whose read side has failed the way a client
// killed mid-request does: a reset, which is neither io.EOF nor net.ErrClosed
// and is not something the connection recovers from.
type resetConn struct{ net.Conn }

func (c *resetConn) Read([]byte) (int, error) {
	return 0, &net.OpError{Op: "read", Net: "tcp", Err: errors.New("connection reset by peer")}
}

// A connection whose local client died must be released without waiting for the
// sandbox-side server to notice.
//
// A half-close is EOF and must not end the connection — the response still has
// to come back — but a *failed* read is the client being gone, and there is
// nothing left to deliver to. Without ending the connection there, the
// receiving pump stays parked in stream.Recv until the sandbox-side server
// happens to close: one goroutine, one descriptor, one gRPC stream and one slot
// against the agent's forward.max_connections, held per aborted request on
// exactly the long-lived forward where they accumulate. A server that neither
// writes nor closes when its peer half-closes — anything waiting for the rest
// of a message — never gets there at all.
func TestCarry_ReleasesAConnectionWhoseLocalClientDied(t *testing.T) {
	server := tcpPair(t)

	r := NewRegistrar(nil, Deps{})
	f := &activeForward{key: forwardKey{sandbox: "build-box", remotePort: 3000}, localAddr: "127.0.0.1:1"}

	done := make(chan error, 1)
	go func() {
		done <- r.carry(t.Context(), f, quietClient{}, &resetConn{Conn: server})
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reading from the local connection",
			"the client's own failure is the cause, and is what belongs in the forward's last_error")
	case <-time.After(20 * time.Second):
		t.Fatal("carry never returned: an aborted local connection holds its stream, its socket and the agent's connection slot until the sandbox-side server happens to close")
	}
}

// ------------------------------------------------------------- the stop call

// The instruction a forward hands back has to be the one that works. remote_host
// is part of the key, so a stop call that omits it looks up a different forward,
// finds nothing, and fails — costing a turn and reading as though the forward
// had closed itself.
func TestForwardKey_StopCallNamesTheHostThatIsPartOfTheKey(t *testing.T) {
	loopback := forwardKey{sandbox: "build-box", remotePort: 3000}
	assert.Equal(t, "fleet_forward(remote_port=3000, stop=true)", loopback.stopCall())

	named := forwardKey{sandbox: "build-box", remoteHost: "db.internal", remotePort: 5432}
	assert.Contains(t, named.stopCall(), "remote_host")
	assert.Contains(t, named.stopCall(), "db.internal")
	assert.Contains(t, named.stopCall(), "remote_port=5432")
	assert.Contains(t, named.stopCall(), "stop=true")
}

// ---------------------------------------------------------- accept backoff

// A listener that fails an accept for a transient reason — a workstation at its
// descriptor limit for a second, which the kernel hands back as EMFILE — must
// not cost the model the tunnel it is working through. The retry is backed off
// so a listener that is genuinely broken costs one syscall a second rather than
// a spin.
func TestNextAcceptBackoff_GrowsToACapAndStopsThere(t *testing.T) {
	d := nextAcceptBackoff(0)
	assert.Equal(t, minAcceptBackoff, d)

	seen := 1
	for d < maxAcceptBackoff {
		next := nextAcceptBackoff(d)
		require.Greater(t, next, d, "the backoff must grow")
		d = next
		seen++
		require.Less(t, seen, 64, "the backoff must reach its cap in a bounded number of steps")
	}
	assert.Equal(t, maxAcceptBackoff, d)
	assert.Equal(t, maxAcceptBackoff, nextAcceptBackoff(d), "and stay there")
}

// flakyListener fails a fixed number of accepts before reporting that it is
// closed. It stands in for a workstation momentarily out of descriptors, which
// the kernel hands straight back through Accept.
type flakyListener struct {
	mu       sync.Mutex
	failures int
	calls    int
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	if l.failures > 0 {
		l.failures--
		return nil, &net.OpError{Op: "accept", Err: syscall.EMFILE}
	}
	return nil, net.ErrClosed
}

func (l *flakyListener) Close() error   { return nil }
func (l *flakyListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }

func (l *flakyListener) accepts() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

// A transient accept failure must not cost the forward. Giving up leaves a
// listener that is still listed as open, still holding its port, and
// permanently deaf — and nothing in the result would say so.
func TestAcceptLoop_RetriesATransientAcceptFailure(t *testing.T) {
	lis := &flakyListener{failures: 3}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f := &activeForward{
		key:       forwardKey{sandbox: "build-box", remotePort: 3000},
		localAddr: "127.0.0.1:1",
		listener:  lis,
		cancel:    cancel,
	}
	r := NewRegistrar(nil, Deps{})

	f.wg.Add(1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.acceptLoop(ctx, f, nil, nil)
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the accept loop never returned")
	}

	assert.Equal(t, 4, lis.accepts(),
		"the loop must retry a transient failure and stop only when the listener is closed")
	_, _, lastErr := f.stats()
	assert.Contains(t, lastErr, "accepting a local connection",
		"the failure must be visible in the forward's listing rather than only in a log")
}

// alwaysFailingListener never recovers and never reports itself closed: a
// descriptor limit that does not clear, which is the case the retry must not
// turn into a forward that cannot be torn down.
type alwaysFailingListener struct{ flakyListener }

func (l *alwaysFailingListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	return nil, &net.OpError{Op: "accept", Err: syscall.EMFILE}
}

// A forward torn down while its accept loop is backing off has to come apart at
// once.
//
// activeForward.close closes the listener, cancels, and then joins — so a
// backoff that only waited out its timer would hold fleet_forward(stop=true),
// fleet_remove and the MCP server's own shutdown for up to the cap, on a
// listener that has already been closed. The retry is what makes a transient
// failure survivable; the cancellation is what stops it making teardown wait.
func TestAcceptLoop_TearingDownDuringABackoffReturnsAtOnce(t *testing.T) {
	lis := &alwaysFailingListener{}
	ctx, cancel := context.WithCancel(context.Background())
	f := &activeForward{
		key:       forwardKey{sandbox: "build-box", remotePort: 3000},
		localAddr: "127.0.0.1:1",
		listener:  lis,
		cancel:    cancel,
	}
	r := NewRegistrar(nil, Deps{})

	f.wg.Add(1)
	go r.acceptLoop(ctx, f, nil, nil)

	// Let it climb to the cap, so a loop that waited out its timer would be
	// waiting out the longest one.
	require.Eventually(t, func() bool { return lis.accepts() > 8 }, 20*time.Second, 5*time.Millisecond,
		"the loop must keep retrying a failure that does not clear")

	closed := make(chan struct{})
	go func() {
		defer close(closed)
		f.close()
	}()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("tearing down a forward blocked on its accept loop's backoff")
	}
}

// ------------------------------------------------------------ the listing

// The manager tears down a whole sandbox's forwards together, which is what
// fleet_remove needs: a forward whose sandbox has been deregistered points at
// a channel this server has closed.
func TestForwardManager_StopForSandboxClosesOnlyThatSandboxesForwards(t *testing.T) {
	m := newForwardManager(slog.New(slog.DiscardHandler))

	keep := listeningForward(t, forwardKey{sandbox: "gpu-01", remotePort: 3000})
	drop1 := listeningForward(t, forwardKey{sandbox: "build-box", remotePort: 3000})
	drop2 := listeningForward(t, forwardKey{sandbox: "build-box", remoteHost: "db.internal", remotePort: 5432})
	for _, f := range []*activeForward{keep, drop1, drop2} {
		require.NoError(t, m.add(f))
	}

	closed := m.stopForSandbox("build-box")
	require.Len(t, closed, 2)
	assert.Contains(t, closed, drop1.localAddr)
	assert.Contains(t, closed, drop2.localAddr)

	remaining := m.list()
	require.Len(t, remaining, 1, "the other sandbox's forward must survive")
	assert.Equal(t, "gpu-01", remaining[0].Sandbox)

	// The ports are genuinely released, not merely delisted.
	for _, address := range closed {
		_, port, err := net.SplitHostPort(address)
		require.NoError(t, err)
		lis, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", port))
		require.NoErrorf(t, err, "port %s was not released", port)
		require.NoError(t, lis.Close())
	}

	require.NoError(t, m.Close())
}

// listeningForward builds an activeForward on a real loopback listener, with no
// accept loop behind it: stopForSandbox is being tested, not the pumps.
func listeningForward(t *testing.T, key forwardKey) *activeForward {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr, ok := lis.Addr().(*net.TCPAddr)
	require.True(t, ok)
	t.Cleanup(func() { _ = lis.Close() })

	_, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &activeForward{
		key:       key,
		localAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(addr.Port)),
		localPort: addr.Port,
		createdAt: time.Now(),
		listener:  lis,
		cancel:    cancel,
	}
}
