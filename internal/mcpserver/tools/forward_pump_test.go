package tools

import (
	"context"
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

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

// The half-close contract, asserted on the pump rather than through a live
// forward.
//
// TestForward_ClientCanStillSendAfterTheRemoteHalfCloses in the mcpserver suite
// asserts the same property end to end, but it cannot fail reliably: the bug it
// is named for is a race between this pump ending and the other one's last
// Send being consumed, so on an unloaded machine the wrong implementation wins
// the race and the test passes. These drive streamToLocal directly, through the
// narrowed forwardReceiver the file already defines, so the invariant is pinned
// by something that fails every time.

// scriptedForward replays a fixed sequence of responses and then blocks until
// released, standing in for an agent handler that has not returned yet.
type scriptedForward struct {
	events   []*sandboxdv1.ForwardResponse
	next     int
	released chan struct{}
}

func (s *scriptedForward) Recv() (*sandboxdv1.ForwardResponse, error) {
	if s.next < len(s.events) {
		event := s.events[s.next]
		s.next++
		return event, nil
	}
	if s.released != nil {
		<-s.released
	}
	return nil, io.EOF
}

func forwardData(b string) *sandboxdv1.ForwardResponse {
	return &sandboxdv1.ForwardResponse{Event: &sandboxdv1.ForwardResponse_Data{Data: []byte(b)}}
}

func forwardCloseEvent() *sandboxdv1.ForwardResponse {
	return &sandboxdv1.ForwardResponse{
		Event: &sandboxdv1.ForwardResponse_Close{Close: &sandboxdv1.ForwardClose{Reason: "the sandbox-side connection closed"}},
	}
}

// tcpPair returns two ends of a real loopback connection. A net.Pipe would not
// do: closeLocalWrite half-closes a *net.TCPConn and closes anything else
// outright, and the difference is the whole subject here.
func tcpPair(t *testing.T) (client, server net.Conn) {
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

	client, err = net.DialTimeout("tcp", lis.Addr().String(), 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	got := <-done
	require.NoError(t, got.err)
	t.Cleanup(func() { _ = got.conn.Close() })
	return client, got.conn
}

// A ForwardClose is a half-close, and the pump that receives it must keep
// receiving.
//
// Ending here ends carry, which cancels the gRPC stream — and CloseSend does
// not wait for the agent to have consumed what the other pump already sent, so
// the client's last bytes are dropped and the request is silently truncated.
func TestStreamToLocal_KeepsReceivingAfterARemoteHalfClose(t *testing.T) {
	client, server := tcpPair(t)

	released := make(chan struct{})
	stream := &scriptedForward{
		events:   []*sandboxdv1.ForwardResponse{forwardData("greeting"), forwardCloseEvent()},
		released: released,
	}

	done := make(chan error, 1)
	go func() { done <- streamToLocal(stream, server) }()

	// Reading to EOF proves both that the data arrived and that the close was
	// processed: the write half of the local socket is shut and no more can
	// come. Anything the pump does after this it has already had the chance to
	// do.
	require.NoError(t, client.SetReadDeadline(time.Now().Add(20*time.Second)))
	got, err := io.ReadAll(client)
	require.NoError(t, err)
	require.Equal(t, "greeting", string(got), "the local client must see a clean EOF, not a reset")

	select {
	case err := <-done:
		t.Fatalf("streamToLocal returned at the sandbox-side half-close (%v); doing that cancels the stream and drops whatever the client sent after it", err)
	case <-time.After(250 * time.Millisecond):
	}

	// The agent's handler returns, which is the point at which there is
	// genuinely nothing left in flight.
	close(released)
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(20 * time.Second):
		t.Fatal("streamToLocal did not return once the stream ended")
	}
}

// And the end of the stream is what ends the pump, cleanly.
func TestStreamToLocal_EndsOnStreamEOF(t *testing.T) {
	client, server := tcpPair(t)

	stream := &scriptedForward{events: []*sandboxdv1.ForwardResponse{forwardData("body")}}

	done := make(chan error, 1)
	go func() { done <- streamToLocal(stream, server) }()

	require.NoError(t, client.SetReadDeadline(time.Now().Add(20*time.Second)))
	got, err := io.ReadAll(client)
	require.NoError(t, err)
	assert.Equal(t, "body", string(got))

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(20 * time.Second):
		t.Fatal("streamToLocal did not return at the end of the stream")
	}
}

// ------------------------------------------------------------- the stop call

// The instruction a forward hands back has to be the one that works. remote_host
// is part of the key, so a stop call that omits it looks up a different forward,
// finds nothing, and fails — costing a turn and reading as though the forward
// had closed itself.
func TestForwardKey_StopCallNamesTheHostThatIsPartOfTheKey(t *testing.T) {
	loopback := forwardKey{sandbox: "build-box", remotePort: 3000}
	assert.Equal(t, "sandbox_forward(remote_port=3000, stop=true)", loopback.stopCall())

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

// ------------------------------------------------------------ the listing

// The manager tears down a whole sandbox's forwards together, which is what
// sandbox_remove needs: a forward whose sandbox has been deregistered points at
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
