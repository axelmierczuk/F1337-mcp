// Package tunnel carries one local TCP connection over one
// sandboxd.v1.ForwardService stream.
//
// It is the client half of the forward path, and there is exactly one of it on
// purpose. fleet_forward, fleet_socks and `fleetctl socks` all move bytes the
// same way — accept locally, open a stream, pump both directions, half-close
// each independently — and the differences between them are all in how the
// destination is chosen, not in how it is carried.
//
// A second byte-pump would be a second place to leak a goroutine, a descriptor
// and a gRPC stream per connection. This repository has already shipped two
// connection-lifetime leaks on this exact code and fixed both here; a copy of
// it would have had to be found and fixed twice more, on a path where the
// symptom is an MCP server that is slowly using a gigabyte rather than
// anything that looks like a bug. So [Carry] is the only implementation, and
// the comments below record what each half of it is for.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
)

// CopyBuffer is the local-to-sandbox pump buffer.
const CopyBuffer = 32 * 1024

// Target is where on the sandbox's network a connection is going.
type Target struct {
	// Host is the host to connect to from the sandbox. Empty means the
	// sandbox's own loopback.
	Host string
	// Port is the port on that host.
	Port int
	// SOCKS marks the connection as one a SOCKS proxy asked for, which selects
	// which of the agent's two policies applies to it. See ForwardOpen.socks in
	// forward.proto: it can only ever make the policy stricter.
	SOCKS bool
}

// Label renders a target for an error message or a listing.
func (t Target) Label() string {
	host := t.Host
	if host == "" {
		host = "localhost"
	}
	return net.JoinHostPort(host, strconv.Itoa(t.Port))
}

// FailureKind classifies a connection that was never established, so a caller
// that has to answer in a protocol of its own — a SOCKS reply code — can say
// which of them happened without parsing a sentence.
type FailureKind int

const (
	// FailureUnknown is a failure with no more specific classification.
	FailureUnknown FailureKind = iota
	// FailureDenied is the agent's configuration refusing the target.
	FailureDenied
	// FailureUnreachable is a name that did not resolve on the agent, or a
	// network with no route to it.
	FailureUnreachable
	// FailureRefused is a target that resolved and routed but did not answer.
	FailureRefused
	// FailureTransport is the agent itself being unreachable, as distinct from
	// anything about the target.
	FailureTransport
)

// OpenError reports a connection that never opened.
//
// It is separate from the errors a pump returns because the two mean opposite
// things to a caller: an open that failed carries nothing and can be reported
// as a status, and a pump that failed happened after bytes were already
// flowing.
type OpenError struct {
	// Kind is what went wrong, for a caller that has to map it onto a code.
	Kind FailureKind
	// Message is the agent's own account of the failure, which is more useful
	// than anything this side could compose: it is the only half that knows
	// whether the port was closed or the name was wrong.
	Message string

	err error
}

func (e *OpenError) Error() string { return e.Message }
func (e *OpenError) Unwrap() error { return e.err }

// Denied reports a refusal by the agent's configuration.
func (e *OpenError) Denied() bool { return e.Kind == FailureDenied }

// Carry runs one accepted connection over one Forward stream, and returns when
// both directions have finished.
//
// The caller owns conn and must close it. Carry deliberately does not: a caller
// speaking a protocol of its own has something left to say on a connection
// whose open failed — a SOCKS reply code — and a socket this function had
// already closed could not carry it.
//
// onOpen, when not nil, is called once the sandbox-side connection is
// established and before any bytes move in either direction. It is the seam a
// protocol with its own handshake needs: a SOCKS client sends nothing until its
// reply arrives, so the reply has to be written after the far side is connected
// — which is the only moment that knows whether to report success — and before
// the pumps start, which is the only moment nothing is competing for the
// socket. An error from it ends the connection without carrying anything.
func Carry(ctx context.Context, client sandboxdv1.ForwardServiceClient, conn net.Conn, target Target, onOpen func() error) error {
	// Per-connection cancellation, so a stream whose pumps have finished
	// releases its gRPC resources immediately rather than at teardown of
	// whatever owns the listener.
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Cancelling the context has to close the socket, not merely the stream.
	// A pump parked in conn.Read is not waiting on a context, so without this a
	// teardown would block forever joining a goroutine that is blocked on a
	// client which has no reason to say anything — and the tool call that asked
	// for the teardown would never return.
	stopOnCancel := context.AfterFunc(streamCtx, func() { _ = conn.Close() })
	defer stopOnCancel()

	stream, err := client.Forward(streamCtx)
	if err != nil {
		return openFailure(err, "opening a forward stream")
	}
	if err := stream.Send(&sandboxdv1.ForwardRequest{
		Event: &sandboxdv1.ForwardRequest_Open{Open: &sandboxdv1.ForwardOpen{
			RemotePort: uint32(target.Port), //nolint:gosec // range-checked before a target is built
			RemoteHost: target.Host,
			Socks:      target.SOCKS,
		}},
	}); err != nil {
		return openFailure(err, "opening a connection to "+target.Label())
	}

	first, err := stream.Recv()
	if err != nil {
		return openFailure(err, "connecting to "+target.Label())
	}
	opened := first.GetOpened()
	if opened == nil {
		return &OpenError{Kind: FailureUnknown, Message: "the agent answered a forward open with an unexpected message"}
	}
	if !opened.GetSuccess() {
		// Reported, and the local connection deliberately left open: the
		// caller owns it, and one speaking a protocol of its own has something
		// left to say on it. A destination the agent refused is exactly where
		// the SOCKS proxy writes 0x02 onto this socket, and closing it here
		// would give its client a reset instead — which is the defect this
		// ownership rule was moved out of fleet_forward to prevent.
		return &OpenError{Kind: classifyDialFailure(opened.GetError()), Message: opened.GetError()}
	}

	if onOpen != nil {
		if err := onOpen(); err != nil {
			// Before either pump exists, so there is nothing to join and
			// nothing in flight; the caller's own close is the whole teardown.
			return err
		}
	}

	var (
		wg      sync.WaitGroup
		sendErr error
		recvErr error
	)

	// Local to sandbox. The local client closing its write side ends this
	// direction and only this direction: the response still has to come back.
	//
	// A local socket that *failed* is a different event, and it is why this
	// cancels where a clean half-close must not. localToStream reports EOF —
	// which is both a half-close and this side's own teardown closing the
	// socket underneath it — as no error at all, so a non-nil error here means
	// the local client is gone rather than merely finished: killed mid-request,
	// or reset. There is nobody left to deliver a response to, and without the
	// cancel the receiving pump stays parked in stream.Recv until the
	// sandbox-side server happens to close — holding one goroutine, one
	// descriptor, one gRPC stream and one slot against the agent's
	// forward.max_connections. A server that neither writes nor closes when its
	// peer half-closes never gets there at all, and an aborted request is
	// ordinary traffic on a proxy that stays open for hours.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if sendErr = localToStream(conn, stream); sendErr != nil {
			cancel()
		}
	}()

	// Sandbox to local. A close *event* does not stop the other direction: a
	// server that closed its write half has not necessarily stopped reading,
	// and a client still sending must still be delivered.
	//
	// The stream *ending* is different, and cancelling on it is what stops this
	// connection outliving its own transport. Once this pump returns there is
	// no stream left — the agent's handler has returned, so it has already
	// consumed everything the caller sent, or the RPC failed outright — and
	// nothing the local client says afterwards can reach the sandbox. Without
	// the cancel, the other pump stays parked in conn.Read on a client with no
	// reason to speak: one goroutine, one descriptor and one gRPC stream held
	// until the whole listener is torn down, per connection, on exactly the
	// long-lived proxy where they accumulate. An agent restart under an idle
	// keep-alive connection is all it takes.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		recvErr = streamToLocal(stream, conn)
	}()

	wg.Wait()
	// The local socket failing is a cause rather than a consequence, so it is
	// the one to report: this side's own teardown closes that socket with
	// net.ErrClosed, which localToStream reports as no error, so a non-nil
	// sendErr is always the client's own failure and never a knock-on of the
	// stream ending. It is what a reader of the listener's last_error needs —
	// "connection reset by peer" rather than "the forward stream ended:
	// context canceled", which is this function describing its own cleanup.
	if sendErr != nil {
		return sendErr
	}
	return recvErr
}

// openFailure wraps a gRPC failure from the opening exchange, classified.
func openFailure(err error, doing string) error {
	kind := FailureTransport
	switch status.Code(err) {
	case codes.PermissionDenied, codes.FailedPrecondition:
		// The agent answered, and the answer was no. That is a fact about the
		// configuration rather than about reachability, and reporting it as a
		// transport failure would send an operator to look at the network.
		kind = FailureDenied
	case codes.InvalidArgument:
		kind = FailureUnknown
		// A name the agent could not resolve arrives as InvalidArgument, and it
		// is the same event a dial that failed to resolve reports through
		// ForwardOpened.error — which classifyDialFailure already reads as
		// unreachable. Which of the two paths a given name takes is decided by
		// something a client cannot see: a name *on* the allow list is dialed
		// by name and fails in the dialer, and a name that is not is resolved
		// first and fails here. Left alone, the same unresolvable name reaches
		// a SOCKS client as "host unreachable" or as "general server failure"
		// depending on the agent's allow list, which is a client sent to debug
		// the wrong layer for a reason nothing in front of it explains.
		if looksUnresolvable(status.Convert(err).Message()) {
			kind = FailureUnreachable
		}
	}
	return &OpenError{
		Kind:    kind,
		Message: fmt.Sprintf("%s: %s", doing, status.Convert(err).Message()),
		err:     err,
	}
}

// classifyDialFailure reads the agent's account of a dial that failed.
//
// The agent already phrased the failure for a human, and re-deriving the cause
// from a code the proto does not carry is not an option — so this matches on
// the words the agent uses. It is a hint for a reply code, never a decision
// with consequences: every branch below produces a failure, and the caller's
// own message is the agent's sentence either way.
func classifyDialFailure(message string) FailureKind {
	if looksUnresolvable(message) {
		return FailureUnreachable
	}
	// Anything else is reported as a target that did not answer, which is what
	// it nearly always is and what a SOCKS client renders most usefully.
	return FailureRefused
}

// looksUnresolvable reads the agent's own sentence for a name that went
// nowhere.
//
// Shared by the two paths a resolution failure can take, so that the same event
// gets the same reply code whichever one it came back on. It is a hint, never a
// decision with consequences: both callers produce a failure either way.
func looksUnresolvable(message string) bool {
	for _, unreachable := range []string{
		"could not be resolved", "no such host", "resolved to no addresses", "unreachable",
	} {
		if strings.Contains(message, unreachable) {
			return true
		}
	}
	return false
}

// Sender is the send half of the client stream, narrowed so a test can drive
// it.
type Sender interface {
	Send(*sandboxdv1.ForwardRequest) error
	CloseSend() error
}

// localToStream copies local bytes onto the stream and half-closes at EOF.
func localToStream(conn net.Conn, stream Sender) error {
	buf := make([]byte, CopyBuffer)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if sendErr := stream.Send(&sandboxdv1.ForwardRequest{
				Event: &sandboxdv1.ForwardRequest_Data{Data: buf[:n]},
			}); sendErr != nil {
				// The stream is gone; the receiving pump reports why.
				return nil //nolint:nilerr // the other direction carries the real error
			}
		}
		if err != nil {
			// EOF here is the local client half-closing, which is an ordinary
			// and meaningful event: tell the far end, then stop sending.
			_ = stream.Send(&sandboxdv1.ForwardRequest{
				Event: &sandboxdv1.ForwardRequest_Close{Close: &sandboxdv1.ForwardClose{
					Reason: "the local client closed its write side",
				}},
			})
			_ = stream.CloseSend()
			if IsLocalClose(err) {
				return nil
			}
			return fmt.Errorf("reading from the local connection: %w", err)
		}
	}
}

// Receiver is the receive half of the client stream.
type Receiver interface {
	Recv() (*sandboxdv1.ForwardResponse, error)
}

// streamToLocal copies sandbox bytes onto the local connection.
func streamToLocal(stream Receiver, conn net.Conn) error {
	for {
		resp, err := stream.Recv()
		switch {
		case errors.Is(err, io.EOF):
			return CloseLocalWrite(conn)
		case err != nil:
			// Half-closing rather than closing outright: a client that is
			// still reading gets a clean EOF instead of a reset that looks like
			// a truncated response.
			_ = CloseLocalWrite(conn)
			return fmt.Errorf("the forward stream ended: %w", err)
		}

		if resp.GetClose() != nil {
			// The sandbox-side server closed its write side. The local client
			// may still be sending, so shut down only the write half here —
			// and then keep receiving.
			//
			// Returning here instead would end this pump, which ends Carry,
			// which cancels the stream. CloseSend does not wait for the agent
			// to have consumed what was already sent, so a cancel that lands
			// first drops the client's last bytes: the request is silently
			// truncated and the server never sees the end of it. The stream
			// ends on its own once the agent's handler returns, which is the
			// point at which there is genuinely nothing left in flight.
			_ = CloseLocalWrite(conn)
			continue
		}
		data := resp.GetData()
		if len(data) == 0 {
			continue
		}
		// Written straight through, never accumulated. A large response is a
		// stream of these, and a buffer that held one would hold the whole body
		// of every concurrent transfer at once.
		if _, err := conn.Write(data); err != nil {
			return nil //nolint:nilerr // the local client hung up; nothing left to report to it
		}
	}
}

// CloseLocalWrite shuts down only the write half where the platform offers it.
func CloseLocalWrite(conn net.Conn) error {
	if tcp, ok := conn.(*net.TCPConn); ok {
		if err := tcp.CloseWrite(); err != nil && !IsLocalClose(err) {
			return nil //nolint:nilerr // a connection already gone is not a failure of this direction
		}
		return nil
	}
	return conn.Close()
}

// IsLocalClose reports whether err is an ordinary end of a local connection.
func IsLocalClose(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)
}

// compile-time check that the generated client stream satisfies the narrowed
// interfaces above, so a regeneration that changes their shape fails here
// rather than at the first forwarded byte.
var (
	_ Sender   = (grpc.BidiStreamingClient[sandboxdv1.ForwardRequest, sandboxdv1.ForwardResponse])(nil)
	_ Receiver = (grpc.BidiStreamingClient[sandboxdv1.ForwardRequest, sandboxdv1.ForwardResponse])(nil)
)
