package socks

import (
	"context"
	"errors"
	"net"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/tunnel"
)

// The wiring between the protocol above and the transport under it, kept in its
// own file so socks.go stays a statement about SOCKS5 and nothing else.
//
// It is here rather than in internal/tunnel because the dependency has to point
// this way: the transport does not know what a SOCKS reply code is, and giving
// it an opinion about one would make every other caller of it — fleet_forward
// today, anything later — carry a protocol it does not speak.
//
// It is shared rather than written twice because `fleetctl socks` and
// fleet_socks want exactly the same thing from it. Two copies would be two
// places for the classification below to drift, and the symptom of drift is a
// `curl` that reports "connection refused" for a destination the operator never
// permitted.

// ForwardConnector carries proxied connections over a sandbox's
// ForwardService.
//
// Every connection is its own stream with its own destination, which is what a
// proxy is: unlike a port forward, the destination is chosen by the client, one
// connection at a time, and the agent decides about each one separately.
func ForwardConnector(client sandboxdv1.ForwardServiceClient) Connect {
	return func(ctx context.Context, conn net.Conn, dst Destination, accepted func() error) error {
		err := tunnel.Carry(ctx, client, conn, tunnel.Target{
			Host: dst.Host,
			Port: dst.Port,
			// The declaration the agent's policy is written in terms of. See
			// ForwardOpen.socks in forward.proto: it selects which of the two
			// gates applies, and setting it can only ever make the answer
			// stricter.
			SOCKS: true,
		}, accepted)
		return classify(err)
	}
}

// replyForOpenError maps a connection that never opened onto the reply code a
// SOCKS client renders.
//
// The distinction that matters is the first one. A destination refused by the
// agent's configuration is not a fact about the network, and a client shown
// "connection refused" for it sends its operator to check whether the service
// is up — which it is. 0x02 is the code for "your request was not allowed",
// and `curl` renders it as such.
func replyForOpenError(err *tunnel.OpenError) byte {
	switch err.Kind {
	case tunnel.FailureDenied:
		return ReplyNotAllowed
	case tunnel.FailureUnreachable:
		return ReplyHostUnreachable
	case tunnel.FailureRefused:
		return ReplyConnectionRefused
	case tunnel.FailureTransport, tunnel.FailureUnknown:
		return ReplyGeneralFailure
	default:
		return ReplyGeneralFailure
	}
}

// socksReplyError adapts a transport failure to [ReplyCoder].
type socksReplyError struct {
	error
	code byte
}

func (e socksReplyError) SOCKSReply() byte { return e.code }
func (e socksReplyError) Unwrap() error    { return e.error }

// classify wraps err so that [ReplyCode] can answer for it.
//
// Only a connection that never opened is classified. A failure after the reply
// was written keeps its general code and never reaches a client anyway: it has
// its answer already, and learns the rest from the connection ending.
func classify(err error) error {
	if err == nil {
		return nil
	}
	var openErr *tunnel.OpenError
	if errors.As(err, &openErr) {
		return socksReplyError{error: err, code: replyForOpenError(openErr)}
	}
	return err
}
