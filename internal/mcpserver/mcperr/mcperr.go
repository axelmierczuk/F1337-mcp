// Package mcperr turns the errors a sandbox agent returns into messages a
// model can act on.
//
// The translation lives here, once, rather than in each tool handler.
// Nineteen handlers each inventing their own phrasing for "sandbox
// unreachable" is nineteen chances to leak a Go type name, a bare gRPC
// status, or nothing useful at all into the model's context — and the model
// cannot recover from an error it cannot read.
//
// It builds on internal/client's MapError rather than duplicating it:
// MapError decides *what kind* of failure this is, and this package decides
// what to say about it. The split matters because MapError's message is aimed
// at a Go caller (it wraps the raw status for errors.Is) while this one is
// aimed at a model, which has no use for "rpc error: code = Unavailable desc
// = ...".
package mcperr

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/axelmierczuk/fleet-mcp/internal/client"
)

// Call describes the call an error came out of, so the mapped message can
// name the things the model needs in order to fix the problem: which host,
// at which address, about which path or process, under which limit.
//
// Only Sandbox is required. The rest sharpen the message when the failure
// mode can use them — Subject for NotFound, Timeout and Limit for
// DeadlineExceeded — and are ignored otherwise.
type Call struct {
	// Sandbox is the resolved sandbox name the call was made against.
	Sandbox string
	// Address is the sandbox's host:port, named when it could not be reached
	// so the operator knows what to check.
	Address string
	// Subject is what the call was about, already labelled: "path
	// /srv/app/main.go", "process web-dev". It is what a NotFound is
	// reported against.
	Subject string
	// Timeout is the deadline the caller applied, if any.
	Timeout time.Duration
	// Limit names where Timeout came from, e.g. "timeout_seconds". A model
	// that is told which knob it turned can turn it again; one told only
	// "deadline exceeded" cannot.
	Limit string
}

// Map translates err into a tool-facing error, or returns nil if err is nil.
//
// The result is always returned to the model as a tool error (IsError), never
// as a protocol error: a failed command is a successful tool call reporting
// failure, and the model needs the report to act on it.
func (c Call) Map(err error) error {
	if err == nil {
		return nil
	}

	// MapError classifies; the phrasing below is ours.
	switch mapped := client.MapError(err); {
	case errors.Is(mapped, client.ErrUnreachable):
		return fmt.Errorf("sandbox %s is unreachable at %s: %s. Check the host is powered on and fleet-agent is running; fleet_list shows current health",
			c.Sandbox, c.addressOrUnknown(), message(err))

	case errors.Is(mapped, client.ErrCertificateRejected):
		return fmt.Errorf("sandbox %s rejected this client's certificate: %s. The control certificate is missing, expired, or issued by a different fleet CA; re-issue it with fleetctl",
			c.Sandbox, message(err))

	case errors.Is(mapped, client.ErrPermissionDenied):
		return fmt.Errorf("sandbox %s refused the operation: %s", c.Sandbox, c.withSubject(message(err)))

	case errors.Is(mapped, client.ErrDeadlineExceeded):
		return fmt.Errorf("call to sandbox %s timed out%s", c.Sandbox, c.limitSuffix())

	case errors.Is(mapped, client.ErrMessageTooLarge):
		return fmt.Errorf("the response from sandbox %s exceeds the configured message size limit: %s. Ask for less at a time — a line range, a tighter pattern, a lower max_output_bytes",
			c.Sandbox, message(err))
	}

	switch status.Code(err) {
	case codes.NotFound:
		return fmt.Errorf("not found on sandbox %s: %s", c.Sandbox, c.withSubject(message(err)))
	case codes.Canceled:
		return fmt.Errorf("the call to sandbox %s was cancelled", c.Sandbox)
	case codes.InvalidArgument, codes.FailedPrecondition, codes.AlreadyExists, codes.OutOfRange:
		return fmt.Errorf("sandbox %s rejected the request: %s", c.Sandbox, c.withSubject(message(err)))
	}

	return fmt.Errorf("sandbox %s: %s", c.Sandbox, message(err))
}

// Map is the shorthand for a failure that needs nothing beyond the sandbox
// it happened on.
func Map(sandbox, address string, err error) error {
	return Call{Sandbox: sandbox, Address: address}.Map(err)
}

func (c Call) addressOrUnknown() string {
	if c.Address == "" {
		return "its registered address"
	}
	return c.Address
}

// withSubject prefixes the agent's message with what the call was about,
// because "permission denied" alone tells a model nothing it can correct.
func (c Call) withSubject(msg string) string {
	if c.Subject == "" {
		return msg
	}
	if msg == "" {
		return c.Subject
	}
	return c.Subject + ": " + msg
}

// limitSuffix names the deadline that expired and the argument it came from,
// so the model can raise the right one instead of retrying the same call.
func (c Call) limitSuffix() string {
	switch {
	case c.Timeout > 0 && c.Limit != "":
		return fmt.Sprintf(" after %s (%s). Raise %s or narrow the work", c.Timeout, c.Limit, c.Limit)
	case c.Timeout > 0:
		return fmt.Sprintf(" after %s", c.Timeout)
	case c.Limit != "":
		return fmt.Sprintf(" (%s)", c.Limit)
	default:
		return ""
	}
}

// Message returns just the readable half of an error, with no sentence built
// around it and no "rpc error: code = … desc =" envelope left in it.
//
// [Call.Map] is for a failure the model has to act on, and phrases a whole
// sentence naming the host and what to check. A fleet_list detail column is
// the other case: the row it sits in already carries the name, the address and
// the health, so repeating them there costs tokens on every fleet check and
// tells the reader nothing new. Both go through this package so neither path
// can leak a gRPC or Go internal into the model's context.
//
// It returns the empty string for a nil error.
func Message(err error) string {
	if err == nil {
		return ""
	}
	return message(err)
}

// message extracts the human-readable half of an error.
//
// For a gRPC error that is the status message, which deliberately excludes
// the "rpc error: code = X desc =" envelope the wire error's Error() carries.
// For anything else it is the error text with any such envelope stripped, so
// a status that reached us wrapped in something else still reads cleanly.
func message(err error) string {
	if st, ok := status.FromError(err); ok {
		if msg := strings.TrimSpace(st.Message()); msg != "" {
			return msg
		}
		return st.Code().String()
	}
	return strings.TrimSpace(stripStatusEnvelope(err.Error()))
}

// stripStatusEnvelope removes gRPC's "rpc error: code = X desc = " prefix
// wherever it appears in a message.
func stripStatusEnvelope(msg string) string {
	const marker = "rpc error: code = "
	i := strings.Index(msg, marker)
	if i < 0 {
		return msg
	}
	rest := msg[i+len(marker):]
	const desc = " desc = "
	j := strings.Index(rest, desc)
	if j < 0 {
		return msg[:i] + rest
	}
	return msg[:i] + rest[j+len(desc):]
}
