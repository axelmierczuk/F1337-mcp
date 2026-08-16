package client

import (
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Sandbox-level errors that MapError normalizes gRPC status codes into.
// Callers can test for these with errors.Is regardless of which RPC or
// which sandbox produced them.
var (
	// ErrUnreachable means the sandbox could not be reached at all:
	// powered off, network partitioned, or agent not running.
	ErrUnreachable = errors.New("client: sandbox unreachable")
	// ErrDeadlineExceeded means the call's context expired before the
	// sandbox responded.
	ErrDeadlineExceeded = errors.New("client: deadline exceeded")
	// ErrCertificateRejected means mTLS authentication failed: wrong CA,
	// wrong certificate profile, or expired leaf. It is about *who the
	// caller is*, and the fix is always a certificate.
	ErrCertificateRejected = errors.New("client: certificate rejected")
	// ErrPermissionDenied means the agent authenticated the caller and then
	// refused the operation: a path outside the allowed roots, a command the
	// policy forbids. It is about *what was asked for*, and the fix is never
	// a certificate — which is why it does not share ErrCertificateRejected.
	ErrPermissionDenied = errors.New("client: permission denied by sandbox policy")
	// ErrMessageTooLarge means the call exceeded the configured max message
	// size. See Config.MaxRecvMsgSize / MaxSendMsgSize.
	ErrMessageTooLarge = errors.New("client: message exceeds configured size limit")
)

// MapError translates a gRPC status error into a sandbox-level error,
// wrapping the original status message for context and preserving err via
// %w so errors.Is/As still finds the underlying status. Non-gRPC errors and
// nil pass through unchanged.
//
// This exists so every MCP tool handler that calls through Pool gets the
// same vocabulary of failures, defined once here rather than re-derived at
// each call site.
func MapError(err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return err
	}

	switch st.Code() {
	case codes.Unavailable:
		return fmt.Errorf("%w: %s: %w", ErrUnreachable, st.Message(), err)
	case codes.DeadlineExceeded:
		return fmt.Errorf("%w: %s: %w", ErrDeadlineExceeded, st.Message(), err)
	case codes.Unauthenticated:
		return fmt.Errorf("%w: %s: %w", ErrCertificateRejected, st.Message(), err)
	case codes.PermissionDenied:
		return fmt.Errorf("%w: %s: %w", ErrPermissionDenied, st.Message(), err)
	case codes.ResourceExhausted:
		return fmt.Errorf("%w: %s: %w", ErrMessageTooLarge, st.Message(), err)
	default:
		return err
	}
}
