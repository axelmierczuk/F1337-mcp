package client_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/axelmierczuk/sandboxd-mcp/internal/client"
)

func TestMapError_Nil(t *testing.T) {
	assert.NoError(t, client.MapError(nil))
}

func TestMapError_NonGRPCError_PassesThrough(t *testing.T) {
	err := errors.New("boom")
	assert.Equal(t, err, client.MapError(err))
}

func TestMapError_MapsKnownCodes(t *testing.T) {
	cases := []struct {
		code codes.Code
		want error
	}{
		{codes.Unavailable, client.ErrUnreachable},
		{codes.DeadlineExceeded, client.ErrDeadlineExceeded},
		{codes.Unauthenticated, client.ErrCertificateRejected},
		{codes.PermissionDenied, client.ErrPermissionDenied},
		{codes.ResourceExhausted, client.ErrResourceExhausted},
	}
	for _, tc := range cases {
		t.Run(tc.code.String(), func(t *testing.T) {
			err := status.Error(tc.code, "detail")
			mapped := client.MapError(err)
			assert.ErrorIs(t, mapped, tc.want)
		})
	}
}

func TestMapError_UnmappedCode_ReturnedAsIs(t *testing.T) {
	err := status.Error(codes.NotFound, "detail")
	assert.Equal(t, err, client.MapError(err))
}

// A policy denial from the agent and a rejected client certificate arrive as
// different gRPC codes and must stay distinguishable: one is fixed by editing
// the sandbox's policy, the other by re-issuing a certificate, and an
// operator told the wrong one debugs the wrong system.
func TestMapError_PolicyDenialIsNotACertificateProblem(t *testing.T) {
	denied := client.MapError(status.Error(codes.PermissionDenied, "path /etc is outside the allowed roots"))
	assert.ErrorIs(t, denied, client.ErrPermissionDenied)
	assert.NotErrorIs(t, denied, client.ErrCertificateRejected)

	rejected := client.MapError(status.Error(codes.Unauthenticated, "bad certificate"))
	assert.ErrorIs(t, rejected, client.ErrCertificateRejected)
	assert.NotErrorIs(t, rejected, client.ErrPermissionDenied)
}

// ResourceExhausted is not one condition. gRPC raises it when a message
// exceeds the configured limit, and the agent raises it when a budget of its
// own runs out — the cap on concurrently supervised processes that
// docs/security.md commits to. Reporting the second as the first sends an
// operator to resize a message that was never too big.
func TestMapError_ResourceExhaustedIsNotAlwaysASizeLimit(t *testing.T) {
	tooBig := client.MapError(status.Error(codes.ResourceExhausted,
		"grpc: received message larger than max (5242880 vs. 4194304)"))
	assert.ErrorIs(t, tooBig, client.ErrMessageTooLarge)
	assert.NotErrorIs(t, tooBig, client.ErrResourceExhausted)

	atCap := client.MapError(status.Error(codes.ResourceExhausted,
		"sandbox is already supervising the maximum of 16 processes"))
	assert.ErrorIs(t, atCap, client.ErrResourceExhausted)
	assert.NotErrorIs(t, atCap, client.ErrMessageTooLarge,
		"a process-count cap is not fixed by reading less at a time")
}
