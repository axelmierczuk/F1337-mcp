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
		{codes.PermissionDenied, client.ErrCertificateRejected},
		{codes.ResourceExhausted, client.ErrMessageTooLarge},
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
