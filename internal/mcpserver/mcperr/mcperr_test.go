package mcperr_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/axelmierczuk/sandboxd-mcp/internal/mcpserver/mcperr"
)

func TestMap_NilPassesThrough(t *testing.T) {
	assert.NoError(t, mcperr.Call{Sandbox: "build-box"}.Map(nil))
}

// TestMap_CodesBecomeReadableMessages walks the status codes issue #19 names,
// checking each says the thing that lets a model or an operator act.
func TestMap_CodesBecomeReadableMessages(t *testing.T) {
	call := mcperr.Call{
		Sandbox: "build-box",
		Address: "build-box.internal:8722",
		Subject: "path /srv/app/main.go",
		Timeout: 30 * time.Second,
		Limit:   "timeout_seconds",
	}

	for _, tc := range []struct {
		name     string
		err      error
		contains []string
		absent   []string
	}{
		{
			name:     "unavailable names the sandbox and its address",
			err:      status.Error(codes.Unavailable, "connection refused"),
			contains: []string{"build-box", "build-box.internal:8722", "unreachable", "connection refused"},
		},
		{
			name:     "permission denied carries the policy reason",
			err:      status.Error(codes.PermissionDenied, "path escapes allowed roots"),
			contains: []string{"build-box", "escapes allowed roots", "/srv/app/main.go"},
		},
		{
			name:     "not found names the subject",
			err:      status.Error(codes.NotFound, "no such file or directory"),
			contains: []string{"not found", "/srv/app/main.go", "build-box"},
		},
		{
			name:     "deadline exceeded names the limit that was hit",
			err:      status.Error(codes.DeadlineExceeded, "context deadline exceeded"),
			contains: []string{"build-box", "timed out", "30s", "timeout_seconds"},
		},
		{
			name:     "unauthenticated points at the certificate, not the request",
			err:      status.Error(codes.Unauthenticated, "bad certificate"),
			contains: []string{"build-box", "certificate", "sandboxctl"},
		},
		{
			name:     "resource exhausted explains the size limit",
			err:      status.Error(codes.ResourceExhausted, "grpc: received message larger than max"),
			contains: []string{"build-box", "size limit"},
		},
		{
			name:     "invalid argument reports what the agent objected to",
			err:      status.Error(codes.InvalidArgument, "argv must not be empty"),
			contains: []string{"build-box", "argv must not be empty"},
		},
		{
			name:     "an unclassified code still carries its message",
			err:      status.Error(codes.Internal, "supervisor panicked"),
			contains: []string{"build-box", "supervisor panicked"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := call.Map(tc.err)
			require.Error(t, err)
			for _, want := range tc.contains {
				assert.Contains(t, err.Error(), want)
			}
			assertNoLeakage(t, err.Error())
		})
	}
}

// TestMap_NeverLeaksGoOrGRPCInternals. Everything mapped here is going
// straight into a model's context, where "rpc error: code = Unavailable desc
// =" is noise it has to read past and "*status.Error" is noise it might try
// to act on.
func TestMap_NeverLeaksGoOrGRPCInternals(t *testing.T) {
	call := mcperr.Call{Sandbox: "build-box", Address: "build-box.internal:8722"}

	for _, err := range []error{
		status.Error(codes.Unavailable, "connection refused"),
		// A status that reached the mapper already wrapped, which is what
		// happens when an intermediate layer added context with %w.
		errors.New("dial: " + status.Error(codes.Unavailable, "connection refused").Error()),
		errors.New("plain failure with no status at all"),
	} {
		assertNoLeakage(t, call.Map(err).Error())
	}
}

func assertNoLeakage(t *testing.T, msg string) {
	t.Helper()
	for _, forbidden := range []string{"rpc error: code =", "desc =", "*status.", "*errors.", "%!"} {
		assert.NotContainsf(t, msg, forbidden, "message leaks an implementation detail: %q", msg)
	}
}

// TestMap_DegradesWhenContextIsMissing: the mapper is called from nineteen
// tools, and most calls will not have a subject or a limit to name.
func TestMap_DegradesWhenContextIsMissing(t *testing.T) {
	err := mcperr.Map("build-box", "", status.Error(codes.Unavailable, "connection refused"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build-box")
	assert.Contains(t, err.Error(), "its registered address")

	err = mcperr.Call{Sandbox: "build-box"}.Map(status.Error(codes.DeadlineExceeded, "deadline"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
	assert.NotContains(t, err.Error(), "()", "an absent limit must not leave empty parentheses")

	err = mcperr.Call{Sandbox: "build-box"}.Map(status.Error(codes.NotFound, "missing"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing")
}

// TestMap_MessagesStayShortEnoughToRead. These are read by a model on every
// failure; a paragraph per error is a paragraph per retry.
func TestMap_MessagesStayShortEnoughToRead(t *testing.T) {
	call := mcperr.Call{Sandbox: "build-box", Address: "build-box.internal:8722", Subject: "path /a/b"}
	for _, code := range []codes.Code{
		codes.Unavailable, codes.PermissionDenied, codes.NotFound,
		codes.DeadlineExceeded, codes.Unauthenticated, codes.Internal,
	} {
		msg := call.Map(status.Error(code, "the agent said something")).Error()
		assert.Lessf(t, len(msg), 300, "%s message is %d bytes: %q", code, len(msg), msg)
		assert.Equalf(t, 0, strings.Count(msg, "\n"), "%s message spans lines", code)
	}
}
