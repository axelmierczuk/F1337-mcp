package shell

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/security/policy"
)

// TestSession_IsRecordedWithoutItsContents is the test this feature exists to
// have.
//
// A shell session carries passwords, tokens, and whatever the operator pastes
// into it. An audit log that captured any of it would be a credential store
// nobody meant to build, on the least protected host in the fleet. The package
// is shaped so that the audit path cannot see a byte of a session — see
// sessionAudit — and this asserts the property rather than the shape, in both
// directions at once:
//
//   - typedSecret exists only as bytes the client sent. It is in no argument,
//     no environment entry, and nothing the agent wrote down before it arrived.
//   - printedSecret exists only as bytes the session produced. The helper echoes
//     what it was typed, so it appears on the terminal and nowhere else.
//
// Both are checked against the audit log and against the daemon's own log,
// because a service that kept its record clean and then debug-logged the buffer
// would have leaked the same secret to the same disk.
func TestSession_IsRecordedWithoutItsContents(t *testing.T) {
	requirePTY(t)

	const (
		typedSecret   = "hunter2-typed-into-the-session"
		printedSecret = "read[hunter2-typed-into-the-session]"
	)

	logs := &syncBuffer{}
	svc := newService(t, options{logs: logs})
	client := serve(t, svc)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sess, err := openSession(ctx, t, client, openOptions("cat"))
	require.NoError(t, err)

	require.NoError(t, sess.typed(typedSecret+"\n"))
	// Waited for, not assumed: if the secret never reached the session, the
	// assertions below would hold for a session that carried nothing and this
	// test would prove nothing at all.
	sess.awaitOutput(printedSecret)

	require.NoError(t, sess.typed("quit\n"))
	require.NotNil(t, sess.awaitEnd())

	rec := onlyRecord(t, svc)
	assert.Equal(t, "sandboxd.v1.ShellService/Shell", rec.RPC)
	assert.Equal(t, policy.OutcomeOK, rec.Outcome)
	assert.Equal(t, "test-box", rec.Sandbox, "a record that does not name its host cannot be acted on once it is shipped off-box")
	assert.False(t, rec.Time.IsZero(), "the record has to say when the session started")
	assert.Positive(t, rec.DurationMS, "the record has to say how long the session ran; start plus duration is the end")
	require.NotNil(t, rec.ExitCode)

	logged := auditFile(t, svc)
	assert.NotContains(t, logged, typedSecret, "the audit log captured what the operator typed")
	assert.NotContains(t, logged, printedSecret, "the audit log captured what the session printed")

	daemonLog := logs.String()
	assert.NotContains(t, daemonLog, typedSecret, "the daemon's own log captured what the operator typed")
	assert.NotContains(t, daemonLog, printedSecret, "the daemon's own log captured what the session printed")
}

// TestSession_RecordsThePrincipalTheDaemonAuthenticated checks the field an
// investigation starts from.
//
// The bufconn connection here carries no client certificate, so the principal
// is empty — which is the honest outcome and is asserted as such. What matters
// is that the value comes from the authenticated context rather than from
// anything the caller sent; the end-to-end suite asserts the populated case
// against a real mTLS handshake.
func TestSession_RecordsThePrincipalTheDaemonAuthenticated(t *testing.T) {
	requirePTY(t)

	svc := newService(t, options{})
	client := serve(t, svc)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sess, err := openSession(ctx, t, client, openOptions("exit", "0"))
	require.NoError(t, err)
	require.NotNil(t, sess.awaitEnd())

	rec := onlyRecord(t, svc)
	assert.Empty(t, rec.Principal, "an unauthenticated bufconn peer has no principal to record, and inventing one would be worse than an empty field")
	assert.NotEmpty(t, rec.Argv, "the command a session ran is what an operator searches the log for")
	assert.NotEmpty(t, rec.Path)
	assert.NotEmpty(t, rec.WorkingDir)
}

// TestSession_MalformedEnvironmentIsRefusedWithoutRecordingIt covers the one
// place a caller's environment could reach the record.
//
// Record's contract is that no environment value ever lands in it, and an error
// string is a field too: quoting the offending entry back into the record would
// write down a value on every request that malformed one. The caller is told
// what it sent — it sent it — and the record says only that something was
// malformed.
func TestSession_MalformedEnvironmentIsRefusedWithoutRecordingIt(t *testing.T) {
	const secret = "AWS_SECRET_ACCESS_KEY-with-no-equals-sign"

	svc := newService(t, options{})
	client := serve(t, svc)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	open := openOptions("exit", "0")
	open.Env = append(open.Env, secret)
	_, err := openSession(ctx, t, client, open)
	require.Error(t, err)
	assert.Contains(t, err.Error(), secret, "the caller has to be told which entry it malformed; it sent it")

	rec := onlyRecord(t, svc)
	assert.Equal(t, policy.OutcomeError, rec.Outcome)
	assert.NotContains(t, auditFile(t, svc), secret, "the audit log wrote down an environment entry")
}

// TestSession_AuditRequiredWithholdsTheResult pins the setting an operator
// chooses when the agent must not act unrecorded.
//
// It cannot refuse before the fact — by the time the record is written the
// session has already happened — so what it withholds is the clean ending. That
// is the honest report: the agent could not record what it did.
func TestSession_AuditRequiredWithholdsTheResult(t *testing.T) {
	requirePTY(t)

	svc := newService(t, options{audit: func(cfg *policy.AuditConfig) {
		// A path inside a file rather than a directory: nothing can be created
		// there, on any platform, and the failure is the daemon's to report.
		cfg.Required = true
		cfg.Path = filepathInsideAFile(t)
	}})
	client := serve(t, svc)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sess, err := openSession(ctx, t, client, openOptions("exit", "0"))
	require.NoError(t, err)

	sess.awaitEnd()
	sess.mu.Lock()
	streamErr := sess.streamErr
	sess.mu.Unlock()

	require.Error(t, streamErr)
	assert.Contains(t, streamErr.Error(), "audit.required")
}

// filepathInsideAFile returns a path whose parent is a regular file, so opening
// it must fail on every platform.
func filepathInsideAFile(t *testing.T) string {
	t.Helper()

	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	return filepath.Join(blocker, "audit.jsonl")
}
