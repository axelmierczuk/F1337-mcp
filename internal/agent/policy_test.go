package agent_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/agent"
	"github.com/axelmierczuk/sandboxd-mcp/internal/security/policy"
)

// policyRecord is a minimal record for the tests that only care that the log
// accepted one.
func policyRecord() policy.Record {
	return policy.Record{
		Principal: "sandboxd-mcp",
		RPC:       "sandboxd.v1.ExecService/Exec",
		Outcome:   policy.OutcomeOK,
	}
}

// The command policy and the audit log are built once per daemon and handed to
// every service, rather than each service building its own.
//
// A cap enforced from per-service copies is not a cap on the agent — two
// services each allowing 32 concurrent processes is a host running 64 — and two
// audit instances over one file would rotate it out from under each other, so
// records written by one would land in a segment the other had already moved
// aside.
func TestServer_DepsCarryOnePolicyAndOneAuditLog(t *testing.T) {
	fleet := newTestFleet(t)
	cfg := fleet.agentConfig(t)
	cfg.Exec.DenyCommands = []string{"rm"}
	cfg.Exec.MaxOutputBytes = 4096
	cfg.Process.MaxConcurrent = 3
	cfg.Audit.Enabled = true
	cfg.Audit.Path = filepath.Join(t.TempDir(), "audit.jsonl")

	h := start(t, cfg, []agent.Registration{registration("host", newCountingService())})
	deps := h.server.Deps()

	require.NotNil(t, deps.Policy)
	require.NotNil(t, deps.Audit)

	allow, deny := deps.Policy.Rules()
	assert.Empty(t, allow)
	assert.Equal(t, []string{"rm"}, deny)
	assert.EqualValues(t, 4096, deps.Policy.Caps().MaxOutputBytes)
	assert.Equal(t, 3, deps.Policy.Caps().MaxConcurrent,
		"the supervisor's concurrency cap is the agent's, and exec takes its slots from it")
	assert.Equal(t, cfg.Exec.DefaultTimeout.Duration(), deps.Policy.Caps().DefaultTimeout)

	assert.True(t, deps.Audit.Enabled())
	assert.Equal(t, cfg.Audit.Path, deps.Audit.Path())
}

// A rule the daemon could not enforce as written stops it starting.
//
// An operator who wrote a deny list believes it is in force. A daemon that came
// up healthy having silently dropped the entry would be running exactly the
// commands they thought they had refused, and nothing would say so.
func TestServer_MalformedCommandRuleAbortsStartup(t *testing.T) {
	fleet := newTestFleet(t)
	cfg := fleet.agentConfig(t)
	cfg.Exec.DenyCommands = []string{"rm[a-"}

	_, err := agent.New(agent.Options{
		Config:   cfg,
		Log:      discardLogger(),
		Listener: newBufconn(t),
		Services: []agent.Registration{registration("host", newCountingService())},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deny_commands")
}

// An audit log that cannot be written is loud, and it is not fatal.
//
// The record is forensic: it prevents nothing, so refusing to serve without it
// would trade a gap in the record for an outage. When audit.required is set,
// every affected RPC fails on its own — the same refusal, delivered where the
// caller can see it.
func TestServer_UnwritableAuditLogIsLoudButNotFatal(t *testing.T) {
	fleet := newTestFleet(t)

	blocked := filepath.Join(t.TempDir(), "a-file")
	require.NoError(t, os.WriteFile(blocked, []byte("not a directory"), 0o600))

	cfg := fleet.agentConfig(t)
	cfg.Audit.Enabled = true
	cfg.Audit.Required = true
	cfg.Audit.Path = filepath.Join(blocked, "audit.jsonl")

	log, logs := capturedLogger()
	h := start(t, cfg, []agent.Registration{registration("host", newCountingService())},
		func(o *agent.Options) { o.Log = log })

	assert.True(t, h.server.Deps().Audit.Required())
	assert.Contains(t, logs.String(), "AUDIT LOG IS NOT WRITABLE")
	assert.Contains(t, logs.String(), "audit.required")
}

// An agent with the audit log turned off says so at every start, for the same
// reason it says so when the path jail is off: a record nobody is keeping is a
// thing an operator will otherwise assume they have.
func TestServer_DisabledAuditLogWarns(t *testing.T) {
	fleet := newTestFleet(t)
	cfg := fleet.agentConfig(t)
	cfg.Audit.Enabled = false

	log, logs := capturedLogger()
	h := start(t, cfg, []agent.Registration{registration("host", newCountingService())},
		func(o *agent.Options) { o.Log = log })

	assert.False(t, h.server.Deps().Audit.Enabled())
	assert.Contains(t, logs.String(), "AUDIT LOG IS OFF")
	assert.Contains(t, logs.String(), "level=WARN")
}

// The audit log is released on shutdown, after every Shutdowner has had its
// chance to write a final record.
func TestServer_ShutdownClosesTheAuditLog(t *testing.T) {
	fleet := newTestFleet(t)
	cfg := fleet.agentConfig(t)
	cfg.Audit.Enabled = true
	cfg.Audit.Path = filepath.Join(t.TempDir(), "audit.jsonl")

	h := start(t, cfg, []agent.Registration{registration("host", newCountingService())})
	auditLog := h.server.Deps().Audit
	require.NoError(t, h.stop(t))

	// Closing is idempotent and a later write reopens the file, so the
	// observable property is that the daemon exits without an error and the
	// log is still usable — not that the handle is unusable afterwards.
	require.NoError(t, auditLog.Close())
	require.NoError(t, auditLog.Write(policyRecord()))
	require.NoError(t, auditLog.Close())

	data, err := os.ReadFile(cfg.Audit.Path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "sandboxd.v1.ExecService/Exec")
}

// Stop is the impatient path, and it releases the audit log's handle before it
// returns.
//
// It skips the shutdown participants on purpose, but the log is an OS handle
// rather than a participant's state: left open it makes the file undeletable on
// Windows for the life of the process, including by the caller that gave up on
// the server.
//
// "Before it returns" is the load-bearing half. Stop also makes Serve return,
// and Serve's own shutdown closes the log — but on another goroutine, so a
// caller that stops the server and then removes its log file would be racing
// that goroutine. On Windows it would lose that race about as often as it won
// it, which is a flake in someone else's test suite rather than a bug anyone
// goes looking for.
func TestServer_StopReleasesTheAuditLog(t *testing.T) {
	fleet := newTestFleet(t)
	dir := t.TempDir()
	cfg := fleet.agentConfig(t)
	cfg.Audit.Enabled = true
	cfg.Audit.Path = filepath.Join(dir, "audit.jsonl")

	h := start(t, cfg, []agent.Registration{registration("host", newCountingService())})
	require.NoError(t, h.server.Deps().Audit.Write(policyRecord()))

	h.server.Stop()

	// Removing the file is the portable spelling of "nothing holds it open":
	// on Windows an open handle is what makes this fail, and on Unix it
	// succeeds either way, so the assertion bites exactly where the failure
	// lives. Nothing reopens it afterwards — that a write would is
	// TestServer_ShutdownClosesTheAuditLog's assertion, and making it here as
	// well would leave this test holding the handle its own subject exists to
	// release.
	require.NoError(t, os.Remove(cfg.Audit.Path))
}

// A config assembled in memory gets the same caps as one read from disk.
//
// Load applies the documented defaults; nothing else did, so a Config built by
// hand reached the policy layer with a zero default timeout and a zero output
// cap — which are not "strict", they are "no limit at all".
func TestServer_AppliesConfigDefaultsToTheCaps(t *testing.T) {
	fleet := newTestFleet(t)
	cfg := fleet.agentConfig(t)
	require.Zero(t, cfg.Exec.MaxOutputBytes, "the fixture deliberately sets none")

	h := start(t, cfg, []agent.Registration{registration("host", newCountingService())})
	caps := h.server.Deps().Policy.Caps()
	assert.Positive(t, caps.DefaultTimeout)
	assert.Positive(t, caps.MaxTimeout)
	assert.GreaterOrEqual(t, caps.MaxTimeout, caps.DefaultTimeout)
	assert.Positive(t, caps.MaxOutputBytes)
	assert.Positive(t, caps.MaxConcurrent)
	assert.LessOrEqual(t, caps.DefaultTimeout, 10*time.Minute)
}
