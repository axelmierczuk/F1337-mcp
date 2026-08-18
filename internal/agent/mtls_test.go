package agent_test

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	"github.com/axelmierczuk/fleet-mcp/internal/agent/exec"
)

// plaintextConfig is the configuration of a host that never enrolled: a name,
// an address, and no TLS material anywhere.
//
// Written by hand rather than derived from testFleet's, because that is what
// the operator this option exists for does — there is no CA on that machine to
// derive anything from.
func plaintextConfig(t *testing.T, listen string) *agent.Config {
	t.Helper()
	dir := t.TempDir()
	return &agent.Config{
		Name:     "tailnet-box",
		Listen:   listen,
		StateDir: filepath.Join(dir, "state"),
		Audit: agent.AuditConfig{
			Enabled: true,
			Path:    filepath.Join(dir, "audit.jsonl"),
		},
	}
}

// A config naming no TLS material serves without mTLS, and one naming a leaf
// and a CA does not — with nothing to say so in either file.
//
// The inference is the whole of "off by default" that an upgrade can survive:
// every agent already enrolled has certificate paths and no `tls.enabled`, and
// a default that read those as "off" would silently drop a whole fleet to
// plaintext on the version they upgraded to.
func TestTLSEnabled_IsInferredFromTheMaterialAndOverriddenByTheKey(t *testing.T) {
	t.Parallel()

	yes := true
	no := false

	cases := []struct {
		name string
		tls  agent.TLSConfig
		want bool
	}{
		{name: "nothing configured", tls: agent.TLSConfig{}, want: false},
		{
			name: "enrolled: a leaf, a key and a CA, and no enabled key",
			tls:  agent.TLSConfig{Certificate: "a.crt", PrivateKey: "a.key", CABundle: "ca.crt"},
			want: true,
		},
		{
			name: "a CA bundle alone is still an agent that means to authenticate",
			tls:  agent.TLSConfig{CABundle: "ca.crt"},
			want: true,
		},
		{
			name: "an explicit false wins over the material",
			tls:  agent.TLSConfig{Enabled: &no, Certificate: "a.crt", PrivateKey: "a.key", CABundle: "ca.crt"},
			want: false,
		},
		{
			name: "an explicit true wins over the absence of it",
			tls:  agent.TLSConfig{Enabled: &yes},
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tc.tls.IsEnabled())
		})
	}
}

// ---------------------------------------------------------------- guard 1

// The refusal, through Config.Validate — which is the call `fleet-agent serve`
// makes before it builds anything.
//
// Driven from Validate rather than from the classifier underneath it because
// the classifier being right buys nothing if the command never reaches it, and
// this repository's dominant defect is exactly that: a behaviour whose test
// would pass without the wiring.
func TestValidate_RefusesAnUnauthenticatedListenerOffLoopbackAndPrivateNetworks(t *testing.T) {
	t.Parallel()

	refused := []struct {
		name   string
		listen string
	}{
		{name: "the default listen address", listen: "0.0.0.0:8722"},
		{name: "IPv6 wildcard", listen: "[::]:8722"},
		{name: "a bare port, which is every interface", listen: ":8722"},
		{name: "a public address", listen: "203.0.113.9:8722"},
		{name: "a public IPv6 address", listen: "[2001:db8::1]:8722"},
		{name: "a name, which this agent will not resolve to decide", listen: "agent.example.com:8722"},
	}
	for _, tc := range refused {
		t.Run("refused: "+tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := plaintextConfig(t, tc.listen)
			err := cfg.Validate(agent.ValidateOptions{})
			require.Error(t, err, "serving %s without mTLS is unauthenticated remote code execution", tc.listen)
			assert.ErrorIs(t, err, agent.ErrUnauthenticatedPublicListen)

			// And the flag is the only way past it.
			assert.NoError(t, cfg.Validate(agent.ValidateOptions{AllowUnauthenticatedPublic: true}),
				"--allow-unauthenticated-public is the documented override and must work")
		})
	}

	allowed := []struct {
		name   string
		listen string
	}{
		{name: "loopback", listen: "127.0.0.1:8722"},
		{name: "loopback by name", listen: "localhost:8722"},
		{name: "IPv6 loopback", listen: "[::1]:8722"},
		{name: "RFC 1918", listen: "10.4.0.9:8722"},
		{name: "RFC 1918, 172.16/12", listen: "172.20.1.1:8722"},
		{name: "RFC 1918, 192.168/16", listen: "192.168.7.3:8722"},
		{name: "link-local", listen: "169.254.4.9:8722"},
		{name: "unique-local IPv6", listen: "[fd7a:115c:a1e0::1]:8722"},
		// The address every Tailscale node has. net.IP.IsPrivate says no —
		// it is carrier space — and this is the deployment the whole option
		// exists for, so it is named explicitly.
		{name: "carrier-grade NAT, where a tailnet lives", listen: "100.83.4.17:8722"},
	}
	for _, tc := range allowed {
		t.Run("allowed: "+tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := plaintextConfig(t, tc.listen)
			assert.NoError(t, cfg.Validate(agent.ValidateOptions{}),
				"%s is reachable only from a network the operator already controls", tc.listen)
		})
	}
}

// With mTLS on, every address is permitted: the handshake is the boundary, and
// a publicly reachable enrolled agent is an ordinary deployment.
//
// This is the half that stops the guard from being a wildcard-address ban.
func TestValidate_LeavesAnAuthenticatedAgentFreeToListenAnywhere(t *testing.T) {
	t.Parallel()

	fleet := newTestFleet(t)
	cfg := fleet.agentConfig(t)
	for _, listen := range []string{"0.0.0.0:8722", "203.0.113.9:8722", "agent.example.com:8722"} {
		cfg.Listen = listen
		assert.NoError(t, cfg.Validate(agent.ValidateOptions{AllowNoJail: true}),
			"mTLS authenticates the caller, so %s is a deployment decision rather than an exposure", listen)
	}
}

// The daemon refuses to bind, not only to validate.
//
// New is what actually opens the socket, and a caller that never calls Validate
// — a test harness, an embedder, a future command — must not be able to reach a
// listening unauthenticated agent on a public address by skipping it.
func TestNew_RefusesToBindAnUnauthenticatedPublicListener(t *testing.T) {
	t.Parallel()

	cfg := plaintextConfig(t, "0.0.0.0:0")
	_, err := agent.New(agent.Options{Config: cfg, Log: discardLogger()})
	require.Error(t, err)
	assert.ErrorIs(t, err, agent.ErrUnauthenticatedPublicListen)
	assert.Contains(t, err.Error(), "--allow-unauthenticated-public",
		"the refusal has to say how to proceed: it is met by an operator whose agent works on their laptop")
}

// And it binds when the operator has said they mean it, which is what stops
// the test above from passing for the wrong reason — a daemon that refused
// every plaintext listener would satisfy it just as well.
func TestNew_BindsAnUnauthenticatedPublicListenerWhenToldTo(t *testing.T) {
	t.Parallel()

	cfg := plaintextConfig(t, "127.0.0.1:0")
	cfg.Listen = "0.0.0.0:0"
	srv, err := agent.New(agent.Options{
		Config:                     cfg,
		Log:                        discardLogger(),
		Services:                   []agent.Registration{},
		AllowUnauthenticatedPublic: true,
	})
	require.NoError(t, err)
	defer srv.Stop()
	assert.NotNil(t, srv.Addr(), "the listener is open")
}

// ---------------------------------------------------------------- guard 2

// The daemon says what it is at every start, and it is the daemon that says it.
//
// Asserted through start(), which is the real agent.New and the real Serve
// against a real logger — not by calling the function that composes the line.
// A warning nothing emits is the exact shape of defect this repository keeps
// finding.
func TestServing_AnnouncesThatItAuthenticatesNobody(t *testing.T) {
	t.Parallel()

	log, buf := capturedLogger()
	cfg := plaintextConfig(t, "127.0.0.1:0")
	start(t, cfg, []agent.Registration{}, func(o *agent.Options) { o.Log = log })

	logs := buf.String()
	assert.Contains(t, logs, "THIS AGENT AUTHENTICATES NOBODY")
	assert.Contains(t, logs, "tls.enabled is false")
	assert.Contains(t, logs, "127.0.0.1:0", "the listen address is half the question")
	assert.Contains(t, logs, "authenticates its peers", "the precondition is what makes the posture legitimate")

	// The serving line is written by Serve, which start() runs in a goroutine,
	// so this waits for the recorded fact rather than assuming it has landed.
	awaitLog(t, buf, "mtls=false", "the serving line states the posture too")
}

// awaitLog waits for a line to appear in a daemon's log.
//
// The daemon logs from its own goroutine, so a bare read races the write. This
// polls for the recorded fact instead of sleeping a fixed duration and hoping —
// the same rule the rest of this suite follows.
func awaitLog(t *testing.T, buf *syncBuffer, want, why string) {
	t.Helper()
	require.Eventuallyf(t, func() bool {
		return strings.Contains(buf.String(), want)
	}, 30*time.Second, 5*time.Millisecond, "%s; waiting for %q in:\n%s", why, want, buf.String())
}

// An enrolled agent says nothing of the sort, so the line above means
// something when it appears.
func TestServing_SaysNothingAboutAuthenticationWhenItAuthenticates(t *testing.T) {
	t.Parallel()

	log, buf := capturedLogger()
	fleet := newTestFleet(t)
	start(t, fleet.agentConfig(t), []agent.Registration{}, func(o *agent.Options) { o.Log = log })

	awaitLog(t, buf, "mtls=true", "an authenticated agent states its posture too")
	assert.NotContains(t, buf.String(), "THIS AGENT AUTHENTICATES NOBODY")
}

// Certificates sitting in a config that has turned mTLS off are called out
// separately: every other signal on that host — files on disk, a registry
// entry, an enrollment record — says the opposite of what is happening.
func TestServing_AnnouncesCertificatesItIsIgnoring(t *testing.T) {
	t.Parallel()

	log, buf := capturedLogger()
	fleet := newTestFleet(t)
	cfg := fleet.agentConfig(t)
	cfg.Listen = "127.0.0.1:0"
	off := false
	cfg.TLS.Enabled = &off
	start(t, cfg, []agent.Registration{}, func(o *agent.Options) { o.Log = log })

	logs := buf.String()
	assert.Contains(t, logs, "CERTIFICATES ARE CONFIGURED AND IGNORED")
	assert.Contains(t, logs, "THIS AGENT AUTHENTICATES NOBODY")
}

// ---------------------------------------------------------------- the transport

// A client with no certificate at all reaches an agent serving without mTLS,
// and is named as what it is.
//
// The client here presents nothing and verifies nothing — insecure credentials,
// the same ones internal/client uses for an insecure target — so this is the
// real posture rather than a relaxed handshake.
func TestPlaintextAgent_ServesAnAnonymousCallerAndNamesItUnauthenticated(t *testing.T) {
	t.Parallel()

	counting := newCountingService()
	cfg := plaintextConfig(t, "127.0.0.1:0")
	h := start(t, cfg, []agent.Registration{registration("host", counting)})

	hostClient := sandboxdv1.NewHostServiceClient(h.rawConn(t, insecure.NewCredentials()))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := hostClient.Health(ctx, &sandboxdv1.HealthRequest{})
	require.NoError(t, err, "an agent with mTLS off serves whoever the network let through")

	assert.True(t, strings.HasPrefix(counting.seenPrincipal(), agent.UnauthenticatedPrefix),
		"the principal must name itself as unauthenticated, got %q", counting.seenPrincipal())
	assert.False(t, counting.seenPrincipalAuthenticated(),
		"nothing authenticated this caller, and the principal must not claim otherwise")
}

// The same anonymous caller against an agent that is using mTLS is refused, as
// it always was. The posture is a configuration decision, never a property of
// whatever turned up on the connection.
func TestMTLSAgent_StillRefusesACallerWithNoCertificate(t *testing.T) {
	t.Parallel()

	fleet := newTestFleet(t)
	h := start(t, fleet.agentConfig(t), []agent.Registration{registration("host", newCountingService())})

	hostClient := sandboxdv1.NewHostServiceClient(h.rawConn(t, insecure.NewCredentials()))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := hostClient.Health(ctx, &sandboxdv1.HealthRequest{})
	require.Error(t, err, "an agent with mTLS on authenticates every caller")
	// The handshake fails before any RPC is dispatched, so this is a transport
	// failure rather than an Unauthenticated status. What matters is that no
	// handler ran.
	assert.NotEqual(t, codes.OK, status.Code(err))
}

// ---------------------------------------------------------------- guard 4

// The audit record of a command run on an agent that authenticated nobody says
// so twice: in the principal, and in a field a reader can match on.
//
// This is the guard that decides whether the log keeps meaning what it meant. A
// record whose principal is "whoever connected" must not be indistinguishable
// from one naming a verified certificate subject.
func TestAudit_RecordsThatNothingAuthenticatedTheCaller(t *testing.T) {
	t.Parallel()

	cfg := plaintextConfig(t, "127.0.0.1:0")
	h := start(t, cfg, []agent.Registration{{Name: "exec", Factory: exec.New}})

	execClient := sandboxdv1.NewExecServiceClient(h.rawConn(t, insecure.NewCredentials()))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	stream, err := execClient.Exec(ctx, &sandboxdv1.ExecRequest{
		Argv: []string{selfPath(t), "hello"},
		Env:  []string{"FLEET_EXEC_E2E=echo"},
	})
	require.NoError(t, err)
	for {
		if _, recvErr := stream.Recv(); recvErr != nil {
			require.ErrorIs(t, recvErr, io.EOF)
			break
		}
	}

	rec := onlyAuditRecord(t, h, cfg.Audit.Path)
	assert.Equal(t, "network", rec.PrincipalSource,
		"a record nothing verified must say so in a field, not only in prose")
	assert.True(t, strings.HasPrefix(rec.Principal, agent.UnauthenticatedPrefix),
		"the principal must not read like a certificate subject, got %q", rec.Principal)
	assert.Equal(t, "sandboxd.v1.ExecService/Exec", rec.RPC)
}

// And the record from an authenticated agent names the certificate, and says
// that is where the name came from.
//
// Both halves are asserted in one place because the property is the difference
// between them: either record alone could be produced by a daemon that stamped
// a constant.
func TestAudit_RecordsThatACertificateAuthenticatedTheCaller(t *testing.T) {
	t.Parallel()

	fleet := newTestFleet(t)
	cfg := fleet.agentConfig(t)
	cfg.Audit.Enabled = true
	cfg.Audit.Path = filepath.Join(t.TempDir(), "audit.jsonl")

	h := start(t, cfg, []agent.Registration{{Name: "exec", Factory: exec.New}})

	execClient := sandboxdv1.NewExecServiceClient(h.controlConn(t, fleet))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	stream, err := execClient.Exec(ctx, &sandboxdv1.ExecRequest{
		Argv: []string{selfPath(t), "hello"},
		Env:  []string{"FLEET_EXEC_E2E=echo"},
	})
	require.NoError(t, err)
	for {
		if _, recvErr := stream.Recv(); recvErr != nil {
			require.ErrorIs(t, recvErr, io.EOF)
			break
		}
	}

	rec := onlyAuditRecord(t, h, cfg.Audit.Path)
	assert.Equal(t, "certificate", rec.PrincipalSource)
	assert.Equal(t, "fleet-mcp", rec.Principal)
	assert.NotContains(t, rec.Principal, agent.UnauthenticatedPrefix)
}

// auditRecord is the part of a record these tests read.
type auditRecord struct {
	Principal       string `json:"principal"`
	PrincipalSource string `json:"principal_source"`
	RPC             string `json:"rpc"`
}

// onlyAuditRecord closes the log and returns the single record in it.
func onlyAuditRecord(t *testing.T, h *harness, path string) auditRecord {
	t.Helper()
	require.NoError(t, h.server.Deps().Audit.Close())
	data, err := os.ReadFile(path) //nolint:gosec // a path this test wrote
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 1, "one call, one record")

	var rec auditRecord
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &rec))
	return rec
}

// A context that never came from a served RPC has no principal, on an agent
// with mTLS off as much as on. The daemon's answer to "who is this" comes from
// the connection, and there is no connection here.
func TestPrincipalFromContext_HasNoAnswerForAContextThatServedNothing(t *testing.T) {
	t.Parallel()

	_, ok := agent.PrincipalFromContext(context.Background())
	assert.False(t, ok)
}
