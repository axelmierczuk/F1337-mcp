package mcpserver_test

import (
	"context"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	agentexec "github.com/axelmierczuk/fleet-mcp/internal/agent/exec"
	agentfs "github.com/axelmierczuk/fleet-mcp/internal/agent/fs"
	"github.com/axelmierczuk/fleet-mcp/internal/client"
	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver"
	"github.com/axelmierczuk/fleet-mcp/internal/registry"
	"github.com/axelmierczuk/fleet-mcp/internal/security/jail"
	"github.com/axelmierczuk/fleet-mcp/internal/security/policy"
)

// The exec, file and transfer tools are mostly glue and rendering, and glue
// tested against a mock proves the glue matches the mock. So everything below
// runs the *real* internal/agent/exec and internal/agent/fs services in this
// process, over a real gRPC connection on an in-memory listener, against a
// real directory on this machine standing in for the sandbox's filesystem.
//
// What that buys, concretely: the line numbering is checked against bytes the
// agent actually produced, the two-match edit is refused by the code that will
// refuse it in production, the cancellation test can look for a process that
// really was spawned and really was killed, and every status code the tools
// map is one the agent genuinely returns.

// backendOptions configures the agent services a fixture stands up.
type backendOptions struct {
	// jailRoots confines the file service. Empty means unconfined, which is
	// the default configuration: exec and the path jail are mutually
	// exclusive, so with exec enabled there are no allowed roots at all.
	jailRoots []string
	// execDisabled turns ExecService off, which is the one configuration in
	// which a jail is a real boundary.
	execDisabled bool
	// caps overrides the agent's exec caps.
	caps policy.Caps
}

// agentBackend is one sandbox's ExecService and FileService, served over
// bufconn.
type agentBackend struct {
	files sandboxdv1.FileServiceClient
	exec  sandboxdv1.ExecServiceClient
}

func newAgentBackend(t *testing.T, opts backendOptions) *agentBackend {
	t.Helper()

	confinement := jail.Unconfined()
	if len(opts.jailRoots) > 0 {
		var err error
		confinement, err = jail.New(jail.Config{Roots: opts.jailRoots})
		require.NoError(t, err)
	}

	caps := opts.caps
	if caps.MaxTimeout == 0 {
		caps.MaxTimeout = 5 * time.Minute
	}
	if caps.DefaultTimeout == 0 {
		caps.DefaultTimeout = min(30*time.Second, caps.MaxTimeout)
	}
	if caps.MaxOutputBytes == 0 {
		caps.MaxOutputBytes = 2 * 1024 * 1024
	}
	if caps.MaxConcurrent == 0 {
		caps.MaxConcurrent = 8
	}
	pol, err := policy.New(policy.Config{Caps: caps})
	require.NoError(t, err)

	audit := policy.NewAudit(policy.AuditConfig{Path: filepath.Join(t.TempDir(), "audit.jsonl"), Enabled: true, MaxBytes: 1 << 20, RetainSegments: 2})
	// The log holds its handle for the life of the daemon by design, and
	// Windows will not unlink an open file, so it goes before t.TempDir's own
	// cleanup — which means registering after it.
	t.Cleanup(func() { _ = audit.Close() })

	logger := slog.New(slog.NewTextHandler(&testWriter{t: t}, &slog.HandlerOptions{Level: slog.LevelWarn}))

	enabled := !opts.execDisabled
	execService, err := agentexec.New(agent.Deps{
		Config: &agent.Config{Exec: agent.ExecConfig{Enabled: &enabled}},
		Policy: pol,
		Audit:  audit,
		Log:    logger,
	})
	require.NoError(t, err)

	server := grpc.NewServer()
	agentfs.NewService(confinement, logger, agentfs.Limits{}).Register(server)
	execService.Register(server)

	listener := bufconn.Listen(1024 * 1024)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient("passthrough:///sandbox",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return &agentBackend{
		files: sandboxdv1.NewFileServiceClient(conn),
		exec:  sandboxdv1.NewExecServiceClient(conn),
	}
}

// backendClients is a tools.Clients that dials the in-process agent for the
// two services these tools use, and answers the rest as unimplemented.
type backendClients struct {
	backend *agentBackend
	host    *fakeHost
	// execOverride replaces the real exec client, for the one test that needs
	// an agent behaving worse than the real one ever does. filesOverride does
	// the same for the file client, for a test that has to see the shape of
	// what went over the wire rather than only what came back.
	execOverride  sandboxdv1.ExecServiceClient
	filesOverride sandboxdv1.FileServiceClient
	// onFiles runs when a handler asks for a file client, which is the first
	// thing every one of these handlers does and so the earliest point in a
	// tool call a test can observe from the outside. The memory tests take
	// their baseline here: by this moment the protocol has decoded the
	// request's arguments — for fleet_write that is the content itself,
	// which nothing on this side can avoid holding — and the handler has not
	// yet touched them, so everything measured after it is the handler's own.
	onFiles func()
}

func (c *backendClients) Host(string, string) (sandboxdv1.HostServiceClient, error) {
	return c.host, nil
}

func (c *backendClients) Exec(string, string) (sandboxdv1.ExecServiceClient, error) {
	if c.execOverride != nil {
		return c.execOverride, nil
	}
	return c.backend.exec, nil
}

func (c *backendClients) Files(string, string) (sandboxdv1.FileServiceClient, error) {
	if c.onFiles != nil {
		c.onFiles()
	}
	if c.filesOverride != nil {
		return c.filesOverride, nil
	}
	return c.backend.files, nil
}

func (c *backendClients) Process(string, string) (sandboxdv1.ProcessServiceClient, error) {
	return nil, status.Error(codes.Unimplemented, "not part of these tools")
}

func (c *backendClients) Forward(string, string) (sandboxdv1.ForwardServiceClient, error) {
	return nil, status.Error(codes.Unimplemented, "not part of these tools")
}

func (c *backendClients) Health(string) (client.HealthStatus, bool) {
	return client.HealthStatus{}, false
}

func (c *backendClients) Remove(string) {}

// agentFixture is an MCP session whose sandbox is the real agent services
// above, plus a directory on this machine playing the part of the sandbox's
// filesystem.
type agentFixture struct {
	t       *testing.T
	session *mcp.ClientSession
	backend *agentBackend
	clients *backendClients
	// remote is the directory the tests treat as living on the sandbox.
	remote string
}

// newAgentFixture stands up the agent services and an MCP session against
// them. remote is a directory on this machine; when the options ask for a
// jail, that directory is its only root, so a path outside it is outside the
// jail in exactly the sense #24 means.
func newAgentFixture(t *testing.T, opts backendOptions) *agentFixture {
	t.Helper()

	remote := t.TempDir()
	if opts.jailRoots == nil && opts.execDisabled {
		opts.jailRoots = []string{remote}
	}

	backend := newAgentBackend(t, opts)
	configDir := t.TempDir()
	clients := &backendClients{backend: backend, host: newFakeHost()}

	server, err := mcpserver.New(mcpserver.Options{
		ConfigDir:   configDir,
		Clients:     clients,
		LogWriter:   &testWriter{t: t},
		CallTimeout: 30 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })

	fleet, err := registry.Open(filepath.Join(configDir, "registry.yaml"))
	require.NoError(t, err)
	require.NoError(t, fleet.Add(registry.Sandbox{Name: "build-box", Address: "build-box.internal:8722"}))

	session := connect(t, server)
	callTool(t, session, "fleet_select", map[string]any{"name": "build-box"}, false)

	return &agentFixture{t: t, session: session, backend: backend, clients: clients, remote: remote}
}

// ok calls a tool and fails the test if it reported an error.
func (f *agentFixture) ok(name string, args map[string]any) *mcp.CallToolResult {
	f.t.Helper()
	return callTool(f.t, f.session, name, args, false)
}

// fails calls a tool and returns the error text, failing if it succeeded.
func (f *agentFixture) fails(name string, args map[string]any) string {
	f.t.Helper()
	return resultText(callTool(f.t, f.session, name, args, true))
}

// path renders a path inside the sandbox's directory.
func (f *agentFixture) path(elem ...string) string {
	return filepath.Join(append([]string{f.remote}, elem...)...)
}
