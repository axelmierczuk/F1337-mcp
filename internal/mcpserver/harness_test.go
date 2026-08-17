package mcpserver_test

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	protobuf "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/client"
	"github.com/axelmierczuk/sandboxd-mcp/internal/mcpserver"
	"github.com/axelmierczuk/sandboxd-mcp/internal/mcpserver/selection"
	"github.com/axelmierczuk/sandboxd-mcp/internal/registry"
)

// fakeHost stands in for one sandboxd-agent's HostService. The agent itself
// (#5) is being built concurrently and is not on main, and a fake client is
// what makes "refresh: false issues no probes" assertable on a count rather
// than on elapsed time.
type fakeHost struct {
	mu sync.Mutex

	// healthCalls and infoCalls count what reached this sandbox.
	healthCalls int
	infoCalls   int
	// toolchainCalls counts calls that asked for toolchain detection.
	toolchainCalls int

	// err, when set, is returned by every RPC.
	err error
	// delay is slept before answering, to simulate a slow or hung host.
	delay time.Duration
	// toolchainDelay is added on top when toolchains were requested.
	toolchainDelay time.Duration

	status  sandboxdv1.HealthResponse_Status
	message string
	info    *sandboxdv1.GetHostInfoResponse
}

func newFakeHost() *fakeHost {
	return &fakeHost{
		status: sandboxdv1.HealthResponse_STATUS_SERVING,
		info: &sandboxdv1.GetHostInfoResponse{
			Platform: &sandboxdv1.Platform{
				Os: "linux", Arch: "amd64", KernelVersion: "6.8.0", Hostname: "build-box", PathSeparator: "/",
			},
			Resources: &sandboxdv1.Resources{
				CpuCores: 8, MemoryTotalBytes: 16 << 30, MemoryAvailableBytes: 9 << 30,
				DiskTotalBytes: 512 << 30, DiskAvailableBytes: 200 << 30, LoadAverage_1M: 0.4,
			},
			AgentVersion:           "0.1.0-test",
			AllowedRoots:           []string{"/home/build/workspace"},
			StartedAt:              timestamppb.New(time.Now().Add(-90 * time.Minute)),
			AuthenticatedPrincipal: "sandboxd-mcp",
		},
	}
}

func (f *fakeHost) Health(ctx context.Context, _ *sandboxdv1.HealthRequest, _ ...grpc.CallOption) (*sandboxdv1.HealthResponse, error) {
	f.mu.Lock()
	f.healthCalls++
	err, delay, st, msg := f.err, f.delay, f.status, f.message
	f.mu.Unlock()

	if err := sleepOrFail(ctx, delay); err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	return &sandboxdv1.HealthResponse{
		Status: st, Message: msg, AgentVersion: "0.1.0-test", RunningProcesses: 2,
	}, nil
}

func (f *fakeHost) GetHostInfo(ctx context.Context, in *sandboxdv1.GetHostInfoRequest, _ ...grpc.CallOption) (*sandboxdv1.GetHostInfoResponse, error) {
	f.mu.Lock()
	f.infoCalls++
	if in.GetIncludeToolchains() {
		f.toolchainCalls++
	}
	err, delay, info := f.err, f.delay, f.info
	if in.GetIncludeToolchains() {
		delay += f.toolchainDelay
	}
	f.mu.Unlock()

	if err := sleepOrFail(ctx, delay); err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	// Cloned so a toolchain list added for one call does not leak into the
	// next.
	out, _ := protobuf.Clone(info).(*sandboxdv1.GetHostInfoResponse)
	if in.GetIncludeToolchains() {
		out.Toolchains = []*sandboxdv1.Toolchain{{Name: "go", Version: "1.25.0", Path: "/usr/local/go/bin/go"}}
	}
	return out, nil
}

func sleepOrFail(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return status.Error(codes.DeadlineExceeded, "context deadline exceeded")
	}
}

func (f *fakeHost) counts() (health, info, toolchains int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.healthCalls, f.infoCalls, f.toolchainCalls
}

func (f *fakeHost) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// fakeClients is a tools.Clients backed by per-sandbox fakeHosts.
type fakeClients struct {
	mu sync.Mutex

	hosts  map[string]*fakeHost
	cached map[string]client.HealthStatus
	// dialErr, when set for a name, is what Host returns instead of a client.
	dialErr map[string]error
	removed []string
}

func newFakeClients() *fakeClients {
	return &fakeClients{
		hosts:   map[string]*fakeHost{},
		cached:  map[string]client.HealthStatus{},
		dialErr: map[string]error{},
	}
}

func (c *fakeClients) host(name string) *fakeHost {
	c.mu.Lock()
	defer c.mu.Unlock()
	h, ok := c.hosts[name]
	if !ok {
		h = newFakeHost()
		c.hosts[name] = h
	}
	return h
}

func (c *fakeClients) setCached(name string, h client.HealthStatus) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cached[name] = h
}

func (c *fakeClients) Host(name, _ string) (sandboxdv1.HostServiceClient, error) {
	c.mu.Lock()
	err := c.dialErr[name]
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return c.host(name), nil
}

func (c *fakeClients) Exec(string, string) (sandboxdv1.ExecServiceClient, error) {
	return nil, status.Error(codes.Unimplemented, "exec is milestone M2 issue #22")
}

func (c *fakeClients) Files(string, string) (sandboxdv1.FileServiceClient, error) {
	return nil, status.Error(codes.Unimplemented, "files are milestone M2 issue #24")
}

func (c *fakeClients) Process(string, string) (sandboxdv1.ProcessServiceClient, error) {
	return nil, status.Error(codes.Unimplemented, "processes are milestone M2 issue #23")
}

func (c *fakeClients) Forward(string, string) (sandboxdv1.ForwardServiceClient, error) {
	return nil, status.Error(codes.Unimplemented, "forwarding is milestone M2 issue #26")
}

func (c *fakeClients) Health(name string) (client.HealthStatus, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	h, ok := c.cached[name]
	return h, ok
}

func (c *fakeClients) Remove(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removed = append(c.removed, name)
}

func (c *fakeClients) wasRemoved(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, n := range c.removed {
		if n == name {
			return true
		}
	}
	return false
}

// fixture is a running MCP server plus a connected client session.
type fixture struct {
	t        *testing.T
	dir      string
	fleet    *registry.Registry
	clients  *fakeClients
	server   *mcpserver.Server
	session  *mcp.ClientSession
	identity string
}

type fixtureOptions struct {
	// clientName is the implementation name the test client reports, which
	// is what identity falls back to when _meta carries no explicit id.
	clientName string
	// configDir reuses an existing directory, for restart tests.
	configDir string
	// probeTimeout overrides the per-sandbox health probe deadline.
	probeTimeout time.Duration
	// callTimeout overrides the unary call deadline.
	callTimeout time.Duration
	// clients overrides the fake client pool, for restart tests that must
	// keep the same fakes.
	clients *fakeClients
}

func newFixture(t *testing.T, opts fixtureOptions) *fixture {
	t.Helper()

	dir := opts.configDir
	if dir == "" {
		dir = t.TempDir()
	}
	clients := opts.clients
	if clients == nil {
		clients = newFakeClients()
	}
	clientName := opts.clientName
	if clientName == "" {
		clientName = "test-client"
	}

	server, err := mcpserver.New(mcpserver.Options{
		ConfigDir:    dir,
		Clients:      clients,
		LogWriter:    &testWriter{t: t},
		ProbeTimeout: opts.probeTimeout,
		CallTimeout:  opts.callTimeout,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })

	fleet, err := registry.Open(filepath.Join(dir, "registry.yaml"))
	require.NoError(t, err)

	ctx := t.Context()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport)
	require.NoError(t, err)
	t.Cleanup(func() { _ = serverSession.Close() })

	mcpClient := mcp.NewClient(&mcp.Implementation{Name: clientName, Version: "1.0.0"}, nil)
	session, err := mcpClient.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })

	return &fixture{
		t: t, dir: dir, fleet: fleet, clients: clients,
		server: server, session: session,
		identity: "client:" + clientName,
	}
}

// testWriter routes server logs into the test log, so a failing test shows
// what the server said — and so nothing lands on the real stderr.
type testWriter struct{ t *testing.T }

func (w *testWriter) Write(p []byte) (int, error) {
	w.t.Logf("server: %s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// call invokes a tool. asIdentity, when non-empty, is sent as the explicit
// client id in _meta.
func (f *fixture) call(name string, args map[string]any, asIdentity string) *mcp.CallToolResult {
	f.t.Helper()
	params := &mcp.CallToolParams{Name: name, Arguments: args}
	if asIdentity != "" {
		params.Meta = mcp.Meta{selection.MetaKeyClientID: asIdentity}
	}
	res, err := f.session.CallTool(f.t.Context(), params)
	require.NoError(f.t, err, "tool call must not fail at the protocol level")
	return res
}

// ok calls a tool and fails the test if it reported an error.
func (f *fixture) ok(name string, args map[string]any, asIdentity string) *mcp.CallToolResult {
	f.t.Helper()
	res := f.call(name, args, asIdentity)
	require.Falsef(f.t, res.IsError, "%s reported an error: %s", name, resultText(res))
	return res
}

// fails calls a tool and fails the test if it did not report an error.
func (f *fixture) fails(name string, args map[string]any, asIdentity string) string {
	f.t.Helper()
	res := f.call(name, args, asIdentity)
	require.Truef(f.t, res.IsError, "%s should have reported an error, got: %s", name, resultText(res))
	return resultText(res)
}

// add registers a sandbox directly in the registry, bypassing the tool.
func (f *fixture) add(name, address string, labels map[string]string) {
	f.t.Helper()
	require.NoError(f.t, f.fleet.Add(registry.Sandbox{Name: name, Address: address, Labels: labels}))
}

func resultText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// structured decodes a result's structuredContent into T.
func structured[T any](t *testing.T, res *mcp.CallToolResult) T {
	t.Helper()
	require.NotNil(t, res.StructuredContent, "tool result carries no structured content")
	raw, err := json.Marshal(res.StructuredContent)
	require.NoError(t, err)
	var out T
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

// echoOf pulls the mandatory sandbox echo out of any tool result.
func echoOf(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	m := structured[map[string]any](t, res)
	v, ok := m["sandbox"]
	require.Truef(t, ok, "result has no sandbox echo: %v", m)
	s, ok := v.(string)
	require.Truef(t, ok, "sandbox echo is not a string: %v", v)
	return s
}

func unavailable(sandbox string) error {
	return status.Error(codes.Unavailable, fmt.Sprintf("connection refused dialing %s", sandbox))
}
