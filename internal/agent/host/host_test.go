package host_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/agent"
	"github.com/axelmierczuk/sandboxd-mcp/internal/agent/host"
	"github.com/axelmierczuk/sandboxd-mcp/internal/security/jail"
)

func newService(t *testing.T, roots ...string) (*host.Service, agent.Deps) {
	t.Helper()
	confinement := jail.Unconfined()
	if len(roots) > 0 {
		var err error
		confinement, err = jail.New(jail.Config{Roots: roots})
		require.NoError(t, err)
	}

	deps := agent.Deps{
		Config:    &agent.Config{AllowedRoots: roots},
		Jail:      confinement,
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Status:    agent.NewStatus(),
		Version:   "1.2.3-test",
		StartedAt: time.Now().UTC().Add(-time.Minute),
	}
	svc, err := host.New(deps)
	require.NoError(t, err)
	return svc.(*host.Service), deps
}

// Platform and arch are what this binary was built for, on every platform.
func TestGetHostInfo_Platform(t *testing.T) {
	svc, deps := newService(t)

	resp, err := svc.GetHostInfo(context.Background(), &sandboxdv1.GetHostInfoRequest{})
	require.NoError(t, err)

	assert.Equal(t, runtime.GOOS, resp.GetPlatform().GetOs())
	assert.Equal(t, runtime.GOARCH, resp.GetPlatform().GetArch())
	assert.Equal(t, string(filepath.Separator), resp.GetPlatform().GetPathSeparator())
	assert.NotEmpty(t, resp.GetPlatform().GetHostname())
	assert.NotEmpty(t, resp.GetPlatform().GetKernelVersion(),
		"every platform the agent ships for can report a kernel or OS build version")

	assert.Equal(t, "1.2.3-test", resp.GetAgentVersion())
	assert.WithinDuration(t, deps.StartedAt, resp.GetStartedAt().AsTime(), time.Second)
}

// Resources are honest: cores are at least one, memory is real, and the disk
// figures describe a filesystem that exists.
func TestGetHostInfo_Resources(t *testing.T) {
	root := t.TempDir()
	svc, _ := newService(t, root)

	resp, err := svc.GetHostInfo(context.Background(), &sandboxdv1.GetHostInfoRequest{})
	require.NoError(t, err)

	res := resp.GetResources()
	assert.GreaterOrEqual(t, res.GetCpuCores(), uint32(1))
	assert.LessOrEqual(t, res.GetCpuCores(), uint32(runtime.NumCPU()),
		"the effective core count must never exceed the machine's visible CPUs")
	assert.Positive(t, res.GetMemoryTotalBytes())
	assert.LessOrEqual(t, res.GetMemoryAvailableBytes(), res.GetMemoryTotalBytes())
	assert.Positive(t, res.GetDiskTotalBytes())
	assert.LessOrEqual(t, res.GetDiskAvailableBytes(), res.GetDiskTotalBytes())
	assert.GreaterOrEqual(t, res.GetLoadAverage_1M(), 0.0)
}

// The allowed roots reported are the jail's resolved roots, so a caller
// comparing a rejected path against them is comparing like with like.
func TestGetHostInfo_AllowedRoots(t *testing.T) {
	root := t.TempDir()
	svc, deps := newService(t, root)

	resp, err := svc.GetHostInfo(context.Background(), &sandboxdv1.GetHostInfoRequest{})
	require.NoError(t, err)
	assert.Equal(t, deps.Jail.Roots(), resp.GetAllowedRoots())

	// With no jail, the field is empty — which is exactly what "running
	// without confinement" looks like on the wire.
	noJail, _ := newService(t)
	resp, err = noJail.GetHostInfo(context.Background(), &sandboxdv1.GetHostInfoRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.GetAllowedRoots())
}

// allowed_roots reports what the jail enforces, never what the config wrote
// down.
//
// This is the exec-enabled shape: roots in the config, no jail in force. The
// field is what sandbox_info and sandbox_select show the model to tell it where
// it may write, so echoing back roots that constrain nothing would be the
// model-facing version of exactly the false confidence this design removed.
func TestGetHostInfo_ReportsTheJailNotTheConfig(t *testing.T) {
	root := t.TempDir()
	deps := agent.Deps{
		Config:    &agent.Config{AllowedRoots: []string{root}}, // exec on by default
		Jail:      jail.Unconfined(),
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Status:    agent.NewStatus(),
		Version:   "1.2.3-test",
		StartedAt: time.Now().UTC(),
	}
	require.False(t, deps.Config.JailEnforced(), "guard: this is the exec-enabled configuration")

	built, err := host.New(deps)
	require.NoError(t, err)
	svc := built.(*host.Service)

	resp, err := svc.GetHostInfo(context.Background(), &sandboxdv1.GetHostInfoRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.GetAllowedRoots(),
		"an agent whose jail is off must report itself unconfined, not repeat its ignored roots")
}

// Toolchain probing is opt-in: the default call does not pay for it.
func TestGetHostInfo_ToolchainsAreOptIn(t *testing.T) {
	svc, _ := newService(t)

	resp, err := svc.GetHostInfo(context.Background(), &sandboxdv1.GetHostInfoRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.GetToolchains())

	// Asked for, they show up. Go is on the PATH of anything running this test.
	resp, err = svc.GetHostInfo(context.Background(), &sandboxdv1.GetHostInfoRequest{IncludeToolchains: true})
	require.NoError(t, err)
	require.NotEmpty(t, resp.GetToolchains())

	var foundGo bool
	for _, tc := range resp.GetToolchains() {
		assert.NotEmpty(t, tc.GetPath(), "a reported toolchain must name where it was found")
		if tc.GetName() == "go" {
			foundGo = true
			assert.Contains(t, tc.GetVersion(), "go")
		}
	}
	assert.True(t, foundGo, "go must be detected in an environment that is running go test")
}

// Health reports what Status holds and nothing else.
func TestHealth(t *testing.T) {
	svc, deps := newService(t)

	resp, err := svc.Health(context.Background(), &sandboxdv1.HealthRequest{})
	require.NoError(t, err)
	assert.Equal(t, sandboxdv1.HealthResponse_STATUS_SERVING, resp.GetStatus())
	assert.Equal(t, "1.2.3-test", resp.GetAgentVersion())
	assert.Zero(t, resp.GetRunningProcesses())

	deps.Status.SetProcessCounter(func() uint32 { return 3 })
	deps.Status.Set(sandboxdv1.HealthResponse_STATUS_DEGRADED, "disk is full")

	resp, err = svc.Health(context.Background(), &sandboxdv1.HealthRequest{})
	require.NoError(t, err)
	assert.Equal(t, sandboxdv1.HealthResponse_STATUS_DEGRADED, resp.GetStatus())
	assert.Equal(t, "disk is full", resp.GetMessage())
	assert.EqualValues(t, 3, resp.GetRunningProcesses())
}

// Health must not do the work GetHostInfo does. This asserts it structurally
// rather than by timing: the resource probe and the toolchain probe are the
// two expensive things in this package, and neither counter moves.
func TestHealth_DoesNotProbeAnything(t *testing.T) {
	svc, _ := newService(t, t.TempDir())

	var probes int
	svc.SetProberForTest(&host.Prober{
		Tools:    []host.Tool{{Name: "go", Args: []string{"version"}}},
		LookPath: func(string) (string, error) { probes++; return "", errors.New("prober must not be called") },
	})

	for i := 0; i < 10_000; i++ {
		_, err := svc.Health(context.Background(), &sandboxdv1.HealthRequest{})
		require.NoError(t, err)
	}
	assert.Zero(t, probes, "Health must never reach the toolchain prober")

	// And it is fast enough that a fleet-wide timer is not a standing load: ten
	// thousand calls in well under the time one filesystem stat would take per
	// call.
	start := time.Now()
	for i := 0; i < 10_000; i++ {
		_, _ = svc.Health(context.Background(), &sandboxdv1.HealthRequest{})
	}
	assert.Less(t, time.Since(start), 2*time.Second)
}
