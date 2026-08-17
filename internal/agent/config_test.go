package agent_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/agent"
)

// The schema in examples/agent.yaml is the one the daemon loads. This parses
// the shipped file itself rather than a copy, so the example cannot drift away
// from what the code accepts without this failing.
func TestLoad_ShippedExample(t *testing.T) {
	path, err := filepath.Abs(filepath.Join("..", "..", "examples", "agent.yaml"))
	require.NoError(t, err)
	require.FileExists(t, path)

	cfg, err := agent.Load(path)
	require.NoError(t, err)

	assert.Equal(t, "0.0.0.0:8722", cfg.Listen)
	assert.Equal(t, "/etc/sandboxd/agent.crt", cfg.TLS.Certificate)
	assert.Equal(t, "/etc/sandboxd/agent.key", cfg.TLS.PrivateKey)
	assert.Equal(t, "/etc/sandboxd/ca.crt", cfg.TLS.CABundle)
	assert.Equal(t, "sandboxd-control", cfg.TLS.RequireClientOU)
	assert.Equal(t, []string{"/home/build/workspace", "/tmp/sandboxd"}, cfg.AllowedRoots)

	// Durations come through as durations, not as nanoseconds.
	assert.Equal(t, 120*time.Second, cfg.Exec.DefaultTimeout.Duration())
	assert.Equal(t, 3600*time.Second, cfg.Exec.MaxTimeout.Duration())
	assert.EqualValues(t, 2097152, cfg.Exec.MaxOutputBytes)

	assert.Equal(t, 32, cfg.Process.MaxConcurrent)
	assert.EqualValues(t, 33554432, cfg.Process.MaxLogBytes)
	assert.Equal(t, 2000, cfg.Process.RingBufferLines)
	assert.Equal(t, 10*time.Second, cfg.Process.DefaultGracePeriod.Duration())
	assert.Equal(t, 60*time.Second, cfg.Process.MaxFollowDuration.Duration())

	assert.Equal(t, "/var/log/sandboxd/audit.jsonl", cfg.Audit.Path)
	assert.True(t, cfg.Audit.Enabled)

	require.NoError(t, cfg.Validate(agent.ValidateOptions{}))
}

// An M0-era config used top-level cert_file / key_file / ca_file. A host
// enrolled before the TLS block existed must still start.
func TestLoad_AcceptsLegacyCertificatePaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
name: build-box
listen: "0.0.0.0:8722"
cert_file: /etc/sandboxd/agent.crt
key_file: /etc/sandboxd/agent.key
ca_file: /etc/sandboxd/ca.crt
allowed_roots:
  - /workspace
`), 0o600))

	cfg, err := agent.Load(path)
	require.NoError(t, err)
	assert.Equal(t, "/etc/sandboxd/agent.crt", cfg.TLS.Certificate)
	assert.Equal(t, "/etc/sandboxd/agent.key", cfg.TLS.PrivateKey)
	assert.Equal(t, "/etc/sandboxd/ca.crt", cfg.TLS.CABundle)
	assert.Equal(t, agent.DefaultClientOU, cfg.TLS.RequireClientOU,
		"a config with no explicit OU must demand the control OU, never accept any")
	require.NoError(t, cfg.Validate(agent.ValidateOptions{}))
}

// Save writes the canonical schema and does not re-emit the legacy aliases,
// so a round trip collapses to one source of truth.
func TestConfig_SaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")

	cfg := &agent.Config{
		Name:   "build-box",
		Listen: "0.0.0.0:8722",
		TLS: agent.TLSConfig{
			Certificate:     filepath.Join(dir, "agent.crt"),
			PrivateKey:      filepath.Join(dir, "agent.key"),
			CABundle:        filepath.Join(dir, "ca.crt"),
			RequireClientOU: agent.DefaultClientOU,
		},
		AllowedRoots: []string{filepath.Join(dir, "workspace")},
	}
	require.NoError(t, cfg.Save(path))

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "cert_file")

	loaded, err := agent.Load(path)
	require.NoError(t, err)
	assert.Equal(t, cfg.Name, loaded.Name)
	assert.Equal(t, cfg.TLS, loaded.TLS)
	assert.Equal(t, cfg.AllowedRoots, loaded.AllowedRoots)

	if info, err := os.Stat(path); err == nil && os.Getenv("GOOS") != "windows" {
		assert.NotZero(t, info.Mode().Perm()&0o600)
	}
}

// Paths written relative to the config file resolve against its directory, so
// moving an enrollment directory wholesale keeps working.
func TestLoad_ResolvesRelativePaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
listen: "0.0.0.0:8722"
tls:
  certificate: agent.crt
  private_key: agent.key
  ca_bundle: ca.crt
allowed_roots:
  - workspace
state_dir: state
`), 0o600))

	cfg, err := agent.Load(path)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "agent.crt"), cfg.TLS.Certificate)
	assert.Equal(t, filepath.Join(dir, "agent.key"), cfg.TLS.PrivateKey)
	assert.Equal(t, filepath.Join(dir, "ca.crt"), cfg.TLS.CABundle)
	assert.Equal(t, []string{filepath.Join(dir, "workspace")}, cfg.AllowedRoots)
	assert.Equal(t, filepath.Join(dir, "state"), cfg.StateDir)
}

// The daemon refuses to start with no jail unless the operator asked for it by
// name, and the refusal is matchable so the CLI can explain the override.
func TestValidate_EmptyAllowedRoots(t *testing.T) {
	cfg := &agent.Config{
		Listen: "0.0.0.0:8722",
		TLS: agent.TLSConfig{
			Certificate: "a.crt", PrivateKey: "a.key", CABundle: "ca.crt",
			RequireClientOU: agent.DefaultClientOU,
		},
	}

	err := cfg.Validate(agent.ValidateOptions{})
	require.ErrorIs(t, err, agent.ErrNoAllowedRoots)

	require.NoError(t, cfg.Validate(agent.ValidateOptions{AllowNoJail: true}))
}

func TestValidate_Problems(t *testing.T) {
	base := func() *agent.Config {
		return &agent.Config{
			Listen: "0.0.0.0:8722",
			TLS: agent.TLSConfig{
				Certificate: "a.crt", PrivateKey: "a.key", CABundle: "ca.crt",
				RequireClientOU: agent.DefaultClientOU,
			},
			AllowedRoots: []string{absRoot()},
		}
	}

	for name, tc := range map[string]struct {
		mutate func(*agent.Config)
		want   string
	}{
		"missing certificate": {func(c *agent.Config) { c.TLS.Certificate = "" }, "tls.certificate"},
		"missing key":         {func(c *agent.Config) { c.TLS.PrivateKey = "" }, "tls.private_key"},
		"missing CA":          {func(c *agent.Config) { c.TLS.CABundle = "" }, "tls.ca_bundle"},
		"empty OU":            {func(c *agent.Config) { c.TLS.RequireClientOU = "" }, "require_client_ou"},
		"relative root":       {func(c *agent.Config) { c.AllowedRoots = []string{"workspace"} }, "not absolute"},
		"empty listen":        {func(c *agent.Config) { c.Listen = "" }, "listen is empty"},
		"bad log level":       {func(c *agent.Config) { c.Log.Level = "chatty" }, "log.level"},
		"default beyond max": {func(c *agent.Config) {
			c.Exec.DefaultTimeout, c.Exec.MaxTimeout = agent.Duration(time.Hour), agent.Duration(time.Minute)
		}, "exceeds"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base()
			tc.mutate(cfg)
			err := cfg.Validate(agent.ValidateOptions{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// A bare number in a duration field is read as seconds rather than as
// nanoseconds, which is what an operator writing "30" means.
func TestDuration_AcceptsBareSeconds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
tls: {certificate: a.crt, private_key: a.key, ca_bundle: ca.crt}
exec:
  default_timeout: 30
`), 0o600))

	cfg, err := agent.Load(path)
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, cfg.Exec.DefaultTimeout.Duration())
}

func TestDuration_RejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	require.NoError(t, os.WriteFile(path, []byte("exec:\n  default_timeout: soon\n"), 0o600))

	_, err := agent.Load(path)
	require.Error(t, err)
}

// ResolveConfigPath honours the environment override the service unit uses.
func TestResolveConfigPath(t *testing.T) {
	explicit := filepath.Join(t.TempDir(), "custom.yaml")
	got, err := agent.ResolveConfigPath(explicit)
	require.NoError(t, err)
	assert.Equal(t, explicit, got)

	t.Setenv(agent.EnvConfig, "/opt/sandboxd/agent.yaml")
	got, err = agent.ResolveConfigPath("")
	require.NoError(t, err)
	assert.Equal(t, "/opt/sandboxd/agent.yaml", got)
}

// Health reports what Status holds, and Status is only ever atomics.
func TestStatus(t *testing.T) {
	s := agent.NewStatus()

	state, message, running := s.Snapshot()
	assert.Equal(t, sandboxdv1.HealthResponse_STATUS_SERVING, state)
	assert.Empty(t, message)
	assert.Zero(t, running, "with no supervisor registered, the process count is zero rather than unknown")

	s.SetProcessCounter(func() uint32 { return 7 })
	_, _, running = s.Snapshot()
	assert.EqualValues(t, 7, running)

	s.Set(sandboxdv1.HealthResponse_STATUS_DEGRADED, "state directory is unwritable")
	state, message, _ = s.Snapshot()
	assert.Equal(t, sandboxdv1.HealthResponse_STATUS_DEGRADED, state)
	assert.Equal(t, "state directory is unwritable", message)

	s.SetProcessCounter(nil)
	_, _, running = s.Snapshot()
	assert.Zero(t, running)
}

// Status is read on the Health path and written from shutdown and the
// supervisor, so it has to be race-free without a lock.
func TestStatus_ConcurrentAccess(t *testing.T) {
	s := agent.NewStatus()
	done := make(chan struct{})

	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			s.Set(sandboxdv1.HealthResponse_STATUS_SERVING, "")
			s.SetProcessCounter(func() uint32 { return 1 })
		}
	}()
	for i := 0; i < 1000; i++ {
		s.Snapshot()
	}
	<-done

	state, _, running := s.Snapshot()
	assert.Equal(t, sandboxdv1.HealthResponse_STATUS_SERVING, state)
	assert.EqualValues(t, 1, running)
}
