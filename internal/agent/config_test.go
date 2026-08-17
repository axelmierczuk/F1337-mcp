package agent_test

import (
	"os"
	"path/filepath"
	"runtime"
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
	assert.Equal(t, "sandboxd-control", cfg.TLS.RequireClientOU)

	// The example is a Linux config, and Load resolves paths against the
	// platform it is running on: "/etc/sandboxd/agent.crt" is an absolute path
	// on Unix and a *relative* one on Windows, where absolute means a drive
	// letter. Load rebasing it there is correct, so the exact strings are
	// asserted only where they mean what the file meant. Everything else in
	// this test — the schema, the defaults, the durations — is what stops the
	// example drifting from the code, and that check runs everywhere.
	if runtime.GOOS != "windows" {
		assert.Equal(t, "/etc/sandboxd/agent.crt", cfg.TLS.Certificate)
		assert.Equal(t, "/etc/sandboxd/agent.key", cfg.TLS.PrivateKey)
		assert.Equal(t, "/etc/sandboxd/ca.crt", cfg.TLS.CABundle)
		assert.Equal(t, []string{"/home/build/workspace", "/tmp/sandboxd"}, cfg.AllowedRoots)
	}
	assert.NotEmpty(t, cfg.TLS.Certificate)
	assert.NotEmpty(t, cfg.TLS.PrivateKey)
	assert.NotEmpty(t, cfg.TLS.CABundle)
	assert.Len(t, cfg.AllowedRoots, 2)

	// The example ships exec on, which is what makes the roots above advisory
	// rather than enforced — the file says so, and this asserts the file is
	// describing the behaviour the code actually has.
	assert.True(t, cfg.Exec.IsEnabled())
	assert.False(t, cfg.JailEnforced())

	// Durations come through as durations, not as nanoseconds.
	assert.Equal(t, 120*time.Second, cfg.Exec.DefaultTimeout.Duration())
	assert.Equal(t, 3600*time.Second, cfg.Exec.MaxTimeout.Duration())
	assert.EqualValues(t, 2097152, cfg.Exec.MaxOutputBytes)

	assert.Equal(t, 32, cfg.Process.MaxConcurrent)
	assert.EqualValues(t, 33554432, cfg.Process.MaxLogBytes)
	assert.Equal(t, 2000, cfg.Process.RingBufferLines)
	assert.Equal(t, 10*time.Second, cfg.Process.DefaultGracePeriod.Duration())
	assert.Equal(t, 60*time.Second, cfg.Process.MaxFollowDuration.Duration())

	assert.True(t, cfg.Audit.Enabled)
	if runtime.GOOS != "windows" {
		assert.Equal(t, "/var/log/sandboxd/audit.jsonl", cfg.Audit.Path)
		// Validate insists allowed_roots are absolute, which the example's are
		// on the platform it was written for.
		require.NoError(t, cfg.Validate(agent.ValidateOptions{}))
	}
	assert.NotEmpty(t, cfg.Audit.Path)
}

// An M0-era config used top-level cert_file / key_file / ca_file. A host
// enrolled before the TLS block existed must still start.
func TestLoad_AcceptsLegacyCertificatePaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")

	// Absolute on every platform, written with forward slashes so it is also
	// valid unquoted YAML: filepath.IsAbs accepts "C:/x" on Windows. Hardcoding
	// POSIX paths here would make the test assert Unix semantics rather than
	// the legacy-alias folding it is actually about.
	abs := func(name string) string { return filepath.ToSlash(filepath.Join(dir, name)) }
	certPath, keyPath, caPath, root := abs("agent.crt"), abs("agent.key"), abs("ca.crt"), abs("workspace")

	require.NoError(t, os.WriteFile(path, []byte(`
name: build-box
listen: "0.0.0.0:8722"
cert_file: "`+certPath+`"
key_file: "`+keyPath+`"
ca_file: "`+caPath+`"
exec:
  enabled: false
allowed_roots:
  - "`+root+`"
`), 0o600))

	cfg, err := agent.Load(path)
	require.NoError(t, err)
	assert.Equal(t, certPath, cfg.TLS.Certificate)
	assert.Equal(t, keyPath, cfg.TLS.PrivateKey)
	assert.Equal(t, caPath, cfg.TLS.CABundle)
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
	// Written out explicitly, like every other default: an operator reading
	// this file must be able to see whether the jail below it is enforced
	// without knowing what the code defaults to.
	assert.Contains(t, string(raw), "enabled: true")

	loaded, err := agent.Load(path)
	require.NoError(t, err)
	assert.Equal(t, cfg.Name, loaded.Name)
	assert.Equal(t, cfg.TLS, loaded.TLS)
	assert.Equal(t, cfg.AllowedRoots, loaded.AllowedRoots)

	// Windows does not carry Unix permission bits, so there is nothing to
	// assert there. (This read runtime.GOOS as an environment variable before,
	// which is never set, so the assertion ran everywhere and happened to pass.)
	if info, err := os.Stat(path); err == nil && runtime.GOOS != "windows" {
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

// An exec-disabled daemon refuses to start with no jail unless the operator
// asked for it by name, and the refusal is matchable so the CLI can explain
// the override.
func TestValidate_EmptyAllowedRoots(t *testing.T) {
	disabled := false
	cfg := &agent.Config{
		Listen: "0.0.0.0:8722",
		TLS: agent.TLSConfig{
			Certificate: "a.crt", PrivateKey: "a.key", CABundle: "ca.crt",
			RequireClientOU: agent.DefaultClientOU,
		},
		Exec: agent.ExecConfig{Enabled: &disabled},
	}

	err := cfg.Validate(agent.ValidateOptions{})
	require.ErrorIs(t, err, agent.ErrNoAllowedRoots)

	require.NoError(t, cfg.Validate(agent.ValidateOptions{AllowNoJail: true}))
}

// With exec enabled the refusal must not fire. There is no jail for
// allowed_roots to be missing from — a caller who can run commands reaches any
// path without FileService — so demanding --no-jail would be demanding a flag
// that changes nothing.
func TestValidate_EmptyAllowedRootsIsFineWhenExecIsEnabled(t *testing.T) {
	cfg := &agent.Config{
		Listen: "0.0.0.0:8722",
		TLS: agent.TLSConfig{
			Certificate: "a.crt", PrivateKey: "a.key", CABundle: "ca.crt",
			RequireClientOU: agent.DefaultClientOU,
		},
	}
	require.True(t, cfg.Exec.IsEnabled(), "exec is on unless the config turns it off")
	require.False(t, cfg.JailEnforced())
	require.NoError(t, cfg.Validate(agent.ValidateOptions{}))
}

// exec.enabled defaults to true, and "enabled: false" is distinguishable from
// a key the operator never wrote.
func TestLoad_ExecEnabledDefaultsToTrue(t *testing.T) {
	write := func(body string) *agent.Config {
		t.Helper()
		path := filepath.Join(t.TempDir(), "agent.yaml")
		require.NoError(t, os.WriteFile(path, []byte(
			"tls: {certificate: a.crt, private_key: a.key, ca_bundle: ca.crt}\n"+body), 0o600))
		cfg, err := agent.Load(path)
		require.NoError(t, err)
		return cfg
	}

	omitted := write("")
	assert.True(t, omitted.Exec.IsEnabled())
	assert.False(t, omitted.JailEnforced())

	off := write("exec:\n  enabled: false\n")
	assert.False(t, off.Exec.IsEnabled())
	assert.True(t, off.JailEnforced(), "exec disabled is the one configuration where the jail is real")

	on := write("exec:\n  enabled: true\n")
	assert.True(t, on.Exec.IsEnabled())
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
