package sandboxdagent_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/agent"
	"github.com/axelmierczuk/sandboxd-mcp/internal/cli/sandboxdagent"
)

// `install` is the step that decides the daemon will run as somebody other than
// the account that enrolled it, so it is the step that has to reconcile the two.
// The material it hands over is the config plus the three TLS files the config
// names — the daemon opens all four before it serves anything, and `enroll`
// writes the config and the key at 0600.
func TestEnrollmentMaterial(t *testing.T) {
	dir := t.TempDir()
	cfg := &agent.Config{TLS: agent.TLSConfig{
		Certificate: filepath.Join(dir, "agent.crt"),
		PrivateKey:  filepath.Join(dir, "agent.key"),
		CABundle:    filepath.Join(dir, "ca.crt"),
	}}
	configPath := filepath.Join(dir, "agent.yaml")

	assert.Equal(t, []string{
		configPath,
		filepath.Join(dir, "agent.crt"),
		filepath.Join(dir, "agent.key"),
		filepath.Join(dir, "ca.crt"),
	}, sandboxdagent.EnrollmentMaterialForTest(cfg, configPath))

	// Unset paths are skipped rather than chowned as "", and a bundle that is
	// the certificate file is listed once.
	same := &agent.Config{TLS: agent.TLSConfig{
		Certificate: filepath.Join(dir, "agent.crt"),
		CABundle:    filepath.Join(dir, "agent.crt"),
	}}
	assert.Equal(t, []string{configPath, filepath.Join(dir, "agent.crt")},
		sandboxdagent.EnrollmentMaterialForTest(same, configPath))
}

// The files can be handed over wherever they live; the directory holding them
// cannot. `--config /etc/agent.yaml` would otherwise make `service install`
// chown /etc to the service account.
func TestEnrollmentDirIsOurs(t *testing.T) {
	assert.True(t, sandboxdagent.EnrollmentDirIsOursForTest(agent.SystemConfigDir()))
	assert.True(t, sandboxdagent.EnrollmentDirIsOursForTest(agent.SystemConfigDir()+string(filepath.Separator)),
		"a trailing separator names the same directory")

	userDir, err := agent.UserConfigDir()
	require.NoError(t, err)
	assert.True(t, sandboxdagent.EnrollmentDirIsOursForTest(userDir))

	for _, dir := range []string{
		filepath.Dir(agent.SystemConfigDir()),
		filepath.Dir(userDir),
		t.TempDir(),
		string(filepath.Separator),
	} {
		assert.False(t, sandboxdagent.EnrollmentDirIsOursForTest(dir),
			"install must not take ownership of %s", dir)
	}
}
