package sandboxdagent_test

import (
	"bytes"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/cli/sandboxdagent"
)

// Installing and uninstalling a service needs root, so CI cannot run those
// paths. What CI can run is everything that decides what would be installed —
// unit rendering (unit_test.go), the elevation check, and the answers the
// read-only commands give — plus the guarantee that the ones needing root fail
// before they touch anything.
//
// The steps that genuinely need root are written up in docs/service.md.

// `status` on a host with no service registered reports that clearly and
// exits zero. An installer script branches on this, and so does an operator.
func TestServiceStatus_NotInstalled(t *testing.T) {
	out := &bytes.Buffer{}
	code := sandboxdagent.Main([]string{"service", "status"}, out)

	require.Equal(t, 0, code, "status must report an absent service rather than erroring: %s", out.String())
	text := out.String()
	assert.Contains(t, text, "sandboxd-agent")
	assert.True(t,
		strings.Contains(text, "not installed") || strings.Contains(text, "no service manager detected"),
		"status must say plainly what it found, got: %s", text)
}

// Running install without elevation gives an actionable message naming the
// command to re-run, and fails before creating a user or a directory.
func TestServiceInstall_UnprivilegedIsActionable(t *testing.T) {
	if isRoot() {
		t.Skip("this test asserts the unprivileged path; the suite is running as root")
	}

	out := &bytes.Buffer{}
	code := sandboxdagent.Main([]string{"service", "install"}, out)
	require.Equal(t, 1, code)

	// Cobra writes the error to stderr, which the test cannot capture through
	// Main. Call the command tree directly to inspect the error itself.
	root := sandboxdagent.NewRootCommand(&bytes.Buffer{})
	root.SetArgs([]string{"service", "install"})
	root.SetErr(&bytes.Buffer{})
	err := root.Execute()
	require.Error(t, err)

	msg := err.Error()
	if runtime.GOOS == "windows" {
		assert.Contains(t, msg, "elevated")
		assert.Contains(t, msg, "RunAs")
	} else {
		assert.Contains(t, msg, "needs root")
		assert.Contains(t, msg, "sudo")
	}
	assert.Contains(t, msg, "service install", "the message must name the command to re-run")
}

// Uninstall is elevation-gated on the same terms, and says so before touching
// anything.
func TestServiceUninstall_UnprivilegedIsActionable(t *testing.T) {
	if isRoot() {
		t.Skip("this test asserts the unprivileged path; the suite is running as root")
	}

	root := sandboxdagent.NewRootCommand(&bytes.Buffer{})
	root.SetArgs([]string{"service", "uninstall"})
	root.SetErr(&bytes.Buffer{})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "service uninstall")
}

// start, stop and restart on an unregistered service report that rather than
// producing a service-manager error the operator has to decode.
func TestServiceControl_NotInstalled(t *testing.T) {
	for _, verb := range []string{"start", "stop", "restart"} {
		t.Run(verb, func(t *testing.T) {
			root := sandboxdagent.NewRootCommand(&bytes.Buffer{})
			root.SetArgs([]string{"service", verb})
			root.SetErr(&bytes.Buffer{})
			err := root.Execute()
			require.Error(t, err)
			assert.ErrorIs(t, err, sandboxdagent.ErrNotInstalled)
			assert.Contains(t, err.Error(), "service install")
		})
	}
}

// The service account is never the platform's superuser by default. Every
// command the agent runs inherits this identity, so the default matters more
// than most defaults do.
func TestDefaultServiceUserIsNotASuperuser(t *testing.T) {
	if isRoot() {
		t.Skip("the macOS default is the invoking user, which is root in this environment")
	}

	name, err := sandboxdagent.DefaultServiceUserForTest()
	require.NoError(t, err)
	require.NotEmpty(t, name)

	for _, superuser := range []string{"root", "localsystem", `nt authority\system`} {
		assert.NotEqual(t, superuser, strings.ToLower(name),
			"the service account must never default to a superuser")
	}
}

// `version` prints something identifiable, on every platform.
func TestVersionCommand(t *testing.T) {
	out := &bytes.Buffer{}
	require.Equal(t, 0, sandboxdagent.Main([]string{"version"}, out))
	assert.Contains(t, out.String(), "sandboxd-agent")
}

func isRoot() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	return os.Geteuid() == 0
}
