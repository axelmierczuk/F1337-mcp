package fleetagent_test

import (
	"bytes"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/cli/fleetagent"
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
	code := fleetagent.Main([]string{"service", "status"}, out)

	require.Equal(t, 0, code, "status must report an absent service rather than erroring: %s", out.String())
	text := out.String()
	assert.Contains(t, text, "fleet-agent")
	assert.True(t,
		strings.Contains(text, "not installed") || strings.Contains(text, "no service manager detected"),
		"status must say plainly what it found, got: %s", text)
}

// Running install without elevation gives an actionable message naming the
// command to re-run, and fails before creating a user or a directory.
func TestServiceInstall_UnprivilegedIsActionable(t *testing.T) {
	if elevated() {
		t.Skip("this test asserts the unprivileged path; the suite is running elevated")
	}

	out := &bytes.Buffer{}
	code := fleetagent.Main([]string{"service", "install"}, out)
	require.Equal(t, 1, code)

	// Cobra writes the error to stderr, which the test cannot capture through
	// Main. Call the command tree directly to inspect the error itself.
	root := fleetagent.NewRootCommand(&bytes.Buffer{})
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
	if elevated() {
		t.Skip("this test asserts the unprivileged path; the suite is running elevated")
	}

	root := fleetagent.NewRootCommand(&bytes.Buffer{})
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
			root := fleetagent.NewRootCommand(&bytes.Buffer{})
			root.SetArgs([]string{"service", verb})
			root.SetErr(&bytes.Buffer{})
			err := root.Execute()
			require.Error(t, err)
			assert.ErrorIs(t, err, fleetagent.ErrNotInstalled)
			assert.Contains(t, err.Error(), "service install")
		})
	}
}

// The service account is never the platform's superuser by default. Every
// command the agent runs inherits this identity, so the default matters more
// than most defaults do.
func TestDefaultServiceUserIsNotASuperuser(t *testing.T) {
	// Skipped only where the default *is* the invoking user: on macOS it is
	// $SUDO_USER or the current account, so running the suite as root makes the
	// answer root by construction rather than by defect. On Windows the default
	// is a fixed built-in identity, so it is asserted there whether the runner
	// is elevated or not — and GitHub's Windows runners are.
	if runtime.GOOS != "windows" && elevated() {
		t.Skip("the default here is the invoking user, which is root in this environment")
	}

	name, err := fleetagent.DefaultServiceUserForTest()
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
	require.Equal(t, 0, fleetagent.Main([]string{"version"}, out))
	assert.Contains(t, out.String(), "fleet-agent")
}

// elevated asks the same question `service install` asks before refusing.
//
// Answering it locally — "windows is never root" — was wrong on the one runner
// where it mattered: GitHub's Windows images run as an administrator, so the
// tests below skipped nothing and then failed against a message written for
// someone who cannot install a service.
func elevated() bool { return fleetagent.IsElevatedForTest() }

// TestLegacyServiceNote covers the one name in the fleet rebrand's
// compatibility matrix that has no rule in code: the service registration.
//
// The two environment variables, the config directory and the directories
// nested inside it, and the Linux service account all resolve the pre-rebrand
// name themselves. A service cannot — removing one is not something a daemon
// should do to a host on its own — so what is left is telling the operator, at
// the moment it matters, that the answer they just got is wrong.
//
// It matters most at `install`: the `service` subcommands address the manager
// by name, so an install on a host still carrying `sandboxd-agent` registers a
// *second* service pointing at the same config and the same state directory,
// and both then re-adopt the same supervised processes. docs/service.md
// describes that outcome; nothing prevented it, and nothing said so.
func TestLegacyServiceNote(t *testing.T) {
	assert.Empty(t, fleetagent.LegacyServiceNoteForTest(false),
		"a host with no pre-rebrand service has nothing to be told")

	note := fleetagent.LegacyServiceNoteForTest(true)
	require.NotEmpty(t, note)

	assert.Contains(t, note, fleetagent.LegacyServiceNameForTest,
		"the note has to name the service that is actually registered, or it is not actionable")
	assert.Contains(t, note, fleetagent.ServiceName,
		"and the name the subcommands do know, so the mismatch is legible")

	// The removal commands, which are the whole of the remedy. Asserted per
	// platform because the wrong platform's commands are worse than none.
	switch runtime.GOOS {
	case "windows":
		assert.Contains(t, note, "sc.exe delete "+fleetagent.LegacyServiceNameForTest)
	case "darwin":
		assert.Contains(t, note, "launchctl bootout system /Library/LaunchDaemons/"+
			fleetagent.LegacyServiceNameForTest+".plist")
	default:
		assert.Contains(t, note, "systemctl disable --now "+fleetagent.LegacyServiceNameForTest)
	}

	// The consequence, not just the fact. An operator who reads "there is an
	// old service" and not "installing now gives you two of them fighting over
	// one state directory" has no reason to stop.
	assert.Contains(t, note, "second service")
	assert.Contains(t, note, "state directory")
}
