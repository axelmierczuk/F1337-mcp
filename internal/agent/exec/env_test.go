package exec

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// allowlist is every variable the base environment is documented to carry on
// this platform, assembled from the same lists buildBaseEnv reads.
//
// Built from those lists rather than written out again on purpose: a test
// holding its own copy of the answer passes when someone adds a name to the
// package and forgets the test, which is the direction that matters. What this
// pins down is the shape — PATH always, the named variables when the daemon has
// them, and nothing else at all — not the spelling of any one entry.
func allowlist() []string {
	names := []string{"PATH", homeVar}
	names = append(names, tempVars...)
	names = append(names, localeVars...)
	names = append(names, basePassthrough...)
	slices.Sort(names)
	return slices.Compact(names)
}

// The base environment carries the allowlist and nothing else.
//
// buildBaseEnv takes its lookup as an argument for exactly this: the Windows
// list is the long one, and asserting it only on Windows means asserting it
// only where it is already too late to find out. The daemon environment here
// holds one of everything — the allowlisted names, and the credentials a real
// installer leaves behind.
func TestBuildBaseEnv_CarriesTheAllowlistAndNothingElse(t *testing.T) {
	const credential = "ghp_pretend-this-is-real"

	daemon := map[string]string{
		// What must not survive: the reason this package builds an environment
		// instead of inheriting one.
		"GITHUB_TOKEN":          credential,
		"AWS_SECRET_ACCESS_KEY": credential,
		"FLEET_ENROLL_TOKEN": credential,
		"NPM_TOKEN":             credential,
		"SSH_AUTH_SOCK":         "/tmp/ssh-agent.sock",
		"USER":                  "whoever-installed-the-service",
	}
	for _, name := range allowlist() {
		daemon[name] = "value-of-" + name
	}

	base := buildBaseEnv(func(name string) string { return daemon[name] })

	got := map[string]string{}
	for _, entry := range base {
		name, value, ok := strings.Cut(entry, "=")
		require.Truef(t, ok, "entry %q is not KEY=VALUE", entry)
		require.NotContainsf(t, got, name, "%s appears twice; execve would carry both and the winner is whichever the libc scan finds first", name)
		got[name] = value
	}

	for _, name := range allowlist() {
		require.Equalf(t, "value-of-"+name, got[name], "%s is documented as passed through when the daemon has it", name)
	}
	require.Len(t, got, len(allowlist()),
		"the base is an allowlist: anything the daemon holds that is not on it must not reach a command")

	for _, entry := range base {
		require.NotContains(t, entry, credential,
			"the daemon's environment holds whatever installed the service, and handing that to every command is a credential leak with a remote trigger")
	}
}

// A daemon started with nothing gets a PATH and no inventions.
//
// systemd starts a unit with an empty environment unless the unit says
// otherwise, so this is the ordinary case on a Linux host rather than a corner
// one: PATH falls back to the platform default, because nothing runs without
// one, and no other variable is conjured out of a default that does not
// describe the host.
func TestBuildBaseEnv_FallsBackToAPlatformPathAndInventsNothingElse(t *testing.T) {
	base := buildBaseEnv(func(string) string { return "" })

	path, ok := envValue(base, "PATH")
	require.True(t, ok, "PATH, or nothing runs")
	require.Equal(t, defaultPath, path)

	for _, entry := range base {
		name, _, _ := strings.Cut(entry, "=")
		// homeVar is the one other entry that may appear: baseHome falls back
		// to os.UserHomeDir, which has a source other than the variable on
		// some platforms. A locale is never invented, and neither is a TMPDIR.
		require.Containsf(t, []string{"PATH", homeVar}, name,
			"%s was not in the daemon's environment and must not be invented", name)
	}
}

// A request entry replaces the base entry of the same name rather than joining
// it, and the platform decides whether the names fold.
func TestMergeEnv_ReplacesRatherThanAppends(t *testing.T) {
	base := []string{"PATH=/base/bin", homeVar + "=/home/base"}

	merged, err := mergeEnv(base, []string{"PATH=/mine/bin", "EXTRA=1"})
	require.NoError(t, err)

	path, ok := envValue(merged, "PATH")
	require.True(t, ok)
	require.Equal(t, "/mine/bin", path)
	require.Len(t, merged, 3, "PATH was replaced, not appended beside the base one")

	// Case folding follows the platform's environment, not Go's map semantics:
	// on Windows "path" and "PATH" are one variable, on Unix they are two.
	folded, err := mergeEnv(base, []string{"path=/folded/bin"})
	require.NoError(t, err)
	if caseInsensitiveEnv {
		require.Len(t, folded, 2, "the Windows environment block is case-insensitive")
	} else {
		require.Len(t, folded, 3, "PATH and path are two variables on Unix, and execve carries both")
	}
}
