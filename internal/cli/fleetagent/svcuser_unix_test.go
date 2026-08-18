//go:build unix

package fleetagent_test

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/cli/fleetagent"
)

// The failure this closes: `enroll` writes agent.yaml and agent.key at 0600
// into a 0700 directory owned by whoever ran it, `install` points a service at
// them under a *different* account, and the daemon then fails every start on
// "permission denied" opening its own certificate. The one-line install is
// exactly that sequence — enroll as root, install, start.
//
// The handover runs for real here rather than against a mock. Changing a file's
// owner needs privilege, but changing its *group* to one the caller belongs to
// does not — so the material starts out in a group the account does not use and
// the assertion is that the handover moved it.
func TestGrantServiceUserAccess_TakesOwnershipOfTheEnrollmentMaterial(t *testing.T) {
	me, uid, gid := currentAccount(t)
	other := otherGroup(t, gid)

	dir := t.TempDir()
	var files []string
	for _, name := range []string{"agent.yaml", "agent.crt", "agent.key", "ca.crt"} {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))
		chownOrSkip(t, path, uid, other)
		files = append(files, path)
	}
	chownOrSkip(t, dir, uid, other)

	require.NoError(t, fleetagent.GrantServiceUserAccessForTest(me.Username, dir, files))

	for _, path := range append(files, dir) {
		u, g := ownerOf(t, path)
		assert.EqualValues(t, uid, u, "%s must belong to the service account", path)
		assert.EqualValues(t, gid, g,
			"%s was left in the enrolling account's group; the daemon cannot read it as %s", path, me.Username)
	}
}

// A config naming a file that is not there fails the install rather than
// registering a service that cannot start. The error names the file, because
// that is the whole of the diagnosis.
func TestGrantServiceUserAccess_MissingFileIsAnError(t *testing.T) {
	me, _, _ := currentAccount(t)

	missing := filepath.Join(t.TempDir(), "ca.crt")
	err := fleetagent.GrantServiceUserAccessForTest(me.Username, "", []string{missing})
	require.Error(t, err)
	assert.Contains(t, err.Error(), missing)
	assert.Contains(t, err.Error(), me.Username)
}

// An empty directory argument means "the caller judged this directory not ours
// to reassign": the files are still handed over, the directory is untouched.
// That is what keeps `--config /etc/agent.yaml` from chowning /etc.
func TestGrantServiceUserAccess_LeavesAForeignDirectoryAlone(t *testing.T) {
	me, uid, gid := currentAccount(t)
	other := otherGroup(t, gid)

	dir := t.TempDir()
	file := filepath.Join(dir, "agent.yaml")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))
	chownOrSkip(t, file, uid, other)
	chownOrSkip(t, dir, uid, other)

	require.NoError(t, fleetagent.GrantServiceUserAccessForTest(me.Username, "", []string{file}))

	_, fileGid := ownerOf(t, file)
	assert.EqualValues(t, gid, fileGid, "the file is handed over wherever it lives")
	_, dirGid := ownerOf(t, dir)
	assert.EqualValues(t, other, dirGid, "a directory install does not own must not change hands")
}

// TestLinuxServiceUserKeepsAPreRebrandAccount covers the compatibility rule the
// fleet rebrand needed on Linux, and the only one with no other coverage.
//
// The installer creates a dedicated system account and chowns the state and log
// directories to it. A host installed before the rebrand has that account under
// the old name and its directories owned by it, so defaulting to the new name
// would create a *second* system account and hand the running daemon's state
// away from the account running as it.
//
// The lookup is injected because the answer turns on which accounts exist on
// the host, and a test cannot create a system account. That is also why the
// rule is a function taking the lookup rather than three calls inline.
func TestLinuxServiceUserKeepsAPreRebrandAccount(t *testing.T) {
	const (
		current = fleetagent.ServiceUserNameForTest
		legacy  = fleetagent.LegacyServiceUserNameForTest
	)
	require.NotEqual(t, current, legacy, "the rule only means anything if the names differ")

	existing := func(names ...string) func(string) bool {
		set := map[string]bool{}
		for _, n := range names {
			set[n] = true
		}
		return func(name string) bool { return set[name] }
	}

	for _, tc := range []struct {
		name  string
		have  func(string) bool
		want  string
		about string
	}{
		{"a fresh host starts on the new name", existing(), current,
			"nothing to keep, so the account is created under the current name"},
		{"an upgraded host keeps its existing account", existing(legacy), legacy,
			"the state and log directories are owned by this account and the daemon is running as it"},
		{"a migrated host uses the new account", existing(current), current, ""},
		{"both accounts present resolves to the new name", existing(current, legacy), current,
			"an operator who created the new account deliberately gets it; the leftover is theirs to remove"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, fleetagent.LinuxServiceUserForTest(tc.have), tc.about)
		})
	}
}

func currentAccount(t *testing.T) (*user.User, int, int) {
	t.Helper()
	me, err := user.Current()
	require.NoError(t, err)
	uid, err := strconv.Atoi(me.Uid)
	require.NoError(t, err)
	gid, err := strconv.Atoi(me.Gid)
	require.NoError(t, err)
	if uid == 0 {
		t.Skip("the superuser already reads everything, which is the case the handover deliberately skips")
	}
	return me, uid, gid
}

// otherGroup returns a group this account belongs to that is not its primary
// one, so a file can be put somewhere the handover has to move it from.
func otherGroup(t *testing.T, primary int) int {
	t.Helper()
	me, err := user.Current()
	require.NoError(t, err)
	ids, err := me.GroupIds()
	require.NoError(t, err)
	for _, id := range ids {
		gid, err := strconv.Atoi(id)
		if err == nil && gid != primary {
			return gid
		}
	}
	t.Skip("this account has only one group, so there is nowhere to start the files from")
	return 0
}

func chownOrSkip(t *testing.T, path string, uid, gid int) {
	t.Helper()
	if err := os.Chown(path, uid, gid); err != nil {
		t.Skipf("cannot set up the test's starting ownership on %s: %v", path, err)
	}
}

func ownerOf(t *testing.T, path string) (uid, gid uint32) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	return stat.Uid, stat.Gid
}
