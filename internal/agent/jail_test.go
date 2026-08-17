package agent_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/agent"
)

// These cover the provisional jail in internal/agent/jail.go. Issue #6 owns
// the real implementation; when it lands, these move with it and the case
// below that matters most — a symlink out of the jail — is the one to keep.

func TestJail_ContainsAndRejects(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, os.MkdirAll(filepath.Join(root, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "sub", "file"), []byte("x"), 0o600))

	j, err := agent.NewJail([]string{root})
	require.NoError(t, err)
	require.True(t, j.Enabled())

	got, err := j.Resolve(filepath.Join(root, "sub", "file"))
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(root, "sub", "file"), got)

	// The root itself is contained by itself.
	got, err = j.Resolve(root)
	require.NoError(t, err)
	assert.Equal(t, root, got)

	// A file that does not exist yet, in a directory that does: this is every
	// write of a new file, and it must be allowed.
	got, err = j.Resolve(filepath.Join(root, "sub", "new.txt"))
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(root, "sub", "new.txt"), got)

	// Somewhere else entirely.
	_, err = j.Resolve(filepath.Join(os.TempDir(), "elsewhere"))
	require.ErrorIs(t, err, agent.ErrOutsideJail)
}

// The case the naive implementation gets wrong: a symlink inside the jail
// whose target is outside it. Rejecting ".." before resolution would let this
// straight through.
func TestJail_SymlinkOutOfJailIsRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs elevation or developer mode on Windows")
	}

	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)

	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	require.NoError(t, os.MkdirAll(root, 0o755))
	require.NoError(t, os.MkdirAll(outside, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret"), []byte("s"), 0o600))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "link")))

	j, err := agent.NewJail([]string{root})
	require.NoError(t, err)

	_, err = j.Resolve(filepath.Join(root, "link", "secret"))
	require.ErrorIs(t, err, agent.ErrOutsideJail,
		"a symlink inside the jail pointing outside it must not be a way out")

	// Creating a new file through that symlink is the same escape.
	_, err = j.Resolve(filepath.Join(root, "link", "new.txt"))
	require.ErrorIs(t, err, agent.ErrOutsideJail)
}

// A symlink whose target is inside the jail resolves and is allowed.
func TestJail_SymlinkInsideJailIsAllowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs elevation or developer mode on Windows")
	}

	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(base, "real"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(base, "real", "file"), []byte("x"), 0o600))
	require.NoError(t, os.Symlink(filepath.Join(base, "real"), filepath.Join(base, "link")))

	j, err := agent.NewJail([]string{base})
	require.NoError(t, err)

	got, err := j.Resolve(filepath.Join(base, "link", "file"))
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(base, "real", "file"), got,
		"the resolved path must be the real one, since that is what the caller will open")
}

// A dangling symlink is an error, not a panic and not an allow.
func TestJail_DanglingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs elevation or developer mode on Windows")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, os.Symlink(filepath.Join(base, "gone"), filepath.Join(base, "dangling")))

	j, err := agent.NewJail([]string{base})
	require.NoError(t, err)

	_, err = j.Resolve(filepath.Join(base, "dangling"))
	require.Error(t, err)
}

// Containment is on component boundaries: a sibling with the root as a string
// prefix is outside.
func TestJail_PrefixIsNotContainment(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	root := filepath.Join(base, "workspace")
	sibling := filepath.Join(base, "workspace-old")
	require.NoError(t, os.MkdirAll(root, 0o755))
	require.NoError(t, os.MkdirAll(sibling, 0o755))

	j, err := agent.NewJail([]string{root})
	require.NoError(t, err)

	_, err = j.Resolve(filepath.Join(sibling, "file"))
	require.ErrorIs(t, err, agent.ErrOutsideJail)
}

// Containment in any one root is enough.
func TestJail_MultipleRoots(t *testing.T) {
	a, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	b, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)

	j, err := agent.NewJail([]string{a, b})
	require.NoError(t, err)

	for _, root := range []string{a, b} {
		_, err := j.Resolve(filepath.Join(root, "file"))
		require.NoError(t, err)
	}
	assert.Len(t, j.Roots(), 2)
}

// No roots is an explicit, reportable "no jail" state — never an accidental
// allow-all that reads as confinement.
func TestJail_EmptyRootsIsExplicitlyDisabled(t *testing.T) {
	j, err := agent.NewJail(nil)
	require.NoError(t, err)
	assert.False(t, j.Enabled())
	assert.Empty(t, j.Roots())

	// It still resolves, because downstream services call Resolve
	// unconditionally.
	got, err := j.Resolve(os.TempDir())
	require.NoError(t, err)
	assert.NotEmpty(t, got)
}

func TestJail_RejectsEmptyPath(t *testing.T) {
	j, err := agent.NewJail([]string{t.TempDir()})
	require.NoError(t, err)
	_, err = j.Resolve("  ")
	require.Error(t, err)
}

// A root that does not exist yet is kept, because an installer may name a
// workspace the operator creates afterwards.
func TestJail_NonExistentRootIsKept(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-yet")
	j, err := agent.NewJail([]string{root})
	require.NoError(t, err)
	assert.True(t, j.Enabled())
	assert.Equal(t, []string{filepath.Clean(root)}, j.Roots())
}

func absRoot() string {
	if runtime.GOOS == "windows" {
		return `C:\workspace`
	}
	return "/workspace"
}
