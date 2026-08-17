package agent_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

// No jail is a state with its own constructor, never what an empty slice
// decays into. "Confine to nothing" and "confine to everything" are one typo
// apart and only one of them may be arrived at by accident.
func TestJail_EmptyRootsIsRefused(t *testing.T) {
	for name, roots := range map[string][]string{
		"nil":            nil,
		"empty slice":    {},
		"empty strings":  {"", ""},
		"blank strings":  {"   "},
		"mixed emptines": {"", "  "},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := agent.NewJail(roots)
			require.ErrorIs(t, err, agent.ErrNoRoots,
				"an empty root list must not silently produce a jail that permits everything")
		})
	}
}

// Unconfined is the explicit no-jail state: reportable, and still normalising.
func TestJail_UnconfinedIsExplicit(t *testing.T) {
	j := agent.Unconfined()
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
	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	root := filepath.Join(base, "not-yet")

	j, err := agent.NewJail([]string{root})
	require.NoError(t, err)
	assert.True(t, j.Enabled())
	assert.Equal(t, []string{filepath.Clean(root)}, j.Roots())
}

// A root that does not exist yet is still resolved as far as it does exist.
//
// Keeping it lexical is what breaks the shipped example config on macOS: /tmp
// is a symlink to /private/tmp, so a configured root of /tmp/sandboxd stays
// "/tmp/sandboxd" while every path under it resolves to "/private/tmp/..." —
// and the jail then refuses every path under its own root. The symlinked
// parent here stands in for /tmp.
func TestJail_LateCreatedRootUnderSymlinkedParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs elevation or developer mode on Windows")
	}

	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	target := filepath.Join(base, "target")
	require.NoError(t, os.MkdirAll(target, 0o755))
	link := filepath.Join(base, "link")
	require.NoError(t, os.Symlink(target, link))

	// Configured before the directory exists, exactly as an installer does.
	root := filepath.Join(link, "workspace")
	j, err := agent.NewJail([]string{root})
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join(target, "workspace")}, j.Roots(),
		"a not-yet-existing root must be resolved through the symlinks above it")

	// The operator creates it afterwards.
	require.NoError(t, os.MkdirAll(filepath.Join(target, "workspace"), 0o755))

	got, err := j.Resolve(filepath.Join(root, "file.txt"))
	require.NoError(t, err, "the jail must not refuse a path under its own configured root")
	assert.Equal(t, filepath.Join(target, "workspace", "file.txt"), got)

	// And it still refuses everything outside.
	_, err = j.Resolve(filepath.Join(target, "elsewhere"))
	require.ErrorIs(t, err, agent.ErrOutsideJail)
}

// Windows case folding is ASCII-only, and this is asserted from any runner
// because the failure it prevents cannot be reproduced on a case-sensitive
// platform.
//
// Unicode simple folding — what strings.EqualFold and strings.ToLower do —
// treats U+212A KELVIN SIGN as equal to "k". Under it a root of C:\workspace
// contains C:\wor<U+212A>space, which Windows treats as an entirely different
// directory: the containment check admits a path outside the jail.
func TestJail_WindowsCaseFoldIsASCIIOnly(t *testing.T) {
	const kelvin = "\u212A"

	require.True(t, strings.EqualFold(`C:\WORKSPACE\`, `c:\wor`+kelvin+`space\`),
		"guard: if Go's Unicode folding stops treating U+212A as K this test is testing nothing")

	assert.True(t, agent.EqualPathFoldForTest(`C:\WORKSPACE\`, `c:\workspace\`, true),
		"ASCII case must still fold, or no Windows path matches its own root")
	assert.False(t, agent.EqualPathFoldForTest(`C:\workspace\`, `c:\wor`+kelvin+`space\`, true),
		"a directory that merely Unicode-folds to the root's name is not inside the root")

	// And with folding off, ASCII case is significant.
	assert.False(t, agent.EqualPathFoldForTest("/Workspace", "/workspace", false))
	assert.True(t, agent.EqualPathFoldForTest("/workspace", "/workspace", false))
}

// The Windows namespaces are refused deliberately rather than failing every
// containment check for reasons nobody chose.
func TestJail_WindowsPathClassification(t *testing.T) {
	for path, want := range map[string]string{
		`C:\root\sub`:      "local",
		`c:/root/sub`:      "local",
		`\\?\C:\root`:      "device",
		`\\.\PhysicalDisk`: "device",
		`\\server\share\x`: "UNC",
		`C:work`:           "invalid",
		`work\sub`:         "relative",
		`\rooted`:          "relative",
		``:                 "invalid",
	} {
		assert.Equal(t, want, agent.ClassifyWindowsPathForTest(path), path)
	}
}

// On Windows those namespaces are refused by name, at construction and on
// every resolve.
func TestJail_RefusesWindowsNamespaces(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the namespaces only exist on Windows; the classifier is asserted on every platform above")
	}

	_, err := agent.NewJail([]string{`\\server\share\workspace`})
	require.ErrorIs(t, err, agent.ErrPathNamespace)

	j, err := agent.NewJail([]string{t.TempDir()})
	require.NoError(t, err)
	for _, path := range []string{`\\?\C:\Windows\System32`, `\\server\share\x`, `C:work`} {
		_, err := j.Resolve(path)
		require.ErrorIs(t, err, agent.ErrPathNamespace, path)
	}
}

func absRoot() string {
	if runtime.GOOS == "windows" {
		return `C:\workspace`
	}
	return "/workspace"
}
