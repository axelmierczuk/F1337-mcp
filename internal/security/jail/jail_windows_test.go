package jail_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/security/jail"
)

// These cases need real Windows path semantics — drive letters, the device
// namespace, the case-insensitive filesystem — so they run only on the Windows
// runner. The lexical half of the same rules is covered on every platform by
// TestClassifyWindowsPath in internal/platform, which is why this file can be
// short.

func TestWindows_CaseInsensitivity(t *testing.T) {
	t.Parallel()

	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	root := filepath.Join(base, "root")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "sub", "file"), []byte("x"), 0o644))

	j, err := jail.New(jail.Config{Roots: []string{root}})
	require.NoError(t, err)

	// The same file, spelled in three cases. All three are the same file on a
	// Windows volume, so all three must be admitted.
	for _, path := range []string{
		filepath.Join(root, "sub", "file"),
		strings.ToUpper(filepath.Join(root, "sub", "file")),
		strings.ToLower(filepath.Join(root, "sub", "file")),
	} {
		got, err := j.Resolve(path)
		require.NoErrorf(t, err, "resolving %q", path)
		require.Truef(t, strings.EqualFold(got, filepath.Join(root, "sub", "file")),
			"resolved %q to %q", path, got)
	}

	// A jail whose root was configured in a different case must confine the
	// same directory, not a different one.
	upper, err := jail.New(jail.Config{Roots: []string{strings.ToUpper(root)}})
	require.NoError(t, err)
	_, err = upper.Resolve(filepath.Join(root, "sub", "file"))
	require.NoError(t, err)
}

func TestWindows_RejectedNamespaces(t *testing.T) {
	t.Parallel()

	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	root := filepath.Join(base, "root")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "sub", "file"), []byte("x"), 0o644))

	j, err := jail.New(jail.Config{Roots: []string{root}})
	require.NoError(t, err)

	tests := []struct {
		name string
		path string
	}{
		{
			name: "extended-length prefix on a path that is otherwise inside",
			// Rejected even though it names a file in the jail: \\?\ turns off
			// the normalisation the rest of the path stack assumes, and
			// admitting it means admitting a spelling the checks were not
			// written against.
			path: `\\?\` + filepath.Join(root, "sub", "file"),
		},
		{name: "device namespace", path: `\\.\C:\Windows\System32\config\SAM`},
		{name: "UNC share", path: `\\server\share\file`},
		{name: "UNC share with forward slashes", path: `//server/share/file`},
		{name: "drive-relative", path: `C:sub\file`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := j.Resolve(tc.path)
			require.ErrorIs(t, err, jail.ErrInvalidPath)
		})
	}
}

func TestWindows_RootsInRejectedNamespaces(t *testing.T) {
	t.Parallel()

	for _, root := range []string{`\\server\share`, `\\?\C:\root`, `C:root`} {
		_, err := jail.New(jail.Config{Roots: []string{root}})
		require.Errorf(t, err, "root %q must be refused at construction", root)
	}
}

func TestWindows_ForwardSlashesAreNormalised(t *testing.T) {
	t.Parallel()

	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	root := filepath.Join(base, "root")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "sub", "file"), []byte("x"), 0o644))

	j, err := jail.New(jail.Config{Roots: []string{root}})
	require.NoError(t, err)

	got, err := j.Resolve(strings.ReplaceAll(filepath.Join(root, "sub", "file"), `\`, "/"))
	require.NoError(t, err)
	require.Equal(t, filepath.Join(root, "sub", "file"), got)

	// And the escape still fails when spelled with forward slashes.
	_, err = j.Resolve(strings.ReplaceAll(filepath.Join(root, "..", "outside", "secret"), `\`, "/"))
	require.ErrorIs(t, err, jail.ErrOutsideJail)
}
