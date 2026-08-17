package jail_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/security/jail"
)

// tree is a fixture filesystem shared by most tests here:
//
//	<base>/root/               the jail root
//	<base>/root/sub/file       an ordinary file
//	<base>/root/notes.txt      an ordinary file
//	<base>/root/inner    -> <base>/root/sub      symlink staying inside
//	<base>/root/escape   -> <base>/outside       symlink leaving the jail
//	<base>/root/dangling -> <base>/root/missing  symlink to nothing
//	<base>/outside/secret      the file a caller must not reach
type tree struct {
	root    string // resolved
	outside string // resolved
}

func newTree(t *testing.T) tree {
	t.Helper()

	// t.TempDir sits under /var on macOS, which is itself a symlink to
	// /private/var. Resolve the base once so expectations are written in the
	// same form the jail will return.
	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)

	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "sub"), 0o755))
	require.NoError(t, os.MkdirAll(outside, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "sub", "file"), []byte("inside"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "notes.txt"), []byte("notes"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret"), []byte("secret"), 0o644))

	symlink(t, filepath.Join(root, "sub"), filepath.Join(root, "inner"))
	symlink(t, outside, filepath.Join(root, "escape"))
	symlink(t, filepath.Join(root, "missing"), filepath.Join(root, "dangling"))

	return tree{root: root, outside: outside}
}

// symlink creates a symlink, skipping the test on a platform or account that
// cannot. Unprivileged symlink creation on Windows needs Developer Mode; a
// skip here is honest, and the Windows-specific path behaviour is covered by
// jail_windows_test.go, which needs no symlinks.
func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("cannot create symlinks on this Windows host (needs Developer Mode or admin): %v", err)
		}
		t.Fatalf("creating symlink %s -> %s: %v", link, target, err)
	}
}

func TestResolve(t *testing.T) {
	t.Parallel()
	tr := newTree(t)

	j, err := jail.New(jail.Config{Roots: []string{tr.root}})
	require.NoError(t, err)

	tests := []struct {
		name string
		path string
		// want is the expected resolved path; empty means the case must fail.
		want    string
		wantErr error
		why     string
	}{
		{
			name: "file under the root",
			path: filepath.Join(tr.root, "sub", "file"),
			want: filepath.Join(tr.root, "sub", "file"),
		},
		{
			name: "the root itself",
			path: tr.root,
			want: tr.root,
		},
		{
			name:    "dot-dot climbing out",
			path:    filepath.Join(tr.root, "..", "outside", "secret"),
			wantErr: jail.ErrOutsideJail,
			why:     "Clean turns this into an absolute path outside the root; containment refuses it",
		},
		{
			name:    "symlink pointing out of the jail",
			path:    filepath.Join(tr.root, "escape", "secret"),
			wantErr: jail.ErrOutsideJail,
			why:     "the case a lexical .. check gets wrong: no .. appears anywhere in this path",
		},
		{
			name: "symlink pointing inside the jail",
			path: filepath.Join(tr.root, "inner", "file"),
			want: filepath.Join(tr.root, "sub", "file"),
			why:  "allowed, and returned in its resolved form rather than as requested",
		},
		{
			name:    "dangling symlink",
			path:    filepath.Join(tr.root, "dangling"),
			wantErr: jail.ErrDanglingSymlink,
		},
		{
			name:    "path through a dangling symlink",
			path:    filepath.Join(tr.root, "dangling", "child"),
			wantErr: jail.ErrDanglingSymlink,
		},
		{
			name: "new file in an existing allowed directory",
			path: filepath.Join(tr.root, "sub", "created.txt"),
			want: filepath.Join(tr.root, "sub", "created.txt"),
			why:  "the write path: nothing exists at the leaf, the anchor is its parent",
		},
		{
			name: "new file several levels below anything that exists",
			path: filepath.Join(tr.root, "a", "b", "c", "d.txt"),
			want: filepath.Join(tr.root, "a", "b", "c", "d.txt"),
		},
		{
			name:    "new file whose parent is a symlink out of the jail",
			path:    filepath.Join(tr.root, "escape", "created.txt"),
			wantErr: jail.ErrOutsideJail,
			why:     "the anchor is the symlink target, which is outside",
		},
		{
			name:    "existing file outside the jail",
			path:    filepath.Join(tr.outside, "secret"),
			wantErr: jail.ErrOutsideJail,
		},
		{
			name:    "new file outside the jail",
			path:    filepath.Join(tr.outside, "created.txt"),
			wantErr: jail.ErrOutsideJail,
		},
		{
			name: "path under a regular file",
			path: filepath.Join(tr.root, "notes.txt", "child"),
			want: filepath.Join(tr.root, "notes.txt", "child"),
			why: "contained, so the jail permits it; the syscall that follows fails with " +
				"ENOTDIR, which is the caller's answer to give",
		},
		{
			name: "relative path against the working directory",
			path: filepath.Join("sub", "file"),
			want: filepath.Join(tr.root, "sub", "file"),
		},
		{
			name:    "relative path climbing out",
			path:    filepath.Join("..", "outside", "secret"),
			wantErr: jail.ErrOutsideJail,
		},
		{
			name:    "empty path",
			path:    "",
			wantErr: jail.ErrInvalidPath,
		},
		{
			name: "redundant separators and dots",
			path: filepath.Join(tr.root, ".", "sub", "..", "sub", "file"),
			want: filepath.Join(tr.root, "sub", "file"),
		},
		{
			name: "dot-dot after an escaping symlink is collapsed lexically",
			path: filepath.Join(tr.root, "escape", "..", "sub", "file"),
			want: filepath.Join(tr.root, "sub", "file"),
			why: "Clean turns escape/.. into nothing, so this never touches the symlink; " +
				"the file returned is inside the jail and is the file the caller will open",
		},
		{
			name:    "dot-dot after an escaping symlink cannot climb out either",
			path:    filepath.Join(tr.root, "escape", "..", "..", "outside", "secret"),
			wantErr: jail.ErrOutsideJail,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := j.Resolve(tc.path)

			if tc.wantErr != nil {
				require.ErrorIsf(t, err, tc.wantErr, "resolved to %q; %s", got, tc.why)
				require.Empty(t, got)
				return
			}
			require.NoErrorf(t, err, "%s", tc.why)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestResolve_SiblingSharingAPrefix is the string-prefix bug: "/x/rootabc"
// starts with "/x/root" and is not beneath it.
func TestResolve_SiblingSharingAPrefix(t *testing.T) {
	t.Parallel()

	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	root := filepath.Join(base, "root")
	sibling := filepath.Join(base, "rootabc")
	require.NoError(t, os.Mkdir(root, 0o755))
	require.NoError(t, os.Mkdir(sibling, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(sibling, "file"), []byte("x"), 0o644))

	j, err := jail.New(jail.Config{Roots: []string{root}})
	require.NoError(t, err)

	_, err = j.Resolve(filepath.Join(sibling, "file"))
	require.ErrorIs(t, err, jail.ErrOutsideJail)
}

func TestResolve_MultipleRoots(t *testing.T) {
	t.Parallel()

	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	first := filepath.Join(base, "first")
	second := filepath.Join(base, "second")
	third := filepath.Join(base, "third")
	for _, dir := range []string{first, second, third} {
		require.NoError(t, os.Mkdir(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "file"), []byte("x"), 0o644))
	}

	j, err := jail.New(jail.Config{Roots: []string{first, second}})
	require.NoError(t, err)

	// Containment in any one root is sufficient.
	for _, dir := range []string{first, second} {
		got, err := j.Resolve(filepath.Join(dir, "file"))
		require.NoError(t, err)
		require.Equal(t, filepath.Join(dir, "file"), got)
	}

	_, err = j.Resolve(filepath.Join(third, "file"))
	require.ErrorIs(t, err, jail.ErrOutsideJail)

	require.Equal(t, []string{first, second}, j.Roots())
	require.Equal(t, first, j.WorkingDir(), "the working directory defaults to the first root")
}

func TestResolve_DuplicateRootsAreCollapsed(t *testing.T) {
	t.Parallel()

	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	root := filepath.Join(base, "root")
	require.NoError(t, os.Mkdir(root, 0o755))

	j, err := jail.New(jail.Config{Roots: []string{root, root + string(filepath.Separator), filepath.Join(root, "sub", "..")}})
	require.NoError(t, err)
	require.Len(t, j.Roots(), 1)
	require.Len(t, j.ConfiguredRoots(), 3, "the operator's spelling is preserved for reporting")
}

// TestNew_NoRoots covers the criterion that an empty root list is a distinct,
// explicit state and never an accidental allow-all.
func TestNew_NoRoots(t *testing.T) {
	t.Parallel()

	for _, roots := range [][]string{nil, {}} {
		j, err := jail.New(jail.Config{Roots: roots})
		require.ErrorIs(t, err, jail.ErrNoRoots)
		require.Nil(t, j)
	}
}

// TestUnconstructedJailRefusesEverything covers the other half of that
// criterion: the paths to a permissive jail that do not go through New.
func TestUnconstructedJailRefusesEverything(t *testing.T) {
	t.Parallel()

	var zero jail.Jail
	var null *jail.Jail

	for name, j := range map[string]*jail.Jail{"zero value": &zero, "nil pointer": null} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := j.Resolve(filepath.Join(string(filepath.Separator), "etc", "passwd"))
			require.ErrorIs(t, err, jail.ErrNotConfigured)

			_, err = j.OpenFile("anything", os.O_RDONLY, 0)
			require.ErrorIs(t, err, jail.ErrNotConfigured)

			require.False(t, j.Configured())
			require.False(t, j.Confined())
			require.False(t, j.ContainsResolved(string(filepath.Separator)))
			require.Empty(t, j.Roots())
			require.Empty(t, j.WorkingDir())
		})
	}
}

func TestUnconfined(t *testing.T) {
	t.Parallel()
	tr := newTree(t)

	j := jail.Unconfined()
	require.True(t, j.Configured())
	require.False(t, j.Confined(), "an unconfined jail must not claim to be confining anything")
	require.Empty(t, j.Roots(), "reported as no allowed roots, matching the proto's meaning of the empty list")

	got, err := j.Resolve(filepath.Join(tr.outside, "secret"))
	require.NoError(t, err)
	require.Equal(t, filepath.Join(tr.outside, "secret"), got)

	// Still normalises: callers depend on getting an absolute, clean path.
	got, err = j.Resolve(filepath.Join(tr.root, "sub", "..", "sub", "file"))
	require.NoError(t, err)
	require.Equal(t, filepath.Join(tr.root, "sub", "file"), got)

	require.True(t, j.ContainsResolved(filepath.Join(tr.outside, "secret")))
	require.False(t, j.Atomic(), "there is nothing to be atomic about without a root to stay beneath")
}

func TestNew_RootValidation(t *testing.T) {
	t.Parallel()

	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	file := filepath.Join(base, "afile")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))

	tests := []struct {
		name string
		root string
	}{
		{"missing", filepath.Join(base, "nope")},
		{"a regular file", file},
		{"relative", "relative/path"},
		{"empty", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := jail.New(jail.Config{Roots: []string{tc.root}})
			require.Error(t, err)
		})
	}
}

// TestNew_RootIsItselfASymlink checks that roots are resolved too. Comparing a
// resolved path against an unresolved root would refuse every legitimate path
// under a symlinked root.
func TestNew_RootIsItselfASymlink(t *testing.T) {
	t.Parallel()

	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	target := filepath.Join(base, "target")
	link := filepath.Join(base, "link")
	require.NoError(t, os.Mkdir(target, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(target, "file"), []byte("x"), 0o644))
	symlink(t, target, link)

	j, err := jail.New(jail.Config{Roots: []string{link}})
	require.NoError(t, err)
	require.Equal(t, []string{target}, j.Roots())
	require.Equal(t, []string{link}, j.ConfiguredRoots())

	for _, path := range []string{filepath.Join(link, "file"), filepath.Join(target, "file")} {
		got, err := j.Resolve(path)
		require.NoError(t, err)
		require.Equal(t, filepath.Join(target, "file"), got)
	}
}

func TestConfig_WorkingDir(t *testing.T) {
	t.Parallel()
	tr := newTree(t)

	j, err := jail.New(jail.Config{Roots: []string{tr.root}, WorkingDir: filepath.Join(tr.root, "sub")})
	require.NoError(t, err)
	require.Equal(t, filepath.Join(tr.root, "sub"), j.WorkingDir())

	got, err := j.Resolve("file")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(tr.root, "sub", "file"), got)

	// A working directory outside the jail is allowed but makes every relative
	// path fail containment, which is the correct answer.
	outsideWD, err := jail.New(jail.Config{Roots: []string{tr.root}, WorkingDir: tr.outside})
	require.NoError(t, err)
	_, err = outsideWD.Resolve("secret")
	require.ErrorIs(t, err, jail.ErrOutsideJail)
}

func TestOpenFile(t *testing.T) {
	t.Parallel()
	tr := newTree(t)

	j, err := jail.New(jail.Config{Roots: []string{tr.root}})
	require.NoError(t, err)

	t.Run("reads an existing file", func(t *testing.T) {
		f, err := j.OpenFile(filepath.Join(tr.root, "sub", "file"), os.O_RDONLY, 0)
		require.NoError(t, err)
		defer f.Close()

		buf := make([]byte, 6)
		n, err := f.Read(buf)
		require.NoError(t, err)
		require.Equal(t, "inside", string(buf[:n]))
	})

	t.Run("creates a new file", func(t *testing.T) {
		path := filepath.Join(tr.root, "sub", "created-by-open.txt")
		f, err := j.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
		require.NoError(t, err)
		_, err = f.WriteString("written")
		require.NoError(t, err)
		require.NoError(t, f.Close())

		content, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, "written", string(content))
	})

	t.Run("opens the root itself", func(t *testing.T) {
		f, err := j.OpenFile(tr.root, os.O_RDONLY, 0)
		require.NoError(t, err)
		require.NoError(t, f.Close())
	})

	t.Run("refuses a path outside the jail", func(t *testing.T) {
		_, err := j.OpenFile(filepath.Join(tr.outside, "secret"), os.O_RDONLY, 0)
		require.ErrorIs(t, err, jail.ErrOutsideJail)
	})

	t.Run("refuses a symlink out of the jail", func(t *testing.T) {
		_, err := j.OpenFile(filepath.Join(tr.root, "escape", "secret"), os.O_RDONLY, 0)
		require.ErrorIs(t, err, jail.ErrOutsideJail)
	})
}

// TestAtomic pins the claim OpenFile makes about itself to the platform it is
// running on, so the guarantee reported in sandbox_info cannot drift from the
// implementation.
func TestAtomic(t *testing.T) {
	t.Parallel()
	tr := newTree(t)

	j, err := jail.New(jail.Config{Roots: []string{tr.root}})
	require.NoError(t, err)

	if runtime.GOOS != "linux" {
		require.False(t, j.Atomic(), "only Linux has openat2(RESOLVE_BENEATH)")
		return
	}
	// On Linux the answer depends on the kernel and on seccomp, so both are
	// legitimate; what must hold is that opening still works either way.
	t.Logf("atomic open available: %v", j.Atomic())
	f, err := j.OpenFile(filepath.Join(tr.root, "sub", "file"), os.O_RDONLY, 0)
	require.NoError(t, err)
	require.NoError(t, f.Close())
}

func TestPathError(t *testing.T) {
	t.Parallel()
	tr := newTree(t)

	j, err := jail.New(jail.Config{Roots: []string{tr.root}})
	require.NoError(t, err)

	_, err = j.Resolve(filepath.Join(tr.outside, "secret"))

	var pathErr *jail.PathError
	require.ErrorAs(t, err, &pathErr)
	require.Equal(t, "resolve", pathErr.Op)
	require.Equal(t, filepath.Join(tr.outside, "secret"), pathErr.Path, "the caller's spelling is echoed, not the resolved one")
	require.ErrorIs(t, pathErr.Err, jail.ErrOutsideJail)
	require.NotContains(t, err.Error(), "\x00")
}

func TestResolve_Concurrent(t *testing.T) {
	t.Parallel()
	tr := newTree(t)

	j, err := jail.New(jail.Config{Roots: []string{tr.root}})
	require.NoError(t, err)

	inside := filepath.Join(tr.root, "sub", "file")
	outside := filepath.Join(tr.root, "escape", "secret")

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				got, err := j.Resolve(inside)
				if err != nil || got != inside {
					t.Errorf("Resolve(%q) = %q, %v", inside, got, err)
					return
				}
				if _, err := j.Resolve(outside); !errors.Is(err, jail.ErrOutsideJail) {
					t.Errorf("Resolve(%q) error = %v, want ErrOutsideJail", outside, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
