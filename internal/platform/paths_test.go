package platform_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/platform"
)

func abs(parts ...string) string {
	return filepath.Join(append([]string{string(filepath.Separator)}, parts...)...)
}

func TestHasPathPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		path   string
		prefix string
		want   bool
	}{
		{name: "identical", path: abs("root"), prefix: abs("root"), want: true},
		{name: "child", path: abs("root", "sub"), prefix: abs("root"), want: true},
		{name: "grandchild", path: abs("root", "sub", "file"), prefix: abs("root"), want: true},
		{
			name:   "sibling sharing a string prefix",
			path:   abs("rootabc", "file"),
			prefix: abs("root"),
			want:   false,
		},
		{
			name:   "sibling whose name extends the last component",
			path:   abs("a", "rootx"),
			prefix: abs("a", "root"),
			want:   false,
		},
		{name: "parent is not beneath its child", path: abs("root"), prefix: abs("root", "sub"), want: false},
		{name: "unrelated", path: abs("etc", "passwd"), prefix: abs("root"), want: false},
		{name: "trailing separator on the prefix", path: abs("root", "sub"), prefix: abs("root") + string(filepath.Separator), want: true},
		{name: "empty path", path: "", prefix: abs("root"), want: false},
		{name: "empty prefix", path: abs("root"), prefix: "", want: false},
		{name: "root of the filesystem contains everything", path: abs("etc", "passwd"), prefix: abs(), want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, platform.HasPathPrefix(tc.path, tc.prefix))
		})
	}
}

// TestHasPathPrefix_Case pins the platform's case rule in place, in both
// directions, so a change to CaseInsensitivePaths cannot pass unnoticed.
func TestHasPathPrefix_Case(t *testing.T) {
	t.Parallel()

	got := platform.HasPathPrefix(abs("ROOT", "sub"), abs("root"))
	require.Equal(t, platform.CaseInsensitivePaths, got)
	require.Equal(t, runtime.GOOS == "windows", platform.CaseInsensitivePaths,
		"only Windows folds case; see the comment on CaseInsensitivePaths for why darwin does not")
}

func TestEqualPaths(t *testing.T) {
	t.Parallel()

	require.True(t, platform.EqualPaths(abs("root"), abs("root")))
	require.True(t, platform.EqualPaths(abs("root", "sub", ".."), abs("root")))
	require.True(t, platform.EqualPaths(abs("root")+string(filepath.Separator), abs("root")))
	require.False(t, platform.EqualPaths(abs("root"), abs("other")))
}

func TestNormalizePath(t *testing.T) {
	t.Parallel()

	base := abs("base", "dir")

	tests := []struct {
		name    string
		base    string
		path    string
		want    string
		wantErr bool
	}{
		{name: "absolute stays put", base: base, path: abs("elsewhere", "file"), want: abs("elsewhere", "file")},
		{name: "relative joins the base", base: base, path: filepath.Join("sub", "file"), want: filepath.Join(base, "sub", "file")},
		{name: "dot-dot is cleaned away", base: base, path: filepath.Join("..", "file"), want: abs("base", "file")},
		{name: "absolute with dot-dot", base: base, path: abs("a", "b", "..", "c"), want: abs("a", "c")},
		{name: "empty path", base: base, path: "", wantErr: true},
		{name: "relative base", base: "not-absolute", path: "file", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := platform.NormalizePath(tc.base, tc.path)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestNormalizePath_EmptyBaseUsesWorkingDirectory(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	require.NoError(t, err)

	got, err := platform.NormalizePath("", "file")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(wd, "file"), got)
}

func TestClassifyPath(t *testing.T) {
	t.Parallel()

	require.Equal(t, platform.PathInvalid, platform.ClassifyPath(""))
	require.Equal(t, platform.PathLocal, platform.ClassifyPath(abs("root")))
	require.Equal(t, platform.PathRelative, platform.ClassifyPath(filepath.Join("sub", "file")))

	if runtime.GOOS == "windows" {
		require.Equal(t, platform.PathDevice, platform.ClassifyPath(`\\?\C:\root`))
		require.Equal(t, platform.PathUNC, platform.ClassifyPath(`\\server\share`))
		return
	}
	// On Unix a leading backslash is an ordinary filename character, and
	// treating `\\?\x` as a device path there would refuse a legal filename.
	require.Equal(t, platform.PathRelative, platform.ClassifyPath(`\\?\C:\root`))
}

func TestPathSeparator(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		require.Equal(t, `\`, platform.PathSeparator)
		return
	}
	require.Equal(t, "/", platform.PathSeparator)
}

func TestPathKindString(t *testing.T) {
	t.Parallel()

	require.Equal(t, "invalid", platform.PathInvalid.String())
	require.Equal(t, "relative", platform.PathRelative.String())
	require.Equal(t, "local", platform.PathLocal.String())
	require.Equal(t, "unc", platform.PathUNC.String())
	require.Equal(t, "device", platform.PathDevice.String())
	require.Equal(t, "PathKind(99)", platform.PathKind(99).String())
}
