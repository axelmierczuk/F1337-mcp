package platform

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// classifyWindowsPath is pure and compiled on every platform, so these cases
// run on the Linux and macOS runners too. That matters: the Windows path rules
// are the ones least likely to be exercised by hand, and a test that only runs
// on one of three runners is a test that fails late.
func TestClassifyWindowsPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path string
		want PathKind
		why  string
	}{
		{path: "", want: PathInvalid},
		{path: `C:\`, want: PathLocal},
		{path: `C:\root\sub`, want: PathLocal},
		{path: `c:\root\sub`, want: PathLocal, why: "drive letters are letters in either case"},
		{path: `Z:\x`, want: PathLocal},
		{path: `C:/root/sub`, want: PathLocal, why: "Windows accepts forward slashes as separators"},

		{path: `\\?\C:\root`, want: PathDevice, why: "extended-length prefix"},
		{path: `\\?\UNC\server\share`, want: PathDevice},
		{path: `\\.\PhysicalDrive0`, want: PathDevice},
		{path: `//?/C:/root`, want: PathDevice, why: "the device prefix works with forward slashes too"},
		{path: `\\?`, want: PathDevice},

		{path: `\\server\share`, want: PathUNC},
		{path: `\\server\share\file`, want: PathUNC},
		{path: `//server/share/file`, want: PathUNC},
		{path: `\\`, want: PathUNC, why: "degenerate, but in the UNC namespace, not the local one"},

		{path: `C:sub`, want: PathInvalid, why: "drive-relative: depends on per-drive state the agent does not track"},
		{path: `C:`, want: PathInvalid},

		{path: `sub\file`, want: PathRelative},
		{path: `file`, want: PathRelative},
		{path: `\rooted`, want: PathRelative, why: "rooted on the current drive, so it needs a base to mean anything"},
		{path: `1:\x`, want: PathRelative, why: "a digit is not a drive letter"},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			require.Equalf(t, tc.want, classifyWindowsPath(tc.path), "%s", tc.why)
		})
	}
}

func TestFoldASCII(t *testing.T) {
	t.Parallel()

	require.Equal(t, byte('a'), foldASCII('A'))
	require.Equal(t, byte('z'), foldASCII('Z'))
	require.Equal(t, byte('a'), foldASCII('a'))
	require.Equal(t, byte('0'), foldASCII('0'))
	require.Equal(t, byte('\\'), foldASCII('\\'))
	// Non-ASCII bytes are left alone: folding them is what would let a
	// directory whose name merely folds to a root's name be treated as inside
	// that root.
	require.Equal(t, byte(0xC3), foldASCII(0xC3))
}
