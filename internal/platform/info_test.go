package platform_test

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

func TestDescribe(t *testing.T) {
	t.Parallel()

	info := platform.Describe()
	require.Equal(t, runtime.GOOS, info.OS)
	require.Equal(t, runtime.GOARCH, info.Arch)
	require.Equal(t, platform.PathSeparator, info.PathSeparator)
	require.Contains(t, []string{"/", `\`}, info.PathSeparator)

	// Both are best effort and documented as possibly empty, but on the three
	// platforms the agent supports they are not, and a silent regression to
	// empty would show up in fleet_list as a nameless host.
	require.NotEmpty(t, info.Hostname)
	require.NotEmpty(t, info.KernelVersion)

	t.Logf("os=%s arch=%s kernel=%q hostname=%q sep=%q",
		info.OS, info.Arch, info.KernelVersion, info.Hostname, info.PathSeparator)
}
