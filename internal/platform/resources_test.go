package platform_test

import (
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/platform"
)

// TestReadResources exercises the real host read on every runner. The
// cgroup-narrowing logic it feeds is covered separately and exhaustively in
// cgroup_test.go, because a CI runner is not in a memory-limited cgroup and a
// test that only ran here would prove nothing about containers.
func TestReadResources(t *testing.T) {
	t.Parallel()

	res, err := platform.ReadResources(t.TempDir())
	require.NoError(t, err)

	require.Positive(t, res.CPUCores)
	require.LessOrEqual(t, res.CPUCores, uint32(runtime.NumCPU()),
		"the effective core count may be narrowed by a quota but never raised above the machine's")

	require.Positive(t, res.MemoryTotalBytes, "a host with no memory is not a host")
	require.LessOrEqual(t, res.MemoryAvailableBytes, res.MemoryTotalBytes)

	require.Positive(t, res.DiskTotalBytes)
	require.LessOrEqual(t, res.DiskAvailableBytes, res.DiskTotalBytes)

	require.GreaterOrEqual(t, res.LoadAverage1m, 0.0)
	if runtime.GOOS == "windows" {
		require.Zero(t, res.LoadAverage1m, "Windows has no load average and must report zero rather than invent one")
	}

	t.Logf("cores=%d memory=%d/%d disk=%d/%d load=%.2f cpu-limited=%v memory-limited=%v",
		res.CPUCores, res.MemoryAvailableBytes, res.MemoryTotalBytes,
		res.DiskAvailableBytes, res.DiskTotalBytes, res.LoadAverage1m,
		res.CPUQuotaLimited, res.MemoryLimited)
}

func TestReadResources_EmptyPathUsesWorkingDirectory(t *testing.T) {
	t.Parallel()

	res, err := platform.ReadResources("")
	require.NoError(t, err)
	require.Positive(t, res.DiskTotalBytes)
}

func TestReadResources_MissingDiskPathStillReportsMemory(t *testing.T) {
	t.Parallel()

	// A bad disk path must not cost the caller the rest of the report: half a
	// resource report is more useful to a scheduler than none.
	res, err := platform.ReadResources(os.TempDir() + string(os.PathSeparator) + "sandboxd-no-such-directory-xyzzy")
	require.NoError(t, err)
	require.Positive(t, res.MemoryTotalBytes)
	require.Zero(t, res.DiskTotalBytes)
}
