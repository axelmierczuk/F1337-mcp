package platform

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The fixtures elsewhere in this package describe hierarchies; these two tests
// read real ones.
//
// A synthetic fs.FS cannot represent a symlink, and the v1 layout is built on
// them: /sys/fs/cgroup/cpu is conventionally a link to cpu,cpuacct. So the v1
// mount-name handling is exercised over a real directory tree, and the whole
// reader is exercised over the real root filesystem wherever there is one.

// TestReadCgroupLimits_RealRoot runs the reader against this machine's actual
// filesystem. On a Linux runner that is a real hierarchy; everywhere else it is
// the "no cgroups at all" path, which is equally worth not panicking on.
func TestReadCgroupLimits_RealRoot(t *testing.T) {
	root := os.DirFS("/")

	v1, v2 := readCgroupLimitsV1(root), readCgroupLimitsV2(root)
	combined := readCgroupLimits(root)

	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		t.Logf("/proc/self/cgroup:\n%s", strings.TrimSpace(string(data)))
	} else {
		t.Logf("no /proc/self/cgroup on %s: exercising the no-cgroup path", runtime.GOOS)
	}
	t.Logf("v1=%+v v2=%+v combined=%+v", v1, v2, combined)

	for name, l := range map[string]cgroupLimits{"v1": v1, "v2": v2, "combined": combined} {
		if l.MemoryMax > 0 {
			require.Less(t, l.MemoryMax, implausibleMemory,
				"%s: a sentinel must never survive as a limit", name)
		}
		require.Equal(t, l.CPUQuota > 0, l.CPUPeriod > 0,
			"%s: a quota without a period, or the reverse, is not a limit anyone can act on", name)
		if l.CPUQuota > 0 {
			require.Positive(t, l.EffectiveCores(), "%s: a real quota must round to at least one core", name)
		}
	}

	// The combination never invents a limit neither hierarchy reported.
	if v1.MemoryMax == 0 && v2.MemoryMax == 0 {
		require.Zero(t, combined.MemoryMax)
	}
	if v1.CPUQuota == 0 && v2.CPUQuota == 0 {
		require.Zero(t, combined.CPUQuota)
	}
}

// TestReadCgroupLimitsV1_RealSymlinkedMount builds a v1 layout on disk, with
// /sys/fs/cgroup/cpu a real symlink to cpu,cpuacct as a distribution ships it,
// and reads it through os.DirFS.
//
// fstest.MapFS has no symlinks, so this is the only way to show that the
// per-controller name resolves at all — and it is the name a container image
// commonly presents on its own.
func TestReadCgroupLimitsV1_RealSymlinkedMount(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a symlink needs elevation or developer mode on Windows")
	}

	root := t.TempDir()
	mustWrite := func(rel, content string) {
		t.Helper()
		full := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o600))
	}

	mustWrite("proc/self/cgroup", "5:memory:/docker/abc\n3:cpu,cpuacct:/docker/abc\n")
	mustWrite("sys/fs/cgroup/memory/docker/abc/memory.limit_in_bytes", "2147483648\n")
	mustWrite("sys/fs/cgroup/memory/docker/abc/memory.usage_in_bytes", "268435456\n")
	mustWrite("sys/fs/cgroup/cpu,cpuacct/docker/abc/cpu.cfs_quota_us", "150000\n")
	mustWrite("sys/fs/cgroup/cpu,cpuacct/docker/abc/cpu.cfs_period_us", "100000\n")

	// The per-controller symlink every distribution ships.
	require.NoError(t, os.Symlink("cpu,cpuacct", filepath.Join(root, "sys", "fs", "cgroup", "cpu")))

	got := readCgroupLimits(os.DirFS(root))
	require.Equal(t, cgroupLimits{
		MemoryMax: 2147483648, MemoryCurrent: 268435456,
		CPUQuota: 150000, CPUPeriod: 100000,
	}, got)

	// And through the symlink alone, which is what a container image that
	// bind-mounts only /sys/fs/cgroup/cpu presents.
	linkOnly := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(linkOnly, "proc", "self"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(linkOnly, "proc", "self", "cgroup"),
		[]byte("3:cpu,cpuacct:/slice\n"), 0o600))
	target := filepath.Join(linkOnly, "sys", "fs", "cgroup", "cpuacct-real", "slice")
	require.NoError(t, os.MkdirAll(target, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(target, "cpu.cfs_quota_us"), []byte("50000\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(target, "cpu.cfs_period_us"), []byte("100000\n"), 0o600))
	require.NoError(t, os.Symlink("cpuacct-real",
		filepath.Join(linkOnly, "sys", "fs", "cgroup", "cpu")))

	got = readCgroupLimits(os.DirFS(linkOnly))
	require.Equal(t, cgroupLimits{CPUQuota: 50000, CPUPeriod: 100000}, got)
	require.Equal(t, uint32(1), got.EffectiveCores())
}
