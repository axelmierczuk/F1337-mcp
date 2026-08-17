package host_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/agent/host"
)

// Issue #5's note: "runtime.NumCPU is a floor, not the answer — respect cgroup
// limits on Linux, since a container-confined agent that reports host memory
// will get scheduled work it cannot run."
//
// These cover the parsing that decides what a confined agent advertises about
// itself: three file formats across two cgroup hierarchies. They run on every
// runner rather than only the Linux one, because the code is pure file parsing
// and because a real /sys/fs/cgroup cannot be made to report a limit from
// inside a test even where one exists.

// fixture is a cgroup tree and the /proc files beside it.
type fixture struct {
	cgroup     string
	selfCgroup string
	meminfo    string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{
		cgroup:     filepath.Join(root, "cgroup"),
		selfCgroup: filepath.Join(root, "self-cgroup"),
		meminfo:    filepath.Join(root, "meminfo"),
	}
	require.NoError(t, os.MkdirAll(f.cgroup, 0o755))
	// A process in the root cgroup unless a test says otherwise, so the mount
	// root is the only place a limit can be.
	f.writeSelfCgroup(t, "0::/\n")
	t.Cleanup(host.SetKernelPathsForTest(f.cgroup, f.selfCgroup, f.meminfo))
	return f
}

func (f *fixture) write(t *testing.T, rel, contents string) {
	t.Helper()
	path := filepath.Join(f.cgroup, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
}

func (f *fixture) writeSelfCgroup(t *testing.T, contents string) {
	t.Helper()
	require.NoError(t, os.WriteFile(f.selfCgroup, []byte(contents), 0o600))
}

func (f *fixture) writeMeminfo(t *testing.T, contents string) {
	t.Helper()
	require.NoError(t, os.WriteFile(f.meminfo, []byte(contents), 0o600))
}

// cgroup v2: "cpu.max" is "<quota> <period>", and "max <period>" when there is
// no quota at all.
func TestCGroupCPUQuota_V2(t *testing.T) {
	f := newFixture(t)

	_, ok := host.CGroupCPUQuotaForTest()
	assert.False(t, ok, "no cpu.max anywhere is no quota, not a quota of zero")

	f.write(t, "cpu.max", "max 100000\n")
	_, ok = host.CGroupCPUQuotaForTest()
	assert.False(t, ok, `"max" is the unlimited spelling and must not parse as a number`)

	f.write(t, "cpu.max", "50000 100000\n")
	quota, ok := host.CGroupCPUQuotaForTest()
	require.True(t, ok)
	assert.InDelta(t, 0.5, quota, 1e-9)
}

// cgroup v1 splits the same figure over two files under the cpu controller, and
// spells "unlimited" as a quota of -1.
func TestCGroupCPUQuota_V1(t *testing.T) {
	f := newFixture(t)

	f.write(t, filepath.Join("cpu", "cpu.cfs_period_us"), "100000\n")
	f.write(t, filepath.Join("cpu", "cpu.cfs_quota_us"), "-1\n")
	_, ok := host.CGroupCPUQuotaForTest()
	assert.False(t, ok, "-1 is v1's unlimited, not a negative quota")

	f.write(t, filepath.Join("cpu", "cpu.cfs_quota_us"), "250000\n")
	quota, ok := host.CGroupCPUQuotaForTest()
	require.True(t, ok)
	assert.InDelta(t, 2.5, quota, 1e-9)
}

// A process in a systemd slice has its limits in the directory /proc/self/cgroup
// names, not at the mount root — and where both name a quota, the tighter one is
// what the agent actually runs under.
func TestCGroupCPUQuota_TightestWins(t *testing.T) {
	f := newFixture(t)
	f.writeSelfCgroup(t, "0::/system.slice/sandboxd-agent.service\n")

	f.write(t, "cpu.max", "400000 100000\n") // 4 cores at the mount root
	f.write(t, filepath.Join("system.slice", "sandboxd-agent.service", "cpu.max"), "150000 100000\n")

	quota, ok := host.CGroupCPUQuotaForTest()
	require.True(t, ok)
	assert.InDelta(t, 1.5, quota, 1e-9, "the tightest limit is the one in force")
}

// cgroup v2 memory: the limit clamps the total, and headroom inside the cgroup
// is a tighter and truer answer than the host's MemAvailable.
func TestCGroupMemoryLimit_V2(t *testing.T) {
	f := newFixture(t)
	f.write(t, "memory.max", "2147483648\n")     // 2 GiB
	f.write(t, "memory.current", "1073741824\n") // 1 GiB in use

	limit, usage, ok := host.CGroupMemoryLimitForTest()
	require.True(t, ok)
	assert.EqualValues(t, 2*1024*1024*1024, limit)
	assert.EqualValues(t, 1024*1024*1024, usage)
}

// v2 spells unlimited as a word.
func TestCGroupMemoryLimit_V2MaxIsNotALimit(t *testing.T) {
	f := newFixture(t)
	f.write(t, "memory.max", "max\n")

	_, _, ok := host.CGroupMemoryLimitForTest()
	assert.False(t, ok)
}

// cgroup v1 spells "no limit" as a number rather than a word, and the number is
// PAGE_COUNTER_MAX scaled by the page size — which lands *just below* half of
// MaxUint64. A threshold of MaxUint64/2, the obvious one, lets it through and
// the agent reports nine exabytes of RAM as its capacity.
func TestCGroupMemoryLimit_V1UnlimitedSentinelIsNotALimit(t *testing.T) {
	for name, sentinel := range map[string]string{
		"4 KiB pages":  "9223372036854771712", // 0x7FFFFFFFFFFFF000
		"64 KiB pages": "9223372036854710272", // 0x7FFFFFFFFFFF0000
		"MaxInt64":     "9223372036854775807",
		"MaxUint64":    "18446744073709551615",
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.write(t, filepath.Join("memory", "memory.limit_in_bytes"), sentinel+"\n")
			f.write(t, filepath.Join("memory", "memory.usage_in_bytes"), "1073741824\n")

			_, _, ok := host.CGroupMemoryLimitForTest()
			assert.False(t, ok, "%s is v1's unlimited, not a machine with that much memory", sentinel)
		})
	}
}

// A real v1 limit is still honoured, so the sentinel guard has not simply
// switched the older hierarchy off.
func TestCGroupMemoryLimit_V1RealLimitIsHonoured(t *testing.T) {
	f := newFixture(t)
	f.write(t, filepath.Join("memory", "memory.limit_in_bytes"), "536870912\n") // 512 MiB
	f.write(t, filepath.Join("memory", "memory.usage_in_bytes"), "134217728\n") // 128 MiB

	limit, usage, ok := host.CGroupMemoryLimitForTest()
	require.True(t, ok)
	assert.EqualValues(t, 512*1024*1024, limit)
	assert.EqualValues(t, 128*1024*1024, usage)
}

// Where both hierarchies name a limit, the tighter one is what the agent has.
func TestCGroupMemoryLimit_TightestWins(t *testing.T) {
	f := newFixture(t)
	f.write(t, "memory.max", "4294967296\n")                                     // 4 GiB
	f.write(t, filepath.Join("memory", "memory.limit_in_bytes"), "1073741824\n") // 1 GiB
	f.write(t, filepath.Join("memory", "memory.usage_in_bytes"), "268435456\n")

	limit, usage, ok := host.CGroupMemoryLimitForTest()
	require.True(t, ok)
	assert.EqualValues(t, 1024*1024*1024, limit)
	assert.EqualValues(t, 256*1024*1024, usage, "the usage reported must be the one beside the limit that won")
}

// /proc/self/cgroup decides which directories are searched. The unified
// hierarchy writes an empty controller list; v1 writes one line per controller
// set, and only cpu and memory are worth following.
func TestCGroupDirs_FollowsProcSelfCgroup(t *testing.T) {
	f := newFixture(t)
	f.writeSelfCgroup(t, strings.Join([]string{
		"12:devices:/user.slice",
		"5:memory:/system.slice/sandboxd-agent.service",
		"3:cpu,cpuacct:/system.slice/sandboxd-agent.service",
		"0::/system.slice/sandboxd-agent.service",
		"",
	}, "\n"))

	slice := filepath.Join("system.slice", "sandboxd-agent.service")
	dirs := host.CGroupDirsForTest()
	assert.Contains(t, dirs, f.cgroup, "the mount root is what a container namespace exposes")
	assert.Contains(t, dirs, filepath.Join(f.cgroup, slice))
	assert.Contains(t, dirs, filepath.Join(f.cgroup, "memory", slice))
	assert.Contains(t, dirs, filepath.Join(f.cgroup, "cpu", slice))
	assert.NotContains(t, dirs, filepath.Join(f.cgroup, "devices", "user.slice"),
		"only the two controllers this package reads are followed")
}

// MemAvailable, not MemFree: page cache is reclaimable, and counting it as used
// makes a healthy box look full.
func TestReadMeminfo_UsesMemAvailable(t *testing.T) {
	f := newFixture(t)
	f.writeMeminfo(t, strings.Join([]string{
		"MemTotal:       16777216 kB",
		"MemFree:          524288 kB",
		"MemAvailable:    8388608 kB",
		"Buffers:          131072 kB",
		"",
	}, "\n"))

	total, available := host.ReadMeminfoForTest()
	assert.EqualValues(t, 16*1024*1024*1024, total)
	assert.EqualValues(t, 8*1024*1024*1024, available, "MemFree would be 512 MiB and is the wrong answer")
}

// A host with no /proc/meminfo reports nothing rather than guessing.
func TestReadMeminfo_AbsentIsZero(t *testing.T) {
	newFixture(t)
	total, available := host.ReadMeminfoForTest()
	assert.Zero(t, total)
	assert.Zero(t, available)
}
