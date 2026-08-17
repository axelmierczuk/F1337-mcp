package platform

import (
	"math"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

// The cgroup reader takes an fs.FS so the whole derivation — the self-cgroup
// lookup, the walk up the hierarchy, and the narrowing of Resources — can be
// exercised against synthetic trees on any runner. Only the single call that
// passes os.DirFS("/") is Linux-only, and it has nothing in it to get wrong.

func cgroupFS(files map[string]string) fstest.MapFS {
	fsys := make(fstest.MapFS, len(files))
	for name, content := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(content)}
	}
	return fsys
}

func TestReadCgroupLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		files map[string]string
		want  cgroupLimits
	}{
		{
			name:  "no cgroup at all",
			files: map[string]string{},
			want:  cgroupLimits{},
		},
		{
			name: "v1 only, no unified line",
			files: map[string]string{
				"proc/self/cgroup": "3:cpu,cpuacct:/user.slice\n2:memory:/user.slice\n",
			},
			want: cgroupLimits{},
		},
		{
			name: "unified hierarchy with no limits set",
			files: map[string]string{
				"proc/self/cgroup":                    "0::/user.slice/user-1000.slice\n",
				"sys/fs/cgroup/user.slice/cpu.max":    "max 100000\n",
				"sys/fs/cgroup/user.slice/memory.max": "max\n",
			},
			want: cgroupLimits{},
		},
		{
			name: "memory limit on the leaf",
			files: map[string]string{
				"proc/self/cgroup": "0::/system.slice/sandboxd.service\n",
				"sys/fs/cgroup/system.slice/sandboxd.service/memory.max":     "2147483648\n",
				"sys/fs/cgroup/system.slice/sandboxd.service/memory.current": "536870912\n",
			},
			want: cgroupLimits{MemoryMax: 2147483648, MemoryCurrent: 536870912},
		},
		{
			name: "cpu quota on the leaf",
			files: map[string]string{
				"proc/self/cgroup": "0::/system.slice/sandboxd.service\n",
				"sys/fs/cgroup/system.slice/sandboxd.service/cpu.max": "150000 100000\n",
			},
			want: cgroupLimits{CPUQuota: 150000, CPUPeriod: 100000},
		},
		{
			name: "a parent slice is tighter than the leaf",
			files: map[string]string{
				"proc/self/cgroup":                                           "0::/system.slice/sandboxd.service\n",
				"sys/fs/cgroup/system.slice/memory.max":                      "1073741824\n",
				"sys/fs/cgroup/system.slice/memory.current":                  "104857600\n",
				"sys/fs/cgroup/system.slice/sandboxd.service/memory.max":     "4294967296\n",
				"sys/fs/cgroup/system.slice/sandboxd.service/memory.current": "1048576\n",
				"sys/fs/cgroup/system.slice/cpu.max":                         "50000 100000\n",
				"sys/fs/cgroup/system.slice/sandboxd.service/cpu.max":        "400000 100000\n",
			},
			want: cgroupLimits{
				MemoryMax:     1073741824,
				MemoryCurrent: 104857600,
				CPUQuota:      50000,
				CPUPeriod:     100000,
			},
		},
		{
			// Moved from internal/agent/host, which used to keep a parallel
			// cgroup reader. A hybrid host writes one line per v1 controller
			// *and* the unified line; the v2 path has to be found among them
			// rather than taken from the first line.
			name: "unified line among v1 controller lines",
			files: map[string]string{
				"proc/self/cgroup": "12:devices:/user.slice\n" +
					"5:memory:/system.slice/sandboxd.service\n" +
					"3:cpu,cpuacct:/system.slice/sandboxd.service\n" +
					"0::/system.slice/sandboxd.service\n",
				"sys/fs/cgroup/system.slice/sandboxd.service/memory.max":     "1073741824\n",
				"sys/fs/cgroup/system.slice/sandboxd.service/memory.current": "104857600\n",
			},
			want: cgroupLimits{MemoryMax: 1073741824, MemoryCurrent: 104857600},
		},
		{
			name: "limit at the root of the hierarchy",
			files: map[string]string{
				"proc/self/cgroup":             "0::/\n",
				"sys/fs/cgroup/memory.max":     "8589934592\n",
				"sys/fs/cgroup/memory.current": "1073741824\n",
			},
			want: cgroupLimits{MemoryMax: 8589934592, MemoryCurrent: 1073741824},
		},
		{
			name: "cpu.max with a malformed quota",
			files: map[string]string{
				"proc/self/cgroup":      "0::/\n",
				"sys/fs/cgroup/cpu.max": "notanumber 100000\n",
			},
			want: cgroupLimits{},
		},
		{
			name: "cpu.max with a zero period",
			files: map[string]string{
				"proc/self/cgroup":      "0::/\n",
				"sys/fs/cgroup/cpu.max": "100000 0\n",
			},
			want: cgroupLimits{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, readCgroupLimits(cgroupFS(tc.files)))
		})
	}
}

func TestCgroupLimits_EffectiveCores(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		quota  uint64
		period uint64
		want   uint32
	}{
		{name: "unlimited", quota: 0, period: 0, want: 0},
		{name: "exactly one core", quota: 100000, period: 100000, want: 1},
		{name: "two cores", quota: 200000, period: 100000, want: 2},
		{name: "one and a half cores rounds up", quota: 150000, period: 100000, want: 2},
		{name: "a tenth of a core still yields one", quota: 10000, period: 100000, want: 1},
		{name: "non-default period", quota: 40000, period: 20000, want: 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l := cgroupLimits{CPUQuota: tc.quota, CPUPeriod: tc.period}
			require.Equal(t, tc.want, l.EffectiveCores())
		})
	}
}

// TestApplyCgroupLimits is the acceptance criterion "cgroup v2 memory and CPU
// limits are reflected in reported resources", checked on the derivation
// rather than on a host that happens to be in a container.
func TestApplyCgroupLimits(t *testing.T) {
	t.Parallel()

	const (
		hostMemory = uint64(64) << 30
		hostAvail  = uint64(40) << 30
		hostCores  = uint32(16)
	)

	tests := []struct {
		name   string
		limits cgroupLimits
		want   Resources
	}{
		{
			name:   "no limits leaves the machine's figures alone",
			limits: cgroupLimits{},
			want: Resources{
				CPUCores: hostCores, MemoryTotalBytes: hostMemory, MemoryAvailableBytes: hostAvail,
			},
		},
		{
			name:   "a memory limit narrows total and available",
			limits: cgroupLimits{MemoryMax: 2 << 30, MemoryCurrent: 512 << 20},
			want: Resources{
				CPUCores:             hostCores,
				MemoryTotalBytes:     2 << 30,
				MemoryAvailableBytes: 2<<30 - 512<<20,
				MemoryLimited:        true,
			},
		},
		{
			name:   "a cpu quota narrows the core count",
			limits: cgroupLimits{CPUQuota: 250000, CPUPeriod: 100000},
			want: Resources{
				CPUCores: 3, MemoryTotalBytes: hostMemory, MemoryAvailableBytes: hostAvail,
				CPUQuotaLimited: true,
			},
		},
		{
			name:   "a quota above the machine's cores is not an upgrade",
			limits: cgroupLimits{CPUQuota: 6400000, CPUPeriod: 100000},
			want: Resources{
				CPUCores: hostCores, MemoryTotalBytes: hostMemory, MemoryAvailableBytes: hostAvail,
			},
		},
		{
			name:   "a memory limit above physical memory is not an upgrade",
			limits: cgroupLimits{MemoryMax: 128 << 30, MemoryCurrent: 1 << 30},
			want: Resources{
				CPUCores: hostCores, MemoryTotalBytes: hostMemory, MemoryAvailableBytes: hostAvail,
			},
		},
		{
			// Moved from internal/agent/host, generalised from v1 to the
			// sentinel reaching v2 through a translating runtime: with
			// /proc/meminfo unreadable there is no machine figure to tighten
			// against, and the agent would otherwise advertise eight exabytes.
			name:   "a sentinel-sized limit is not a machine, even with physical memory unknown",
			limits: cgroupLimits{MemoryMax: 9223372036854771712, MemoryCurrent: 1 << 30},
			want: Resources{
				CPUCores: hostCores, MemoryTotalBytes: hostMemory, MemoryAvailableBytes: hostAvail,
			},
		},
		{
			name:   "usage over the limit reports nothing available rather than underflowing",
			limits: cgroupLimits{MemoryMax: 1 << 30, MemoryCurrent: 2 << 30},
			want: Resources{
				CPUCores: hostCores, MemoryTotalBytes: 1 << 30, MemoryAvailableBytes: 0,
				MemoryLimited: true,
			},
		},
		{
			name:   "both limits at once",
			limits: cgroupLimits{MemoryMax: 4 << 30, MemoryCurrent: 1 << 30, CPUQuota: 50000, CPUPeriod: 100000},
			want: Resources{
				CPUCores:             1,
				MemoryTotalBytes:     4 << 30,
				MemoryAvailableBytes: 3 << 30,
				CPUQuotaLimited:      true,
				MemoryLimited:        true,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Resources{
				CPUCores:             hostCores,
				MemoryTotalBytes:     hostMemory,
				MemoryAvailableBytes: hostAvail,
			}
			applyCgroupLimits(&got, tc.limits)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestApplyCgroupLimits_EndToEnd runs the whole path a containerised agent
// takes, from /proc/self/cgroup to the reported figures.
func TestApplyCgroupLimits_EndToEnd(t *testing.T) {
	t.Parallel()

	fsys := cgroupFS(map[string]string{
		// What a container under a cgroup namespace actually looks like.
		"proc/self/cgroup":             "0::/\n",
		"sys/fs/cgroup/memory.max":     "2147483648\n",
		"sys/fs/cgroup/memory.current": "268435456\n",
		"sys/fs/cgroup/cpu.max":        "200000 100000\n",
	})

	got := Resources{CPUCores: 32, MemoryTotalBytes: 128 << 30, MemoryAvailableBytes: 100 << 30}
	applyCgroupLimits(&got, readCgroupLimits(fsys))

	require.Equal(t, uint32(2), got.CPUCores)
	require.Equal(t, uint64(2147483648), got.MemoryTotalBytes)
	require.Equal(t, uint64(2147483648-268435456), got.MemoryAvailableBytes)
	require.True(t, got.CPUQuotaLimited)
	require.True(t, got.MemoryLimited)
}

func TestApplyCgroupLimits_NeverReportsZeroCores(t *testing.T) {
	t.Parallel()

	got := Resources{}
	applyCgroupLimits(&got, cgroupLimits{})
	require.Equal(t, uint32(1), got.CPUCores, "a scheduler dividing by the core count must not divide by zero")
}

// The sentinel case above with physical memory unknown, which is the shape
// that made it reachable: applyCgroupLimits accepts any limit when there is
// nothing to compare against, so the plausibility ceiling is the only thing
// standing between an unreadable /proc/meminfo and an eight-exabyte host.
//
// Moved from internal/agent/host, where a parallel cgroup reader used to carry
// the same guard against cgroup v1's numeric spelling of "unlimited".
func TestApplyCgroupLimits_SentinelWithUnknownPhysicalMemory(t *testing.T) {
	t.Parallel()

	for name, sentinel := range map[string]uint64{
		"4 KiB pages":  0x7FFFFFFFFFFFF000,
		"64 KiB pages": 0x7FFFFFFFFFFF0000,
		"MaxInt64":     1<<63 - 1,
		"MaxUint64":    1<<64 - 1,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := Resources{CPUCores: 8}
			applyCgroupLimits(&got, cgroupLimits{MemoryMax: sentinel, MemoryCurrent: 1 << 30})

			require.Zero(t, got.MemoryTotalBytes, "an unknown total stays unknown rather than becoming a sentinel")
			require.Zero(t, got.MemoryAvailableBytes)
			require.False(t, got.MemoryLimited)
		})
	}

	// A real limit is still adopted when physical memory is unknown, so the
	// ceiling has not simply switched the unknown-total path off.
	got := Resources{CPUCores: 8}
	applyCgroupLimits(&got, cgroupLimits{MemoryMax: 2 << 30, MemoryCurrent: 512 << 20})
	require.Equal(t, uint64(2)<<30, got.MemoryTotalBytes)
	require.True(t, got.MemoryLimited)
}

// cgroup v1 is not a historical curiosity: RHEL 7, Amazon Linux 2 and any
// Docker on a host booted with systemd.unified_cgroup_hierarchy=0 still use it,
// and an agent that reads only v2 there reports the machine's capacity and
// accepts work the kernel then OOM-kills.
//
// The v1 files say the same things as v2's in three different spellings, and
// each spelling of "no limit" is its own trap.

func TestReadCgroupLimitsV1(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		files map[string]string
		want  cgroupLimits
	}{
		{
			name: "memory limit on the leaf",
			files: map[string]string{
				"proc/self/cgroup": "5:memory:/docker/abc123\n",
				"sys/fs/cgroup/memory/docker/abc123/memory.limit_in_bytes": "2147483648\n",
				"sys/fs/cgroup/memory/docker/abc123/memory.usage_in_bytes": "536870912\n",
			},
			want: cgroupLimits{MemoryMax: 2147483648, MemoryCurrent: 536870912},
		},
		{
			name: "cpu quota on the leaf, from its two files",
			files: map[string]string{
				"proc/self/cgroup": "3:cpu,cpuacct:/docker/abc123\n",
				"sys/fs/cgroup/cpu,cpuacct/docker/abc123/cpu.cfs_quota_us":  "150000\n",
				"sys/fs/cgroup/cpu,cpuacct/docker/abc123/cpu.cfs_period_us": "100000\n",
			},
			want: cgroupLimits{CPUQuota: 150000, CPUPeriod: 100000},
		},
		{
			// The controller is conventionally reachable both by the mounted
			// set and by a per-controller symlink. A container image may
			// present only one.
			name: "cpu reachable through the bare controller name",
			files: map[string]string{
				"proc/self/cgroup":                          "3:cpu,cpuacct:/slice\n",
				"sys/fs/cgroup/cpu/slice/cpu.cfs_quota_us":  "50000\n",
				"sys/fs/cgroup/cpu/slice/cpu.cfs_period_us": "100000\n",
			},
			want: cgroupLimits{CPUQuota: 50000, CPUPeriod: 100000},
		},
		{
			// v1 limits are inherited exactly as v2's are, so the walk up
			// matters for the same reason.
			name: "a parent slice is tighter than the leaf",
			files: map[string]string{
				"proc/self/cgroup": "5:memory:/system.slice/sandboxd.service\n" +
					"3:cpu,cpuacct:/system.slice/sandboxd.service\n",
				"sys/fs/cgroup/memory/system.slice/memory.limit_in_bytes":                   "1073741824\n",
				"sys/fs/cgroup/memory/system.slice/memory.usage_in_bytes":                   "104857600\n",
				"sys/fs/cgroup/memory/system.slice/sandboxd.service/memory.limit_in_bytes":  "4294967296\n",
				"sys/fs/cgroup/memory/system.slice/sandboxd.service/memory.usage_in_bytes":  "1048576\n",
				"sys/fs/cgroup/cpu,cpuacct/system.slice/cpu.cfs_quota_us":                   "50000\n",
				"sys/fs/cgroup/cpu,cpuacct/system.slice/cpu.cfs_period_us":                  "100000\n",
				"sys/fs/cgroup/cpu,cpuacct/system.slice/sandboxd.service/cpu.cfs_quota_us":  "400000\n",
				"sys/fs/cgroup/cpu,cpuacct/system.slice/sandboxd.service/cpu.cfs_period_us": "100000\n",
			},
			want: cgroupLimits{
				MemoryMax: 1073741824, MemoryCurrent: 104857600,
				CPUQuota: 50000, CPUPeriod: 100000,
			},
		},
		{
			name: "limit at the mount root",
			files: map[string]string{
				"proc/self/cgroup":                           "5:memory:/\n",
				"sys/fs/cgroup/memory/memory.limit_in_bytes": "8589934592\n",
				"sys/fs/cgroup/memory/memory.usage_in_bytes": "1073741824\n",
			},
			want: cgroupLimits{MemoryMax: 8589934592, MemoryCurrent: 1073741824},
		},
		{
			// The other v1 sentinel, and a different one from the memory
			// ceiling: a quota of -1 is how v1 says "no limit".
			name: "a quota of -1 is unlimited, not a negative quota",
			files: map[string]string{
				"proc/self/cgroup": "3:cpu,cpuacct:/slice\n",
				"sys/fs/cgroup/cpu,cpuacct/slice/cpu.cfs_quota_us":  "-1\n",
				"sys/fs/cgroup/cpu,cpuacct/slice/cpu.cfs_period_us": "100000\n",
			},
			want: cgroupLimits{},
		},
		{
			name: "a zero period is not a quota",
			files: map[string]string{
				"proc/self/cgroup": "3:cpu,cpuacct:/slice\n",
				"sys/fs/cgroup/cpu,cpuacct/slice/cpu.cfs_quota_us":  "100000\n",
				"sys/fs/cgroup/cpu,cpuacct/slice/cpu.cfs_period_us": "0\n",
			},
			want: cgroupLimits{},
		},
		{
			// systemd's bookkeeping hierarchy carries no limits.
			name: "the name=systemd hierarchy is skipped",
			files: map[string]string{
				"proc/self/cgroup": "1:name=systemd:/user.slice/session-3.scope\n",
			},
			want: cgroupLimits{},
		},
		{
			name: "v2 only, no v1 lines",
			files: map[string]string{
				"proc/self/cgroup":               "0::/slice\n",
				"sys/fs/cgroup/slice/memory.max": "1073741824\n",
			},
			want: cgroupLimits{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, readCgroupLimitsV1(cgroupFS(tc.files)))
		})
	}
}

// v1 spells "no memory limit" as a number, and the number is PAGE_COUNTER_MAX
// scaled by the page size. Both variants land *just below* half of MaxUint64 —
// 4095 and 65535 below it — so the obvious guard of "at least MaxUint64/2"
// misses both and reports the sentinel as the container's ceiling.
//
// This is the defect a previous audit round found in the reader this package
// replaced, which reported nine exabytes of RAM. The guard below is what makes
// this test pass; the naive comparison is what makes it fail.
func TestReadCgroupLimitsV1_UnlimitedMemorySentinel(t *testing.T) {
	t.Parallel()

	sentinels := map[string]string{
		"4 KiB pages":  "9223372036854771712", // 0x7FFFFFFFFFFFF000
		"64 KiB pages": "9223372036854710272", // 0x7FFFFFFFFFFF0000
		"MaxInt64":     "9223372036854775807",
		"MaxUint64":    "18446744073709551615",
	}
	for name, sentinel := range sentinels {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := readCgroupLimitsV1(cgroupFS(map[string]string{
				"proc/self/cgroup": "5:memory:/slice\n",
				"sys/fs/cgroup/memory/slice/memory.limit_in_bytes": sentinel + "\n",
				"sys/fs/cgroup/memory/slice/memory.usage_in_bytes": "1073741824\n",
			}))
			require.Equal(t, cgroupLimits{}, got, "%s is v1's unlimited, not a ceiling", sentinel)
		})
	}

	// Guard: the two page-size sentinels really are below the threshold the
	// naive comparison would use, which is the whole reason it fails.
	for _, sentinel := range []uint64{0x7FFFFFFFFFFFF000, 0x7FFFFFFFFFFF0000} {
		require.Less(t, sentinel, uint64(math.MaxUint64/2),
			"if this stops holding, the naive guard would have worked and this test proves nothing")
		require.GreaterOrEqual(t, sentinel, implausibleMemory)
	}

	// A real limit at the same place is still read.
	got := readCgroupLimitsV1(cgroupFS(map[string]string{
		"proc/self/cgroup": "5:memory:/slice\n",
		"sys/fs/cgroup/memory/slice/memory.limit_in_bytes": "2147483648\n",
		"sys/fs/cgroup/memory/slice/memory.usage_in_bytes": "536870912\n",
	}))
	require.Equal(t, cgroupLimits{MemoryMax: 2147483648, MemoryCurrent: 536870912}, got)
}

// A host can be v1, v2, or hybrid with different controllers on each. Which it
// is, is read from /proc/self/cgroup rather than assumed, and readCgroupLimits
// takes whichever hierarchy carries each controller.
func TestReadCgroupLimits_HierarchyDetection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		files map[string]string
		want  cgroupLimits
	}{
		{
			name: "v2 only",
			files: map[string]string{
				"proc/self/cgroup":                   "0::/slice\n",
				"sys/fs/cgroup/slice/memory.max":     "2147483648\n",
				"sys/fs/cgroup/slice/memory.current": "536870912\n",
				"sys/fs/cgroup/slice/cpu.max":        "200000 100000\n",
			},
			want: cgroupLimits{
				MemoryMax: 2147483648, MemoryCurrent: 536870912,
				CPUQuota: 200000, CPUPeriod: 100000,
			},
		},
		{
			name: "v1 only",
			files: map[string]string{
				"proc/self/cgroup": "5:memory:/docker/abc\n3:cpu,cpuacct:/docker/abc\n",
				"sys/fs/cgroup/memory/docker/abc/memory.limit_in_bytes":  "2147483648\n",
				"sys/fs/cgroup/memory/docker/abc/memory.usage_in_bytes":  "536870912\n",
				"sys/fs/cgroup/cpu,cpuacct/docker/abc/cpu.cfs_quota_us":  "200000\n",
				"sys/fs/cgroup/cpu,cpuacct/docker/abc/cpu.cfs_period_us": "100000\n",
			},
			want: cgroupLimits{
				MemoryMax: 2147483648, MemoryCurrent: 536870912,
				CPUQuota: 200000, CPUPeriod: 100000,
			},
		},
		{
			// The shape a host booted with the hybrid hierarchy actually has:
			// the unified mount carries no controllers, and each controller
			// sits on its own v1 hierarchy.
			name: "hybrid, memory on v1 and cpu on v2",
			files: map[string]string{
				"proc/self/cgroup": "5:memory:/slice\n0::/slice\n",
				"sys/fs/cgroup/memory/slice/memory.limit_in_bytes": "1073741824\n",
				"sys/fs/cgroup/memory/slice/memory.usage_in_bytes": "268435456\n",
				"sys/fs/cgroup/slice/cpu.max":                      "150000 100000\n",
			},
			want: cgroupLimits{
				MemoryMax: 1073741824, MemoryCurrent: 268435456,
				CPUQuota: 150000, CPUPeriod: 100000,
			},
		},
		{
			name: "hybrid, cpu on v1 and memory on v2",
			files: map[string]string{
				"proc/self/cgroup": "3:cpu,cpuacct:/slice\n0::/slice\n",
				"sys/fs/cgroup/cpu,cpuacct/slice/cpu.cfs_quota_us":  "50000\n",
				"sys/fs/cgroup/cpu,cpuacct/slice/cpu.cfs_period_us": "100000\n",
				"sys/fs/cgroup/slice/memory.max":                    "1073741824\n",
				"sys/fs/cgroup/slice/memory.current":                "268435456\n",
			},
			want: cgroupLimits{
				MemoryMax: 1073741824, MemoryCurrent: 268435456,
				CPUQuota: 50000, CPUPeriod: 100000,
			},
		},
		{
			// Both hierarchies naming a limit is not a shape the kernel
			// produces, but taking the tighter of the two is what makes the
			// hybrid cases above need no special case, so it is asserted.
			name: "both hierarchies set a limit, the tighter wins",
			files: map[string]string{
				"proc/self/cgroup": "5:memory:/slice\n0::/slice\n",
				"sys/fs/cgroup/memory/slice/memory.limit_in_bytes": "1073741824\n",
				"sys/fs/cgroup/memory/slice/memory.usage_in_bytes": "268435456\n",
				"sys/fs/cgroup/slice/memory.max":                   "4294967296\n",
				"sys/fs/cgroup/slice/memory.current":               "1048576\n",
			},
			want: cgroupLimits{MemoryMax: 1073741824, MemoryCurrent: 268435456},
		},
		{
			name:  "no cgroups at all",
			files: map[string]string{},
			want:  cgroupLimits{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, readCgroupLimits(cgroupFS(tc.files)))
		})
	}
}

// End to end on a v1 host: from /proc/self/cgroup to the figures a scheduler
// sees. This is the path that regressed to reporting host capacity when the
// only v1-aware reader in the tree was deleted.
func TestApplyCgroupLimits_EndToEndV1(t *testing.T) {
	t.Parallel()

	fsys := cgroupFS(map[string]string{
		"proc/self/cgroup": "5:memory:/docker/abc\n3:cpu,cpuacct:/docker/abc\n",
		"sys/fs/cgroup/memory/docker/abc/memory.limit_in_bytes":  "2147483648\n",
		"sys/fs/cgroup/memory/docker/abc/memory.usage_in_bytes":  "268435456\n",
		"sys/fs/cgroup/cpu,cpuacct/docker/abc/cpu.cfs_quota_us":  "200000\n",
		"sys/fs/cgroup/cpu,cpuacct/docker/abc/cpu.cfs_period_us": "100000\n",
	})

	got := Resources{CPUCores: 32, MemoryTotalBytes: 128 << 30, MemoryAvailableBytes: 100 << 30}
	applyCgroupLimits(&got, readCgroupLimits(fsys))

	require.Equal(t, uint32(2), got.CPUCores)
	require.Equal(t, uint64(2147483648), got.MemoryTotalBytes)
	require.Equal(t, uint64(2147483648-268435456), got.MemoryAvailableBytes)
	require.True(t, got.CPUQuotaLimited)
	require.True(t, got.MemoryLimited)
}
