package platform

import (
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
