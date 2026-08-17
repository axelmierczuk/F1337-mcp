package host

import "time"

// SetProberForTest replaces the toolchain prober, so a test can assert that
// Health never reaches it. Health's cheapness is a load-bearing property —
// every connected MCP server calls it on a timer — and asserting it by timing
// alone would be a test that passes on a fast machine and flakes on a slow one.
func (s *Service) SetProberForTest(p *Prober) { s.prober = p }

// BuildProbeEnvForTest exposes the probe environment with its lookup injected.
//
// The allowlist it applies is Windows-specific and load-bearing there — a child
// started without SystemRoot fails to initialise — so it has to be assertable
// from a Linux or macOS runner rather than only from the platform it matters
// for.
func BuildProbeEnvForTest(get func(string) string) []string { return buildProbeEnv(get) }

// ProbePassthroughForTest is the platform's allowlist of inherited variables.
func ProbePassthroughForTest() []string { return probePassthrough }

// SetKernelPathsForTest redirects the cgroup and /proc readers at a fixture
// tree and returns a function restoring them.
//
// The parsing they drive is what every container-confined agent's advertised
// capacity comes from, and neither hierarchy can be made to report a limit from
// inside a test on a real host — so a fixture is the only way to exercise it.
func SetKernelPathsForTest(cgroup, selfCgroup, meminfo string) func() {
	prev := [3]string{cgroupRoot, procSelfCgroup, procMeminfo}
	cgroupRoot, procSelfCgroup, procMeminfo = cgroup, selfCgroup, meminfo
	return func() { cgroupRoot, procSelfCgroup, procMeminfo = prev[0], prev[1], prev[2] }
}

// CGroupCPUQuotaForTest is the tightest CPU quota in force, in cores.
func CGroupCPUQuotaForTest() (float64, bool) { return cgroupCPUQuota() }

// CGroupMemoryLimitForTest is the tightest memory limit in force, and the usage
// under it.
func CGroupMemoryLimitForTest() (limit, usage uint64, ok bool) { return cgroupMemoryLimit() }

// CGroupDirsForTest is every directory a limit for this process could be
// written in.
func CGroupDirsForTest() []string { return cgroupDirs() }

// ReadMeminfoForTest is the machine's memory totals, as /proc/meminfo reports
// them.
func ReadMeminfoForTest() (total, available uint64) { return readMeminfo() }

// SetDiskUsageForTest replaces the platform's filesystem measurement and
// returns a function restoring it.
//
// The bound it exists to test is a bound on a call that blocks in the kernel
// and cannot be cancelled, which is not something a real filesystem can be
// asked to do on demand.
func SetDiskUsageForTest(fn func(string) (uint64, uint64)) func() {
	prev := diskUsage
	diskUsage = fn
	return func() { diskUsage = prev }
}

// SetDiskProbeTimeoutForTest shortens the measurement bound and returns a
// function restoring it, so a test asserts the mechanism in milliseconds rather
// than paying the production wait.
func SetDiskProbeTimeoutForTest(d time.Duration) func() {
	prev := diskProbeTimeout
	diskProbeTimeout = d
	return func() { diskProbeTimeout = prev }
}

// DiskProbeTimeoutForTest is how long a filesystem measurement is given.
func DiskProbeTimeoutForTest() time.Duration { return diskProbeTimeout }

// WaitDiskProbeIdleForTest blocks until no measurement is outstanding, so a
// test can restore what it replaced without racing the probe goroutine.
func WaitDiskProbeIdleForTest() {
	for diskProbeRunning.Load() {
		time.Sleep(time.Millisecond)
	}
}
