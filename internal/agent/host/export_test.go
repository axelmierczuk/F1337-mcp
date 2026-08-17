package host

import (
	"time"

	"github.com/axelmierczuk/sandboxd-mcp/internal/platform"
)

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

// SetReadResourcesForTest replaces the delegated capacity read and returns a
// function restoring it.
//
// The bound it exists to test is a bound on a call that blocks in the kernel
// and cannot be cancelled, which is not something a real filesystem can be
// asked to do on demand.
func SetReadResourcesForTest(fn func(string) (platform.Resources, error)) func() {
	prev := readResources
	readResources = fn
	return func() { readResources = prev }
}

// ProbeResourcesForTest is the bounded capacity read GetHostInfo makes.
func ProbeResourcesForTest(diskPath string) (platform.Resources, error) {
	return probeResources(diskPath)
}

// SetResourceProbeTimeoutForTest shortens the bound and returns a function
// restoring it, so a test asserts the mechanism in milliseconds rather than
// paying the production wait.
func SetResourceProbeTimeoutForTest(d time.Duration) func() {
	prev := resourceProbeTimeout
	resourceProbeTimeout = d
	return func() { resourceProbeTimeout = prev }
}

// ResourceProbeTimeoutForTest is how long a capacity read is given.
func ResourceProbeTimeoutForTest() time.Duration { return resourceProbeTimeout }

// WaitResourceProbeIdleForTest blocks until no read is outstanding, so a test
// can restore what it replaced without racing the probe goroutine.
func WaitResourceProbeIdleForTest() {
	for resourceProbeRunning.Load() {
		time.Sleep(time.Millisecond)
	}
}
