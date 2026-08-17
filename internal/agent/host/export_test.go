package host

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
