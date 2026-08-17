package host

// SetProberForTest replaces the toolchain prober, so a test can assert that
// Health never reaches it. Health's cheapness is a load-bearing property —
// every connected MCP server calls it on a timer — and asserting it by timing
// alone would be a test that passes on a fast machine and flakes on a slow one.
func (s *Service) SetProberForTest(p *Prober) { s.prober = p }
