package fleetagent

import "github.com/axelmierczuk/fleet-mcp/internal/version"

// reportedVersion is the agent's version as every machine-readable surface
// reports it: the AgentVersion the registry stores at enrollment, and the one
// HostService.Health and HostService.GetHostInfo answer with at runtime.
//
// One function because those are two call sites for a single fact, in two
// files, and they drifted: enrollment sent version.String() — the banner,
// "dev (unknown, built unknown)" — while the daemon reported version.Version,
// "dev". `fleetctl list` prefers the live value and falls back to the stored
// one, so the AGENT column changed shape at the moment a host went unreachable
// and invited the reading that the agent itself had changed. See #61.
//
// version.String() is a banner. It belongs where a human reads one line about
// a binary — `fleet-agent version`, and the daemon's "agent starting" log —
// and nowhere that a column, a filter, or a comparison will see it.
func reportedVersion() string { return version.Version }
