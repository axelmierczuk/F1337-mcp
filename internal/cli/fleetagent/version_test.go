package fleetagent_test

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	"github.com/axelmierczuk/fleet-mcp/internal/cli/fleetagent"
	"github.com/axelmierczuk/fleet-mcp/internal/version"
)

// The agent reports its version from two places — the AgentVersion recorded at
// enrollment, and the one the running daemon answers Health and GetHostInfo
// with — and `fleetctl list` renders whichever answered into a single AGENT
// column, preferring the live value. They disagreed: enrollment sent the
// banner, "dev (unknown, built unknown)", and the daemon sent "dev", so the
// column changed shape at the instant a host went unreachable (#61).
//
// This is the test that keeps them together. Changing either call site back
// fails it, which is the point: the one-line fix is worth less than the thing
// that stops it drifting a second time.
func TestEnrollmentAndDaemonReportTheSameAgentVersion(t *testing.T) {
	req := fleetagent.EnrollRequestForTest("token", []byte("csr"), "build-box", []string{"127.0.0.1:19500"})
	opts := fleetagent.ServerOptionsForTest(&agent.Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)), 0)

	require.Equal(t, opts.Version, req.GetAgentVersion(),
		"the version stored at enrollment and the version the daemon reports are one column in `fleetctl list`; "+
			"a host that goes unreachable must not appear to change version")

	// And which of the two it is. Both paths agreeing on version.String() would
	// satisfy the assertion above while still putting a banner in a table
	// column, so pin the value as well as the agreement.
	assert.Equal(t, version.Version, req.GetAgentVersion(),
		"a table column takes version.Version; version.String() is a banner")
	assert.NotContains(t, req.GetAgentVersion(), " ",
		"the reported version is a single token, not a sentence")
}

// The banner is still a banner. version.String() has a place — `fleet-agent
// version` and the daemon's start-up log — and this records that removing the
// two machine-readable uses did not mean removing the type of string.
func TestBannerStillCarriesCommitAndDate(t *testing.T) {
	banner := version.String()
	assert.True(t, strings.HasPrefix(banner, version.Version+" ("),
		"the banner is the reported version plus its build metadata, got %q", banner)
	assert.NotEqual(t, version.Version, banner,
		"if these were equal the test above would prove nothing about which value was chosen")
}
