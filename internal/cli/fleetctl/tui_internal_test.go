package fleetctl

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/tui"
)

// The pool `tui` runs on, which is the one thing about this command that is
// not a flag.
//
// `fleetctl tui` and every other command in this package build a pool from the
// same credentials and opposite health settings: a one-shot listing probes
// once and must not be kept alive by a background loop it no longer needs,
// while the view's whole refresh design is that loop. There used to be two
// near-identical constructors for that and nothing checking which one `tui`
// got — swapping them left this repository green, including the end-to-end
// suite, because the first probe happens on dial either way and only the
// second one is a fleet's worth later. It is one function taking the interval
// now, and test/e2e's TestTUIDrawsTheFleetAndGivesTheTerminalBack kills an
// agent the view has already drawn as serving, which is the only place the
// second probe can be observed at all.

// controlCredentials puts a CA and a control leaf in the configured directory,
// through the two commands docs/quickstart.md tells an operator to run.
func controlCredentials(t *testing.T) {
	t.Helper()
	for _, args := range [][]string{{"ca", "init"}, {"ca", "sign", "--profile", "control"}} {
		var out bytes.Buffer
		root := NewRootCommand(&out)
		root.SetErr(&out)
		root.SetArgs(args)
		require.NoErrorf(t, root.Execute(), "fleetctl %v: %s", args, out.String())
	}
}

func TestTUIRunsOnAPoolThatKeepsProbing(t *testing.T) {
	t.Setenv("FLEET_CONFIG_DIR", t.TempDir())
	controlCredentials(t)

	var control controlFlags

	live, err := control.pool(4 * time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = live.Close() })
	require.Equal(t, 4*time.Second, live.HealthInterval(),
		"the pool does not re-probe at the interval it was given")

	// The one-shot listing every other command runs is the opposite case, and
	// asking for nothing is what gets it: a background probe against a
	// black-holed host would keep the process alive past the listing.
	once, err := control.pool(0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = once.Close() })
	require.Equal(t, oneShotHealthInterval, once.HealthInterval())
	require.Greater(t, oneShotHealthInterval, defaultHealthInterval,
		"the view and a one-shot listing are asking the pool for the same thing")

	// And the flag `tui` passes has a default of its own, so the view keeps
	// probing even when the operator names no interval.
	require.Positive(t, defaultHealthInterval)
	require.Less(t, defaultHealthInterval, time.Minute,
		"a machine going away would not be noticed while the operator is still looking at the screen")

	// `tui --refresh 0` reaches the same place as `tui`, rather than the
	// one-shot interval, which would be a view whose health stopped after the
	// first probe and never said so. That the flag reaches the pool from the
	// command line is TestTheRefreshFlagReachesThePoolTheViewRunsOn below —
	// this used to claim test/e2e covered it, which it does not: that scenario
	// waits a minute for a re-probe the ten-second default also delivers, so
	// what it pins is that the view gets a probing pool at all.
	require.Equal(t, defaultHealthInterval, healthIntervalFor(0))
	require.Equal(t, defaultHealthInterval, healthIntervalFor(-time.Second))
	require.Equal(t, 5*time.Second, healthIntervalFor(5*time.Second))
}

// TestTheRefreshFlagReachesThePoolTheViewRunsOn.
//
// The interval is what decides whether a machine going away is noticed while
// the operator is still looking at the screen, and until now nothing connected
// the flag to the pool: healthIntervalFor was asserted on its own, pool() was
// asserted on its own, and the line in RunE that composes them was covered by
// neither. Replacing it with the default left this repository green, end-to-end
// suite included — that scenario waits a minute for a re-probe the default
// delivers in ten seconds, so it pins "the view gets a probing pool" and not
// "the flag reaches it".
//
// This drives the command an operator types: cobra parses the real flags, RunE
// refuses because a buffer is not a terminal, and the pool is then built the
// one way the command builds it.
func TestTheRefreshFlagReachesThePoolTheViewRunsOn(t *testing.T) {
	t.Setenv("FLEET_CONFIG_DIR", t.TempDir())
	controlCredentials(t)

	cases := []struct {
		name string
		args []string
		want time.Duration
	}{
		{"no flag at all", nil, defaultHealthInterval},
		{"an interval the operator chose", []string{"--refresh", "5s"}, 5 * time.Second},
		{"a slower one", []string{"--refresh", "45s"}, 45 * time.Second},
		// Nought is the flag's default rather than "never": a pool asked for no
		// interval gives a one-shot command what it wants, and here that is a
		// view whose health stopped after the first probe and never said so.
		{"nought", []string{"--refresh", "0"}, defaultHealthInterval},
		{"a negative one", []string{"--refresh", "-1s"}, defaultHealthInterval},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				f   tuiFlags
				out bytes.Buffer
			)
			cmd := newTUICommandWith(&out, &f)
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs(tc.args)
			require.ErrorIs(t, cmd.Execute(), tui.ErrNotATerminal,
				"the command did not get as far as parsing its flags")

			pool, err := f.pool()
			require.NoError(t, err)
			t.Cleanup(func() { _ = pool.Close() })
			require.Equal(t, tc.want, pool.HealthInterval(),
				"the pool the view runs on does not re-probe at the interval the command line asked for")
		})
	}
}
