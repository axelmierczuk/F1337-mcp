package platform_test

import (
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/platform"
)

// jobName builds a job object name unique to this test binary. Job names are
// global to the session, and two groups given the same name silently share one
// job.
func jobName(suffix string) string {
	return "sandboxd-test-" + strconv.Itoa(os.Getpid()) + "-" + suffix
}

// TestGroupConfig_KillOnCloseWithANameIsRefused pins the one combination of
// GroupConfig that cannot mean anything.
//
// Name is what lets a restarted agent reopen the job with OpenProcessGroup;
// KillOnClose is what kills every process in that job when the agent that made
// it exits. Together they say "keep these processes across my restart" and
// "kill them at my restart", and the kill is the half that happens — so an
// agent upgrade would take down every supervised process on the host. Refusing
// at construction is what makes that unwritable rather than merely documented.
//
// It runs on every platform, though both fields are ignored on Unix, because
// the point is that the mistake surfaces on the developer's own machine rather
// than on the one host that would act on it.
func TestGroupConfig_KillOnCloseWithANameIsRefused(t *testing.T) {
	t.Parallel()

	g, err := platform.NewProcessGroup(platform.GroupConfig{
		Name:        jobName("refused"),
		KillOnClose: true,
	})
	require.ErrorIs(t, err, platform.ErrKillOnCloseNamedJob)
	require.Nil(t, g, "a refused configuration must not hand back a group to close")
}

// TestGroupConfig_LegitimateCombinations is the other half: the three shapes
// the agent actually uses must all still be accepted, so the check above
// cannot be satisfied by refusing more than it should.
func TestGroupConfig_LegitimateCombinations(t *testing.T) {
	t.Parallel()

	cases := map[string]platform.GroupConfig{
		"one-shot exec":              {KillOnClose: true},
		"supervised, re-adoptable":   {Name: jobName("supervised")},
		"supervised, no re-adoption": {},
	}

	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			g, err := platform.NewProcessGroup(cfg)
			require.NoError(t, err)
			require.NotNil(t, g)
			require.NoError(t, g.Close())
		})
	}
}
