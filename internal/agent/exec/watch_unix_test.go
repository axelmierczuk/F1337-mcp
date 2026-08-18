//go:build unix

package exec

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
	"github.com/axelmierczuk/fleet-mcp/internal/security/policy"
)

// These are #105: the timeout watcher signals the same process group that the
// call's own wait is about to collect, and on Unix collecting the leader of an
// emptied group is what hands its id back to the kernel.
//
// Unix only, and not for want of a Windows equivalent. There is no id to hand
// back there: the group signals the job through a handle it created and the
// leader through a handle it pinned at Adopt, so a signal sent after the wait
// is as well aimed as one sent before it. See platform.ProcessGroup.Collect.

// The watcher's signals are refused once the group's own wait has collected the
// leader.
//
// The state is arranged rather than raced for: waitForCommand is what run's
// wait goroutine calls, and after it the group has released its id. The watcher
// is then given a done channel that never closes, which is exactly what it sees
// during the window this is about — run closes done only after waitForCommand
// has returned, and os/exec's Wait does not return until the output copiers do.
// So this is the product goroutine, deciding to kill a command it has every
// reason to believe is still running, against a group that knows better.
func TestWatch_DoesNotSignalAGroupWhoseLeaderHasBeenCollected(t *testing.T) {
	group, cmd := isolatedChild(t, "exit", "0")
	require.NoError(t, waitForCommand(cmd, group, testLogger(&strings.Builder{})),
		"the command exited 0 of its own accord, and its group has been swept and collected")

	h := newHarness(t)
	w := h.svc.watch(context.Background(), group, time.Millisecond, make(chan struct{}))
	<-w.finished

	// The watcher did decide to signal — the line below is written by the call
	// that tried — and the group refused it.
	require.Contains(t, h.logs.String(), `signal=TERM`,
		"the watcher never signalled anything, so it reached the id for a second reason")
	require.NotContains(t, h.logs.String(), `signal=KILL`,
		"the escalation carried on after the refusal; there is nothing left to escalate to and the second signal is refused for the same reason")
	require.NotContains(t, h.logs.String(), "could not signal the process group",
		"a refusal is the ordinary answer here and must not be reported as a failure to stop the command")

	// And the command is not recorded as one the agent killed. It had already
	// finished, which is exactly what the refusal establishes and what the
	// select on done above it cannot see.
	require.False(t, w.timedOut.Load(),
		"the audit record would say the agent timed out a command that had already exited on its own")
}

// And the call an operator makes is what gets there.
//
// The test above drives the watcher directly, which proves nothing on its own:
// the shape this repository has shipped most often is a fix asserted by calling
// the repaired function, with nothing asserting that the path a caller takes
// reaches it. This is fleet_exec's own handler, on the other of the two events
// that make it signal — the caller going away — because that one can be
// triggered at an instant the test chooses rather than waited for.
//
// Nothing here is timed. The interleaving is built out of the two facts #91
// recorded: the command exits at once and leaves a descendant holding its
// stdout, and that descendant is outside the group, so the sweep cannot reach
// it and os/exec's Wait stays parked on the copiers. The test then *watches*
// for the leader's pid to stop existing — which is the collection, because a
// process that has exited and not been collected still holds its pid — and only
// then cancels the call. So the signal is decided on after the group id has
// been released, by construction rather than by luck.
//
// Two facts are asserted. The daemon says it refused to signal, which is what
// distinguishes this from the same run with the guard removed — there, the
// signal goes out, kill(-pgid) succeeds and nothing anywhere says so. And the
// result does not claim the command was cancelled: it had already finished, and
// a record that says otherwise says the agent killed something it did not.
func TestExec_TheWatchersSignalIsNotSentToAGroupTheWaitHasCollected(t *testing.T) {
	h := newHarness(t)

	pidFile := filepath.Join(t.TempDir(), "detached.pid")
	// The grandchild holds the output pipe for long enough that the wait is
	// still parked when the call is cancelled, and lets go long before the
	// drain that would otherwise end the call — so the handler returns with a
	// result rather than giving up on a stalled stream.
	req := helperReq("spawn-exit-holding-stdout-detached", pidFile, "1")
	req.Timeout = durationpb.New(30 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := newFakeStream(ctx)
	returned := make(chan error, 1)
	go func() { returned <- h.svc.Exec(req, stream) }()

	leader, grandchild := readPIDs(t, pidFile)
	waitForPID(t, "the command's leader to be collected", func() bool {
		// A process that has exited and not been collected still holds its pid,
		// so this stops being true at the collection and at nothing else.
		return !platform.ProcessExists(leader)
	})

	cancel()
	select {
	case err := <-returned:
		require.NoError(t, err)
	case <-time.After(60 * time.Second):
		t.Fatal("Exec did not return; the handler is wedged")
	}

	res := stream.result()
	require.NotNil(t, res)
	require.Equal(t, int32(0), res.GetExitCode(),
		"the command exited on its own; a signalled status here means something reached it")
	require.False(t, res.GetSignaled())

	require.Contains(t, h.logs.String(), "the command had already been collected, so the timeout's signal was not sent",
		"the signal went out to a process group id this call had already released; on a developer's machine that is whatever session holds the number now")

	records := h.records(t)
	require.Len(t, records, 1)
	require.Equal(t, policy.OutcomeOK, records[0].Outcome,
		"the record says the agent killed a command that had already finished on its own")

	requireKilled(t, grandchild)
}

// waitForPID polls a fact about a pid until it holds. Every wait in this file
// is on something observed rather than on a duration; the deadline is only a
// bound on the failure.
func waitForPID(t *testing.T, what string, ok func() bool) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
