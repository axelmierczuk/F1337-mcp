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

	require.True(t, w.timedOut.Load(), "the watcher did not decide to kill anything, so it signalled nothing for a second reason")
	require.Contains(t, h.logs.String(), `signal=TERM`,
		"the escalation's first signal went out to an id the collection had already given back")
	require.Contains(t, h.logs.String(), `signal=KILL`,
		"the escalation's second signal went out to an id the collection had already given back")
	require.NotContains(t, h.logs.String(), "could not signal the process group",
		"a refusal is the ordinary answer here and must not be reported as a failure to stop the command")
}

// And the call an operator makes is what gets there.
//
// The test above drives the watcher directly, which proves nothing on its own:
// the shape this repository has shipped most often is a fix asserted by calling
// the repaired function, with nothing asserting that the path a caller takes
// reaches it. This is fleet_exec's own handler, with a request whose timeout
// expires while the command is over and its group already collected.
//
// The interleaving is built out of the two facts #91 recorded rather than
// waited for. The command exits at once and leaves a descendant holding its
// stdout, and that descendant is outside the group, so the sweep cannot reach
// it: os/exec's Wait then blocks on the copiers for the whole of Cmd.WaitDelay,
// which is what keeps done open for seconds after the leader has been
// collected. The timeout and the grace are set well inside that, so both of the
// watcher's signals are decided on while the group id belongs to the kernel.
//
// What is asserted is the daemon's own record of the refusal, which is the fact
// that distinguishes this from the same run with the guard removed: there, both
// signals go out, kill(-pgid) succeeds, and nothing anywhere says so.
func TestExec_TheTimeoutsSignalsAreNotSentToAGroupTheWaitHasCollected(t *testing.T) {
	h := newHarness(t)
	// Both well inside the drain below, so the escalation happens while the
	// wait is still parked on the descendant's pipe. Nothing here is asserted
	// on how long anything took.
	h.svc.killGrace = 300 * time.Millisecond
	h.svc.ioDrain = 2 * time.Second

	pidFile := filepath.Join(t.TempDir(), "detached.pid")
	req := helperReq("spawn-exit-holding-stdout-detached", pidFile)
	req.Timeout = durationpb.New(400 * time.Millisecond)

	stream, err := h.run(t, req)
	require.NoError(t, err)

	res := stream.result()
	require.NotNil(t, res)
	require.Equal(t, int32(0), res.GetExitCode(),
		"the command exited on its own; a signalled status here means something reached it")
	require.False(t, res.GetSignaled())

	require.Contains(t, h.logs.String(), "the command had already been collected, so the timeout's signal was not sent",
		"the timeout's kill went out to a process group id this call had already released; on a developer's machine that is whatever session holds the number now")

	// The descendant is out of the sweep's reach by construction — that is what
	// keeps the wait parked — so nothing else takes it with it.
	_, grandchild := readPIDs(t, pidFile)
	requireKilled(t, grandchild)
}
