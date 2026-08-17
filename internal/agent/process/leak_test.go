package process

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

// A supervisor with a log tailer and a probe loop per process is exactly where
// goroutines accumulate, and the leak does not announce itself: it shows up as
// an agent that slowly stops working on a host nobody is watching. These tests
// run the full lifecycle and require the count to come back down.
//
// They are deliberately not parallel. NumGoroutine is process-wide, so a
// parallel test's goroutines would be indistinguishable from a leak.

func TestNoGoroutineLeakAcrossTheProcessLifecycle(t *testing.T) {
	leakCheck(t)

	ts := newTestSupervisor(t)

	for i := range 10 {
		r := ts.startHelper(fmt.Sprintf("cycle-%d", i), "echo", "20", "5", "chatter")
		waitState(t, r, 20*time.Second,
			sandboxdv1.ProcessState_PROCESS_STATE_EXITED,
			sandboxdv1.ProcessState_PROCESS_STATE_CRASHED)
		require.NoError(t, ts.remove(r, false, true))
	}
	require.NoError(t, ts.Close())
}

func TestNoGoroutineLeakFromProbesAndFollows(t *testing.T) {
	leakCheck(t)

	ts := newTestSupervisor(t, func(c *supervisorConfig) { c.maxFollowDuration = 200 * time.Millisecond })

	for i := range 5 {
		probe := testProbe(probeLogPattern, 300*time.Millisecond)
		probe.patternSrc = "never matches"
		probe.pattern = mustCompile(t, probe.patternSrc)

		// A probe that times out, a follow that hits its deadline, and a follow
		// whose caller hangs up: the three ways these loops end.
		r, err := ts.startProbed(fmt.Sprintf("probed-%d", i), probe, "silent")
		require.Error(t, err)

		require.NoError(t, ts.streamLogs(context.Background(), r, logRequest{
			sel: selector{tail: 10}, follow: true, followFor: 100 * time.Millisecond,
		}, &recordingStream{}))

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(20 * time.Millisecond)
			cancel()
		}()
		_ = ts.streamLogs(ctx, r, logRequest{
			sel: selector{tail: 10}, follow: true, followFor: time.Hour,
		}, &recordingStream{})
		cancel()

		require.NoError(t, ts.remove(r, true, true))
	}
	require.NoError(t, ts.Close())
}

func TestNoGoroutineLeakAcrossRestarts(t *testing.T) {
	leakCheck(t)

	ts := newTestSupervisor(t)

	spec := ts.helperSpec("restarting", "exit", "1", "20")
	spec.restartPolicy = sandboxdv1.RestartPolicy_RESTART_POLICY_ALWAYS
	spec.maxRestarts = 3
	spec.restartBackoff = 10 * time.Millisecond
	r, err := ts.start(spec, false)
	require.NoError(t, err)

	waitFor(t, 30*time.Second, "the restart budget to be exhausted", func() bool {
		return r.currentState() == sandboxdv1.ProcessState_PROCESS_STATE_CRASHED &&
			r.status().GetRestartCount() >= 3
	})
	require.NoError(t, ts.remove(r, false, true))
	require.NoError(t, ts.Close())
}
