package mcpserver_test

import (
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/mcpserver/tools"
)

// ---------------------------------------------------- start and readiness

// The criterion this whole feature exists for: a probe that has actually
// passed before the call returns, not one that has merely been configured.
func TestProcessStart_TCPProbeReturnsOnlyOnceThePortIsLive(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	port := freePort(t)

	args := f.startHelper("web-dev", "listen", "600", strconv.Itoa(port))
	args["ready_probe"] = map[string]any{"tcp_port": port, "timeout_seconds": 20}

	before := time.Now()
	out := liveOK[tools.ProcessStartResult](f, "sandbox_process_start", args)
	elapsed := time.Since(before)

	require.Empty(t, out.ReadyError, "the probe should have passed")
	require.NotNil(t, out.Ready)
	assert.True(t, *out.Ready)
	assert.Equal(t, "ready", out.Process.State)

	// The port is live *now*, from this process, with no retry loop. That is
	// the property "wait_for_ready" is supposed to buy and the one a model
	// relies on when it makes its next call immediately.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 3*time.Second)
	require.NoError(t, err, "the port must accept a connection the instant the tool returns")
	require.NoError(t, conn.Close())

	// And it waited: the child binds after 600ms, so a call that returned
	// sooner did not wait for anything.
	assert.Greater(t, elapsed, 500*time.Millisecond, "the call must have waited for the probe")

	stop(t, f, out.Process.ProcessID)
}

// wait_for_ready defaults to true whenever a probe is set: a caller that
// described readiness and then did not wait for it has the same problem as one
// with no probe at all.
func TestProcessStart_AProbeIsWaitedOnWithoutAskingForIt(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	port := freePort(t)

	args := f.startHelper("implicit-wait", "listen", "400", strconv.Itoa(port))
	args["ready_probe"] = map[string]any{"tcp_port": port, "timeout_seconds": 20}
	// No wait_for_ready.

	out := liveOK[tools.ProcessStartResult](f, "sandbox_process_start", args)
	require.NotNil(t, out.Ready)
	assert.True(t, *out.Ready)
	assert.Equal(t, "ready", out.Process.State)

	stop(t, f, out.Process.ProcessID)
}

// A probe timeout must return ready_error *and* the logs, with the process
// still running. A readiness failure reported on its own sends the model
// straight into another tool call, which is the turn this is meant to save.
func TestProcessStart_ProbeTimeoutReturnsReadyErrorAndLogs(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})

	args := f.startHelper("never-ready", "chatter", "6", "40", "starting up")
	args["ready_probe"] = map[string]any{
		"log_pattern":     "this pattern never appears",
		"timeout_seconds": 1,
	}
	args["wait_for_ready"] = true

	out := liveOK[tools.ProcessStartResult](f, "sandbox_process_start", args)

	require.NotEmpty(t, out.ReadyError, "a probe that cannot pass must report ready_error")
	require.NotNil(t, out.Ready)
	assert.False(t, *out.Ready)
	assert.Contains(t, out.RecentLogs, "starting up",
		"ready_error without logs is the failure this returns logs to prevent")
	assert.Contains(t, out.Note, "left running")

	// Still running, so the logs above are readable and stopping it is the
	// caller's decision.
	list := liveOK[tools.ProcessListResult](f, "sandbox_process_list", map[string]any{})
	found := findProcess(t, list, out.Process.ProcessID)
	assert.NotEqual(t, "exited", found.State)
	assert.NotEqual(t, "crashed", found.State)
	assert.Positive(t, found.PID, "a process left running for its logs must still have a pid")

	stop(t, f, out.Process.ProcessID)
}

// The ready_probe schema is the highest-leverage thing here, so its failure
// modes have to be legible rather than silently accepted.
func TestProcessStart_ProbeSchemaRejectsAmbiguityWithAUsableMessage(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})

	t.Run("no condition", func(t *testing.T) {
		args := f.startHelper("no-condition", "silent")
		args["ready_probe"] = map[string]any{"timeout_seconds": 5}
		msg := f.liveFails("sandbox_process_start", args)
		assert.Contains(t, msg, "exactly one")
		assert.Contains(t, msg, "tcp_port")
	})

	t.Run("two conditions", func(t *testing.T) {
		args := f.startHelper("two-conditions", "silent")
		args["ready_probe"] = map[string]any{"tcp_port": 3000, "log_pattern": "ready"}
		msg := f.liveFails("sandbox_process_start", args)
		assert.Contains(t, msg, "exactly one")
		assert.Contains(t, msg, "log_pattern")
		assert.Contains(t, msg, "tcp_port")
	})
}

// A start with no probe says so, and says why it matters. The sentence is the
// point: it is what stops "started" being read as "usable".
func TestProcessStart_WithoutAProbeSaysWhatStartedDoesNotMean(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})

	out := liveOK[tools.ProcessStartResult](f, "sandbox_process_start", f.startHelper("bare", "silent"))
	assert.Nil(t, out.Ready, "with no probe, readiness has no answer rather than a false one")
	assert.Contains(t, out.Note, "ready_probe")

	stop(t, f, out.Process.ProcessID)
}

// ------------------------------------------------------------------ list

// Twenty processes have to stay compact, because a listing that costs a
// thousand tokens per check is one a model stops making.
func TestProcessList_StaysCompactAtTwentyProcesses(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})

	ids := make([]string, 0, 20)
	for i := range 20 {
		out := liveOK[tools.ProcessStartResult](f, "sandbox_process_start",
			f.startHelper(fmt.Sprintf("svc-%02d", i), "chatter", "3", "5", "a moderately long log line from a dev server"))
		ids = append(ids, out.Process.ProcessID)
	}

	res := f.call("sandbox_process_list", map[string]any{})
	require.False(t, res.IsError, resultText(res))
	out := structured[tools.ProcessListResult](t, res)
	require.Len(t, out.Processes, 20)

	// The whole result, as the model actually receives it.
	payload := len(resultText(res))
	t.Logf("twenty-process listing: %d bytes total, table %d bytes", payload, len(out.Table))
	assert.Less(t, payload, 12*1024,
		"a twenty-process listing must stay small enough to call routinely")

	// Every column the issue names is in the table, and the table is legible:
	// one header line and one line per process, no wrapping.
	lines := strings.Split(strings.TrimSpace(out.Table), "\n")
	header := lines[0]
	for _, col := range []string{"STATE", "NAME", "PID", "UPTIME", "RST", "PORTS", "LAST LOG"} {
		assert.Contains(t, header, col)
	}
	rows := 0
	for _, line := range lines[1:] {
		if strings.HasPrefix(line, "svc-") || strings.Contains(line, "svc-") {
			rows++
			assert.Less(t, len(line), 200, "a row must fit on a line: %q", line)
		}
	}
	assert.Equal(t, 20, rows, "one row per process")

	for _, id := range ids {
		stop(t, f, id)
	}
}

// A listing has to say enough about a process to act on without a second call.
func TestProcessList_ReportsStatePidUptimeRestartsPortsAndLastLine(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	port := freePort(t)

	args := f.startHelper("with-port", "listen", "0", strconv.Itoa(port))
	args["ready_probe"] = map[string]any{"tcp_port": port, "timeout_seconds": 20}
	started := liveOK[tools.ProcessStartResult](f, "sandbox_process_start", args)

	var row tools.ProcessLine
	eventually(t, 15*time.Second, "the listing to report the listening port", func() bool {
		out := liveOK[tools.ProcessListResult](f, "sandbox_process_list", map[string]any{})
		row = findProcess(t, out, started.Process.ProcessID)
		return len(row.ListeningPorts) > 0
	})

	assert.Equal(t, "ready", row.State)
	assert.Positive(t, row.PID)
	assert.NotEmpty(t, row.Uptime)
	assert.Contains(t, row.ListeningPorts, uint32(port)) //nolint:gosec // a port from the kernel is in range
	assert.Contains(t, row.LastLogLine, "listening on")

	stop(t, f, started.Process.ProcessID)
}

func TestProcessList_FiltersByStateAndName(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})

	alive := liveOK[tools.ProcessStartResult](f, "sandbox_process_start", f.startHelper("keeper", "silent"))
	gone := liveOK[tools.ProcessStartResult](f, "sandbox_process_start", f.startHelper("goner", "exit", "0", "0"))

	eventually(t, 15*time.Second, "the short-lived process to exit", func() bool {
		out := liveOK[tools.ProcessListResult](f, "sandbox_process_list", map[string]any{})
		return findProcess(t, out, gone.Process.ProcessID).State == "exited"
	})

	byState := liveOK[tools.ProcessListResult](f, "sandbox_process_list", map[string]any{"states": []any{"exited"}})
	require.Len(t, byState.Processes, 1)
	assert.Equal(t, "goner", byState.Processes[0].Name)

	byName := liveOK[tools.ProcessListResult](f, "sandbox_process_list", map[string]any{"name_pattern": "^keep"})
	require.Len(t, byName.Processes, 1)
	assert.Equal(t, "keeper", byName.Processes[0].Name)

	none := liveOK[tools.ProcessListResult](f, "sandbox_process_list", map[string]any{"name_pattern": "^nothing$"})
	assert.Empty(t, none.Processes)
	assert.Contains(t, none.Hint, "filter")

	stop(t, f, alive.Process.ProcessID)
}

// ------------------------------------------------------------------ logs

// Follow always returns within its deadline, including for a process that
// produces nothing at all. A call that never returns cannot be told apart from
// a hung agent, and a model cannot recover from it.
func TestProcessLogs_FollowReturnsOnASilentProcess(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{maxFollowDuration: 2 * time.Second})

	started := liveOK[tools.ProcessStartResult](f, "sandbox_process_start", f.startHelper("mute", "silent"))

	before := time.Now()
	out := liveOK[tools.ProcessLogsResult](f, "sandbox_process_logs", map[string]any{
		"process_id":     started.Process.ProcessID,
		"follow":         true,
		"follow_seconds": 2,
	})
	elapsed := time.Since(before)

	assert.True(t, out.FollowDeadlineReached, "a silent process must still end at the deadline")
	assert.Less(t, elapsed, 20*time.Second, "the follow must return, and return near its bound")
	assert.GreaterOrEqual(t, elapsed, 1500*time.Millisecond, "it must actually have followed")
	assert.Contains(t, out.Note, "deadline")

	stop(t, f, started.Process.ProcessID)
}

// A follow asking for longer than the agent permits is clamped, not honoured.
func TestProcessLogs_FollowIsClampedToTheAgentMaximum(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{maxFollowDuration: time.Second})

	started := liveOK[tools.ProcessStartResult](f, "sandbox_process_start", f.startHelper("mute-2", "silent"))

	before := time.Now()
	out := liveOK[tools.ProcessLogsResult](f, "sandbox_process_logs", map[string]any{
		"process_id":     started.Process.ProcessID,
		"follow":         true,
		"follow_seconds": 45,
	})
	assert.True(t, out.FollowDeadlineReached)
	assert.Less(t, time.Since(before), 30*time.Second, "the agent's maximum must win over the request")

	stop(t, f, started.Process.ProcessID)
}

// A gap in the log has to be visible. A log with a silent hole in it is worse
// than one that says it has a hole, because a reader draws conclusions from
// the adjacency of two lines that were never adjacent.
func TestProcessLogs_DroppedLinesAreMarkedInline(t *testing.T) {
	// Both bounds are shrunk: the ring alone loses nothing, because the
	// rotating file behind it is what makes the ring's contents recoverable.
	// A line is genuinely gone only once it has fallen out of both.
	f := newLiveFixture(t, liveAgentOptions{ringBufferLines: 20, maxLogBytes: 4096})

	const lines = 8000
	started := liveOK[tools.ProcessStartResult](f, "sandbox_process_start",
		f.startHelper("firehose", "spew", strconv.Itoa(lines)))

	// Wait for the process to have written everything, then assert once.
	//
	// Polling the logs call instead is what this used to do, and it is a poll
	// that fights the thing it is waiting for: the ring cannot cover a
	// four-thousand-line tail, so every one of those calls re-reads the whole
	// retained history off disk, and fifteen hundred of them in thirty seconds
	// compete with the process for the same disk on the way to a conclusion
	// about that process. The listing is cheap, and "the last line it will ever
	// write has arrived" is a defined moment rather than an eventual one — at
	// which eight thousand lines through a twenty-line ring and a 4 KiB log
	// must have lost some, on every platform.
	last := fmt.Sprintf("spew %d ", lines-1)
	eventually(t, 90*time.Second, "the process to finish writing its output", func() bool {
		list := liveOK[tools.ProcessListResult](f, "sandbox_process_list", map[string]any{})
		return strings.Contains(findProcess(t, list, started.Process.ProcessID).LastLogLine, last)
	})

	out := liveOK[tools.ProcessLogsResult](f, "sandbox_process_logs", map[string]any{
		"process_id": started.Process.ProcessID,
		"tail_lines": 4000,
	})
	require.Positive(t, out.LinesDropped,
		"a process that outran both the ring and the rotated file must have its drops counted")
	assert.Contains(t, out.Logs, "dropped", "the gap must be marked in the rendered log")
	assert.Contains(t, out.Note, "dropped")

	stop(t, f, started.Process.ProcessID)
}

func TestProcessLogs_SeparatesStdoutFromStderr(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})

	started := liveOK[tools.ProcessStartResult](f, "sandbox_process_start",
		f.startHelper("two-streams", "stderr", "a warning"))

	var both tools.ProcessLogsResult
	eventually(t, 20*time.Second, "both streams to appear", func() bool {
		both = liveOK[tools.ProcessLogsResult](f, "sandbox_process_logs", map[string]any{
			"process_id": started.Process.ProcessID,
		})
		return strings.Contains(both.Logs, "on stdout") && strings.Contains(both.Logs, "a warning")
	})
	assert.Contains(t, both.Logs, "E| a warning", "stderr must be distinguishable from stdout")
	assert.NotContains(t, both.Logs, "E| on stdout")

	onlyErr := liveOK[tools.ProcessLogsResult](f, "sandbox_process_logs", map[string]any{
		"process_id": started.Process.ProcessID,
		"stream":     "stderr",
	})
	assert.Contains(t, onlyErr.Logs, "a warning")
	assert.NotContains(t, onlyErr.Logs, "on stdout")

	stop(t, f, started.Process.ProcessID)
}

func TestProcessLogs_UnknownProcessIDListsTheValidOnes(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	started := liveOK[tools.ProcessStartResult](f, "sandbox_process_start", f.startHelper("real-one", "silent"))

	msg := f.liveFails("sandbox_process_logs", map[string]any{"process_id": "not-a-real-id"})
	assert.Contains(t, msg, "not-a-real-id")
	assert.Contains(t, msg, started.Process.ProcessID)
	assert.Contains(t, msg, "real-one")

	stop(t, f, started.Process.ProcessID)
}

// Every seconds-valued argument in this group is refused by name when it is
// negative, rather than quietly becoming a default. A caller who sent one got
// the number wrong, and a call that silently substitutes its own teaches them
// the argument was accepted — which is the same class of quiet acceptance the
// probe's two float arguments were fixed for.
func TestProcessTools_RefuseANegativeSecondsArgument(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	started := liveOK[tools.ProcessStartResult](f, "sandbox_process_start", f.startHelper("bounded", "silent"))

	for _, tc := range []struct {
		tool     string
		args     map[string]any
		argument string
	}{
		{"sandbox_process_logs", map[string]any{
			"process_id": started.Process.ProcessID, "follow": true, "follow_seconds": -5,
		}, "follow_seconds"},
		{"sandbox_process_restart", map[string]any{
			"process_id": started.Process.ProcessID, "ready_timeout_seconds": -1,
		}, "ready_timeout_seconds"},
		{"sandbox_process_signal", map[string]any{
			"process_id": started.Process.ProcessID, "graceful_stop": true, "grace_seconds": -1,
		}, "grace_seconds"},
	} {
		msg := f.liveFails(tc.tool, tc.args)
		assert.Containsf(t, msg, tc.argument, "%s must name the argument it refused", tc.tool)
		assert.Containsf(t, msg, "negative", "%s must say why", tc.tool)
	}

	stop(t, f, started.Process.ProcessID)
}

// ---------------------------------------------------------------- signal

// A graceful stop has to report whether it escalated, because "stopped" and
// "killed after refusing to stop" are different facts about the process.
func TestProcessSignal_GracefulStopReportsEscalationToKill(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{gracePeriod: time.Second})

	t.Run("a process that exits on TERM does not escalate", func(t *testing.T) {
		started := liveOK[tools.ProcessStartResult](f, "sandbox_process_start", f.startHelper("polite", "silent"))
		out := liveOK[tools.ProcessSignalResult](f, "sandbox_process_signal", map[string]any{
			"process_id":      started.Process.ProcessID,
			"graceful_stop":   true,
			"grace_seconds":   5,
			"disable_restart": true,
		})
		assert.False(t, out.EscalatedToKill)
		assert.Contains(t, out.Note, "not killed")
	})

	t.Run("a process that ignores TERM escalates and says so", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			// There is no SIGTERM to ignore: the agent terminates the job
			// object, which no process can decline, so escalation is
			// unreachable rather than untested.
			t.Skip("Windows terminates the job object rather than delivering SIGTERM")
		}
		// Waited for, not assumed: the child ignores SIGTERM only once it has
		// installed the disposition, and a signal that beats it there is
		// delivered to a process that still dies on it.
		args := f.startHelper("stubborn", "deaf")
		args["ready_probe"] = map[string]any{"log_pattern": "ignoring SIGTERM", "timeout_seconds": 30}
		started := liveOK[tools.ProcessStartResult](f, "sandbox_process_start", args)
		require.Empty(t, started.ReadyError, "the child must have installed its signal handler before it is signalled")

		out := liveOK[tools.ProcessSignalResult](f, "sandbox_process_signal", map[string]any{
			"process_id":      started.Process.ProcessID,
			"graceful_stop":   true,
			"grace_seconds":   1,
			"disable_restart": true,
		})
		assert.True(t, out.EscalatedToKill, "a process that ignores SIGTERM must be reported as killed")
		assert.Contains(t, out.Note, "SIGKILL")
	})
}

// Signalling an id that does not exist has to name the ones that do.
func TestProcessSignal_UnknownProcessIDListsTheValidOnes(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})

	one := liveOK[tools.ProcessStartResult](f, "sandbox_process_start", f.startHelper("alpha", "silent"))
	two := liveOK[tools.ProcessStartResult](f, "sandbox_process_start", f.startHelper("beta", "silent"))

	msg := f.liveFails("sandbox_process_signal", map[string]any{
		"process_id": "web-dev-typo",
		"signal":     "TERM",
	})
	assert.Contains(t, msg, "web-dev-typo")
	assert.Contains(t, msg, one.Process.ProcessID)
	assert.Contains(t, msg, two.Process.ProcessID)
	assert.Contains(t, msg, "alpha")
	assert.Contains(t, msg, "beta")

	stop(t, f, one.Process.ProcessID)
	stop(t, f, two.Process.ProcessID)
}

// With nothing running at all the message says that rather than listing an
// empty set, because "no processes" and "wrong id" need different fixes.
func TestProcessSignal_UnknownProcessIDWithAnEmptyAgentSaysSo(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	msg := f.liveFails("sandbox_process_signal", map[string]any{"process_id": "nothing", "signal": "TERM"})
	assert.Contains(t, msg, "no processes at all")
	assert.Contains(t, msg, "sandbox_process_start")
}

func TestProcessSignal_RejectsAnUnknownSignalName(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	msg := f.liveFails("sandbox_process_signal", map[string]any{"process_id": "x", "signal": "SIGBANANA"})
	assert.Contains(t, msg, "TERM")
}

// --------------------------------------------------------------- restart

// A restart is the same process, not a similar one: the id it is found by has
// to survive, or every reference the model holds becomes stale.
func TestProcessRestart_PreservesTheProcessIDAndReportsTheNewState(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	port := freePort(t)

	args := f.startHelper("restarter", "listen", "0", strconv.Itoa(port))
	args["ready_probe"] = map[string]any{"tcp_port": port, "timeout_seconds": 20}
	started := liveOK[tools.ProcessStartResult](f, "sandbox_process_start", args)
	require.Equal(t, "ready", started.Process.State)
	firstPID := started.Process.PID

	out := liveOK[tools.ProcessRestartResult](f, "sandbox_process_restart", map[string]any{
		"process_id":    started.Process.ProcessID,
		"grace_seconds": 5,
	})

	assert.Equal(t, started.Process.ProcessID, out.Process.ProcessID, "a restart keeps the process id")
	assert.Equal(t, "ready", out.Process.State, "and reports the state it reached")
	require.NotNil(t, out.Ready)
	assert.True(t, *out.Ready)
	assert.NotEqual(t, firstPID, out.Process.PID, "a restart is a new OS process under the same id")
	// The restart counter is the supervisor's automatic-restart budget, and an
	// explicit restart deliberately does not spend it: a caller restarting by
	// hand must not exhaust the recovery the policy is holding in reserve.
	assert.Zero(t, out.Process.RestartCount)
	assert.Contains(t, out.Note, "unchanged")

	// And the port is live again, which is what "ready" is claiming.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 3*time.Second)
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	stop(t, f, started.Process.ProcessID)
}

func TestProcessRestart_UnknownProcessIDListsTheValidOnes(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})
	started := liveOK[tools.ProcessStartResult](f, "sandbox_process_start", f.startHelper("only", "silent"))

	msg := f.liveFails("sandbox_process_restart", map[string]any{"process_id": "wrong"})
	assert.Contains(t, msg, started.Process.ProcessID)

	stop(t, f, started.Process.ProcessID)
}

// ------------------------------------------------------------------ echo

// The echo is asserted on every successful call by liveOK. This covers the
// path liveOK cannot: an explicit sandbox argument, which must win over the
// sticky selection and be what comes back.
func TestProcessTools_EchoTheResolvedSandbox(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})

	started := liveOK[tools.ProcessStartResult](f, "sandbox_process_start", f.startHelper("echoed", "silent"))

	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"sandbox_process_list", map[string]any{"sandbox": liveSandboxName}},
		{"sandbox_process_logs", map[string]any{"sandbox": liveSandboxName, "process_id": started.Process.ProcessID}},
		{"sandbox_process_restart", map[string]any{"sandbox": liveSandboxName, "process_id": started.Process.ProcessID}},
		{"sandbox_process_signal", map[string]any{
			"sandbox": liveSandboxName, "process_id": started.Process.ProcessID,
			"graceful_stop": true, "disable_restart": true,
		}},
	} {
		res := f.call(tc.tool, tc.args)
		require.Falsef(t, res.IsError, "%s: %s", tc.tool, resultText(res))
		assert.Equal(t, liveSandboxName, echoOf(t, res), "%s must echo the sandbox it ran on", tc.tool)
	}
}

// The five tools are registered under the names the docs promise, as separate
// tools rather than one action-dispatched one.
func TestProcessTools_AreFiveDistinctRegisteredTools(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})

	registered := map[string]bool{}
	for _, reg := range f.server.Registrations() {
		registered[reg.Name] = reg.Targeted
	}
	for _, name := range []string{
		"sandbox_process_start", "sandbox_process_list", "sandbox_process_logs",
		"sandbox_process_signal", "sandbox_process_restart",
	} {
		targeted, ok := registered[name]
		assert.Truef(t, ok, "%s must be registered", name)
		assert.Truef(t, targeted, "%s must resolve a sandbox before running", name)
	}
	assert.NotContains(t, registered, "sandbox_process", "there is no action-dispatched process tool")
}

// The schema a model actually sees has to carry the probe fields flat and
// described. This is the one assertion that fails if someone folds the probe
// back into a oneof or drops the descriptions.
func TestProcessStart_ProbeSchemaIsFlatAndDescribed(t *testing.T) {
	f := newLiveFixture(t, liveAgentOptions{})

	listed, err := f.session.ListTools(t.Context(), nil)
	require.NoError(t, err)

	var schema map[string]any
	var description string
	for _, tool := range listed.Tools {
		if tool.Name != "sandbox_process_start" {
			continue
		}
		description = tool.Description
		raw, err := json.Marshal(tool.InputSchema)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &schema))
	}
	require.NotNil(t, schema, "sandbox_process_start must be listed")

	assert.Contains(t, description, "ready_probe",
		"the description must recommend a probe, in the place a model reads before calling")

	props, _ := schema["properties"].(map[string]any)
	require.NotNil(t, props)
	probe, ok := props["ready_probe"].(map[string]any)
	require.True(t, ok, "ready_probe must be in the input schema")
	probeProps, ok := probe["properties"].(map[string]any)
	require.True(t, ok, "ready_probe must be an object with named fields, not an opaque blob")

	for _, field := range []string{"log_pattern", "tcp_port", "http_get_url", "uptime_seconds", "timeout_seconds"} {
		entry, ok := probeProps[field].(map[string]any)
		require.Truef(t, ok, "ready_probe.%s must be in the schema", field)
		desc, _ := entry["description"].(string)
		assert.NotEmptyf(t, desc, "ready_probe.%s must be described; an undescribed probe field is one a model guesses at", field)
	}
}

// ---------------------------------------------------------------- helpers

func findProcess(t *testing.T, list tools.ProcessListResult, id string) tools.ProcessLine {
	t.Helper()
	for _, p := range list.Processes {
		if p.ProcessID == id {
			return p
		}
	}
	t.Fatalf("process %s is not in the listing (%d entries)", id, len(list.Processes))
	return tools.ProcessLine{}
}

// stop tears a supervised process down, so a test does not leave a sleeping
// child on the machine that ran it.
func stop(t *testing.T, f *liveFixture, id string) {
	t.Helper()
	res := f.call("sandbox_process_signal", map[string]any{
		"process_id": id, "signal": "KILL", "disable_restart": true,
	})
	if res.IsError {
		t.Logf("stopping %s: %s", id, resultText(res))
	}
}
