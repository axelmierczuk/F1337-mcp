package process

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/platform"
	"github.com/axelmierczuk/fleet-mcp/internal/security/policy"
)

// The tests supervise the test binary itself.
//
// Every supervised process in this suite is another copy of this binary,
// re-executed with a mode argument. That is deliberate: `sh -c` is not
// available on Windows, `sleep` is not on the path there either, and a suite
// that reaches for them ends up asserting on Unix and skipping on the platform
// where the process handling is least like the others. Re-executing the test
// binary means the same test runs everywhere, against a child whose behaviour
// the test controls exactly.

const helperEnv = "SANDBOXD_PROCESS_TEST_HELPER"

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) != "" {
		helperMain()
		return
	}
	code := m.Run()
	// The package-wide reaping assertion, and the one that does not depend on
	// test order. TestNoZombiesAfterAHundredShortLivedStarts can only see a
	// leak that happens to overlap it; this runs once, after every test and
	// every cleanup, so a child that any test in the package left unreaped
	// fails the run wherever it was leaked from.
	if zombies := awaitNoZombieChildren(10 * time.Second); len(zombies) > 0 {
		fmt.Fprintf(os.Stderr,
			"FAIL: %d zombie children left in the process table after the suite: %v\n"+
				"a test started a process and never waited on it; killing a child does not reap it\n",
			len(zombies), zombies)
		code = 1
	}
	os.Exit(code)
}

// awaitNoZombieChildren waits for this process's zombie children to be reaped
// and returns whatever is left.
//
// The wait is for the supervisor's own reapers: a process killed in a test
// cleanup is a zombie for as long as it takes the goroutine blocked in
// cmd.Wait to be scheduled. A leak, by contrast, has nothing that will ever
// collect it, so it survives the whole window.
func awaitNoZombieChildren(timeout time.Duration) []int {
	deadline := time.Now().Add(timeout)
	for {
		zombies := zombieChildPIDs()
		if len(zombies) == 0 || time.Now().After(deadline) {
			return zombies
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// helperMain is the entry point of a supervised child. os.Args after the
// "-helper" separator are the mode and its arguments.
func helperMain() {
	args := os.Args[1:]
	for i, arg := range args {
		if arg == "-helper" {
			args = args[i+1:]
			break
		}
	}
	if len(args) == 0 {
		os.Exit(2)
	}

	switch args[0] {
	case "sleep":
		time.Sleep(durationArg(args, 1, time.Hour))

	case "exit":
		code, _ := strconv.Atoi(argAt(args, 1, "0"))
		time.Sleep(durationArg(args, 2, 0))
		os.Exit(code)

	case "echo":
		// echo <count> <intervalMs> <text>
		count, _ := strconv.Atoi(argAt(args, 1, "1"))
		interval := durationArg(args, 2, 0)
		text := argAt(args, 3, "line")
		for i := range count {
			fmt.Printf("%s %d\n", text, i)
			if interval > 0 {
				time.Sleep(interval)
			}
		}
		time.Sleep(durationArg(args, 4, 0))

	case "spew":
		// spew <count> [gapMs] [rounds] — count lines as fast as the pipe will
		// take them, then exit. The backpressure test asserts this still exits
		// promptly.
		//
		// rounds and the gap are for the tests that need the flood to still be
		// flooding while they look at it: one round finishes in milliseconds,
		// and a follower asserting that it fell behind cannot fall behind a
		// process that has already finished. Defaults leave the one-shot
		// behaviour exactly as it was.
		count, _ := strconv.Atoi(argAt(args, 1, "1000"))
		gap := durationArg(args, 2, 0)
		rounds, _ := strconv.Atoi(argAt(args, 3, "1"))
		w := bufio.NewWriterSize(os.Stdout, 64*1024)
		for round := range max(rounds, 1) {
			for i := range count {
				fmt.Fprintf(w, "line %d aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", round*count+i)
			}
			_ = w.Flush()
			if gap > 0 {
				time.Sleep(gap)
			}
		}

	case "streams":
		// streams <gapMs> <pairs> — interleaves stdout and stderr, leaving a gap
		// between each write. The gap is the test's, not the helper's: the two
		// streams are tailed by two goroutines, so the agent's read order only
		// reproduces the write order for writes further apart than a poll.
		gap := durationArg(args, 1, 250*time.Millisecond)
		pairs, _ := strconv.Atoi(argAt(args, 2, "2"))
		for i := range pairs {
			fmt.Printf("out %d\n", i)
			time.Sleep(gap)
			fmt.Fprintf(os.Stderr, "err %d\n", i)
			time.Sleep(gap)
		}
		time.Sleep(time.Hour)

	case "announce":
		// announce <delayMs> <stream> <text> — the readiness announcement a dev
		// server makes, on whichever stream.
		time.Sleep(durationArg(args, 1, 0))
		out := os.Stdout
		if argAt(args, 2, "stdout") == "stderr" {
			out = os.Stderr
		}
		fmt.Fprintln(out, argAt(args, 3, "ready"))
		time.Sleep(time.Hour)

	case "listen":
		// listen <delayMs> <port> — binds loopback after a delay.
		time.Sleep(durationArg(args, 1, 0))
		lis, err := net.Listen("tcp", "127.0.0.1:"+argAt(args, 2, "0"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "listen failed:", err)
			os.Exit(1)
		}
		fmt.Println("listening on", lis.Addr().String())
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}

	case "http":
		// http <port> <status> — serves one status code on every path.
		code, _ := strconv.Atoi(argAt(args, 2, "200"))
		srv := &http.Server{
			Addr:              "127.0.0.1:" + argAt(args, 1, "0"),
			ReadHeaderTimeout: 5 * time.Second,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(code)
			}),
		}
		fmt.Println("serving", code)
		_ = srv.ListenAndServe()

	case "ignore-term":
		// Catches SIGTERM and does nothing with it, which is what forces a
		// graceful stop to escalate.
		ch := make(chan os.Signal, 4)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
		fmt.Println("ignoring TERM")
		for range ch {
			fmt.Println("caught a signal and ignoring it")
		}

	case "handle-term":
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
		fmt.Println("waiting for TERM")
		<-ch
		fmt.Println("handled TERM")
		os.Exit(0)

	case "spawn":
		// spawn — starts a grandchild that inherits the process group, prints
		// its pid, and stays alive. The whole-tree kill test asserts the
		// grandchild is gone afterwards.
		child, err := startGrandchild()
		if err != nil {
			fmt.Fprintln(os.Stderr, "spawn failed:", err)
			os.Exit(1)
		}
		fmt.Println("grandchild", child)
		time.Sleep(time.Hour)

	case "longline":
		// longline <bytes> — one line longer than the agent's per-line cap.
		n, _ := strconv.Atoi(argAt(args, 1, "1024"))
		fmt.Println(strings.Repeat("x", n))
		time.Sleep(durationArg(args, 2, 0))

	case "once-fail":
		// once-fail <markerPath> — exits 1 the first time it is run and stays
		// alive every time after. It gives a test a spec that crashes into
		// RESTARTING and then, on the next spawn, stays up.
		marker := argAt(args, 1, "")
		if _, err := os.Stat(marker); err != nil {
			_ = os.WriteFile(marker, []byte("ran"), 0o600)
			fmt.Fprintln(os.Stderr, "first run, failing")
			os.Exit(1)
		}
		fmt.Println("second run, staying up")
		time.Sleep(time.Hour)

	case "silent":
		// Produces nothing at all. The bounded-follow test needs a process that
		// cannot end a follow by writing.
		time.Sleep(durationArg(args, 1, time.Hour))

	default:
		fmt.Fprintln(os.Stderr, "unknown helper mode", args[0])
		os.Exit(2)
	}
}

// startGrandchild launches another copy of the test binary, in sleep mode, from
// inside a helper. It inherits the helper's process group, which is the point.
func startGrandchild() (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}
	cmd := exec.Command(exe, "-helper", "sleep") //nolint:gosec // the command is this test binary
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	return cmd.Process.Pid, nil
}

func argAt(args []string, i int, fallback string) string {
	if i < len(args) {
		return args[i]
	}
	return fallback
}

func durationArg(args []string, i int, fallback time.Duration) time.Duration {
	if i >= len(args) {
		return fallback
	}
	ms, err := strconv.Atoi(args[i])
	if err != nil {
		return fallback
	}
	return time.Duration(ms) * time.Millisecond
}

// helperArgv builds the argv that re-executes this test binary in helper mode.
func helperArgv(t *testing.T, mode string, args ...string) []string {
	t.Helper()
	exe, err := os.Executable()
	require.NoError(t, err)
	return append([]string{exe, "-helper", mode}, args...)
}

// helperEnviron is the environment a supervised helper needs.
func helperEnviron() []string {
	return append(os.Environ(), helperEnv+"=1")
}

// testSupervisor is a supervisor with test-scale timings.
//
// The knobs that a production agent measures in seconds are compressed to
// milliseconds, which is what lets the suite assert on ordering and outcomes
// instead of waiting out real backoffs. Nothing about the logic changes with
// them: they are all durations, and every assertion below is on what happened
// rather than on when.
type testSupervisor struct {
	*Supervisor
	t   *testing.T
	dir string
}

// testSupervisorOptions is everything a test tunes.
//
// maxConcurrent is not a supervisorConfig field: the cap is agent-wide and
// lives in the shared policy limiter, so it sits here and builds the limiter
// the supervisor is handed, rather than being a second number the supervisor
// could enforce on its own.
type testSupervisorOptions struct {
	supervisorConfig
	maxConcurrent int
}

func newTestSupervisor(t *testing.T, tweak ...func(*testSupervisorOptions)) *testSupervisor {
	t.Helper()
	return newTestSupervisorIn(t, t.TempDir(), tweak...)
}

func newTestSupervisorIn(t *testing.T, dir string, tweak ...func(*testSupervisorOptions)) *testSupervisor {
	t.Helper()

	cfg := supervisorConfig{
		stateDir:           dir,
		maxLogBytes:        256 * 1024,
		ringBufferLines:    200,
		defaultGracePeriod: 300 * time.Millisecond,
		maxFollowDuration:  2 * time.Second,

		retainSegments:        3,
		rawCapBytes:           1 << 20,
		stabilityWindow:       500 * time.Millisecond,
		defaultMaxRestarts:    3,
		defaultRestartBackoff: 20 * time.Millisecond,
		maxRestartBackoff:     200 * time.Millisecond,

		tailPollMin: 2 * time.Millisecond,
		tailPollMax: 20 * time.Millisecond,
		drainWindow: 200 * time.Millisecond,

		probeTimeout:     2 * time.Second,
		probeInterval:    20 * time.Millisecond,
		httpProbeTimeout: 500 * time.Millisecond,
		dialTimeout:      500 * time.Millisecond,

		defaultTailLines: 200,
	}
	opts := testSupervisorOptions{supervisorConfig: cfg, maxConcurrent: 16}
	for _, fn := range tweak {
		fn(&opts)
	}

	sup, err := newSupervisor(opts.supervisorConfig, testPolicy(t, opts.maxConcurrent),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	ts := &testSupervisor{Supervisor: sup, t: t, dir: dir}
	t.Cleanup(func() {
		// Stop every process this supervisor started before closing it. The
		// supervisor deliberately leaves them running — that is the contract —
		// so the test has to be the thing that cleans up, or a failing run
		// leaves helpers on the machine.
		//
		// The kill afterwards is not belt and braces. Several tests here put a
		// record into a state where the supervisor correctly refuses to signal
		// it — ORPHANED, or a start identity that no longer matches its pid —
		// and the helper then survives the stop. On Windows a surviving helper
		// holds its capture files open, the file cannot be deleted while it
		// does, and t.TempDir's own cleanup fails the test with an error that
		// names a path rather than a cause.
		var killed []int
		for _, r := range sup.snapshotRecords() {
			if isLive(r.currentState()) {
				_ = sup.stopRecord(r, 200*time.Millisecond)
			}
			// Never a pid whose process is known to have exited. The record
			// keeps the pid of a finished run on purpose — it is what a caller
			// diagnosing a crash reads — and a suite that starts hundreds of
			// short-lived helpers is exactly where a pid gets recycled. Killing
			// on "the pid answers" would then have the test kill a stranger,
			// which is the mistake the whole package is written to avoid.
			r.mu.Lock()
			exited := !r.exitedAt.IsZero()
			r.mu.Unlock()
			if pid := int(r.status().GetPid()); pid > 0 && !exited && pidAlive(pid) {
				killPID(t, pid)
				killed = append(killed, pid)
			}
		}
		_ = sup.Close()
		// And wait for them, because a terminated process on Windows releases
		// its handles a moment after the call returns, and t.TempDir runs next.
		for _, pid := range killed {
			awaitGone(pid, 10*time.Second)
		}
	})
	return ts
}

// startHelper starts a supervised copy of the test binary.
func (ts *testSupervisor) startHelper(name, mode string, args ...string) *record {
	ts.t.Helper()
	r, err := ts.start(startSpec{
		argv:           helperArgv(ts.t, mode, args...),
		name:           name,
		env:            helperEnviron(),
		restartPolicy:  sandboxdv1.RestartPolicy_RESTART_POLICY_NEVER,
		maxRestarts:    ts.cfg.defaultMaxRestarts,
		restartBackoff: ts.cfg.defaultRestartBackoff,
		maxLogBytes:    ts.cfg.maxLogBytes,
	}, false)
	require.NoError(ts.t, err)
	return r
}

// spec is startHelper's request, for tests that need to change one field.
func (ts *testSupervisor) helperSpec(name, mode string, args ...string) startSpec {
	ts.t.Helper()
	return startSpec{
		argv:           helperArgv(ts.t, mode, args...),
		name:           name,
		env:            helperEnviron(),
		restartPolicy:  sandboxdv1.RestartPolicy_RESTART_POLICY_NEVER,
		maxRestarts:    ts.cfg.defaultMaxRestarts,
		restartBackoff: ts.cfg.defaultRestartBackoff,
		maxLogBytes:    ts.cfg.maxLogBytes,
	}
}

// shortLivedBatchSize bounds how many supervised helpers the hundred-start
// tests keep in flight at once.
//
// The criterion is a hundred starts, not a hundred simultaneous processes, and
// the difference matters off this machine: `go test ./...` runs packages in
// parallel, every helper is another copy of a race-instrumented test binary,
// and a hundred of them at once on a four-vCPU CI runner starves the whole job.
// It did — internal/mcpserver, which this branch does not touch, went from 20
// seconds to 77 on the Windows runner, and a PowerShell-based test in
// internal/platform blew a 60-second budget waiting to start. That second one
// went on failing intermittently even with this batching in place, because
// batching bounds what this package contributes and nothing bounds what four
// concurrent test binaries add up to; internal/platform stopped waiting on
// PowerShell instead. The batch stays: the load it removes is real, and it is
// this package's to remove.
const shortLivedBatchSize = 8

// startShortLived runs total short-lived helpers, at most shortLivedBatchSize
// at a time, and returns their records once every one has reached a terminal
// state.
func startShortLived(t *testing.T, ts *testSupervisor, prefix string, total int) []*record {
	t.Helper()

	records := make([]*record, 0, total)
	for start := 0; start < total; start += shortLivedBatchSize {
		batch := make([]*record, 0, shortLivedBatchSize)
		for i := start; i < start+shortLivedBatchSize && i < total; i++ {
			batch = append(batch, ts.startHelper(fmt.Sprintf("%s-%d", prefix, i), "exit", "0"))
		}
		for _, r := range batch {
			waitState(t, r, 60*time.Second,
				sandboxdv1.ProcessState_PROCESS_STATE_EXITED,
				sandboxdv1.ProcessState_PROCESS_STATE_CRASHED)
		}
		records = append(records, batch...)
	}
	return records
}

// waitState blocks until the record reaches one of the given states.
//
// It waits on the record's own change broadcast rather than sleeping, so it
// asserts on the transition happening rather than on how long it took.
func waitState(t *testing.T, r *record, timeout time.Duration, want ...sandboxdv1.ProcessState) sandboxdv1.ProcessState {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		changed, state := r.wait()
		for _, w := range want {
			if state == w {
				return state
			}
		}
		select {
		case <-changed:
		case <-deadline.C:
			t.Fatalf("process %s stayed in %s, waiting for one of %v",
				r.id, stateName(state), stateNames(want))
			return state
		}
	}
}

func stateNames(states []sandboxdv1.ProcessState) []string {
	out := make([]string, 0, len(states))
	for _, s := range states {
		out = append(out, stateName(s))
	}
	return out
}

// waitFor polls a condition. It is the fallback for the facts that have no
// change broadcast to wait on — a line reaching the log buffer, a port opening,
// a pid disappearing — and it asserts the condition, never a duration.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, what)
}

// waitForLine waits until some captured line contains substr, and returns it.
func waitForLine(t *testing.T, r *record, timeout time.Duration, substr string) string {
	t.Helper()
	var found string
	waitFor(t, timeout, fmt.Sprintf("a log line containing %q", substr), func() bool {
		for _, line := range r.buf.ringLines() {
			if strings.Contains(line.Text, substr) {
				found = line.Text
				return true
			}
		}
		return false
	})
	return found
}

// recordingStream collects what a GetProcessLogs call sends.
type recordingStream struct {
	mu      sync.Mutex
	lines   []*sandboxdv1.LogLine
	summary *sandboxdv1.LogSummary
	onLine  func(*sandboxdv1.LogLine)
}

func (s *recordingStream) Send(resp *sandboxdv1.GetProcessLogsResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch event := resp.GetEvent().(type) {
	case *sandboxdv1.GetProcessLogsResponse_Line:
		s.lines = append(s.lines, event.Line)
		if s.onLine != nil {
			s.onLine(event.Line)
		}
	case *sandboxdv1.GetProcessLogsResponse_Summary:
		s.summary = event.Summary
	}
	return nil
}

func (s *recordingStream) texts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.lines))
	for _, line := range s.lines {
		out = append(out, line.GetText())
	}
	return out
}

func (s *recordingStream) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.lines)
}

// freePort reserves a loopback port and releases it, so a helper can bind it a
// moment later. It is a race in principle and has never been one in practice;
// the alternative — having the child report the port it chose — cannot be read
// before the probe under test has already run.
func freePort(t *testing.T) int {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := lis.Addr().(*net.TCPAddr).Port
	require.NoError(t, lis.Close())
	return port
}

// leakCheck asserts that a block of work leaves no goroutines behind.
//
// A supervisor with a log tailer and a probe loop per process is exactly where
// goroutines accumulate, and the leak does not show up as a failure — it shows
// up as an agent that slowly stops working on a host nobody is watching.
func leakCheck(t *testing.T) {
	t.Helper()
	before := runtime.NumGoroutine()
	t.Cleanup(func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			runtime.GC()
			if runtime.NumGoroutine() <= before+goroutineSlack {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Errorf("goroutines leaked: %d before, %d after\n%s", before, runtime.NumGoroutine(), buf[:n])
	})
}

// goroutineSlack absorbs the runtime's own background goroutines — the HTTP
// transport's idle-connection reaper, most of all — which start on demand and
// stop on their own schedule rather than on the test's.
const goroutineSlack = 4

// testPolicy builds the shared agent-wide limiter a supervisor takes its
// concurrency slots from.
func testPolicy(t *testing.T, maxConcurrent int) *policy.Policy {
	t.Helper()
	p, err := policy.New(policy.Config{Caps: policy.Caps{MaxConcurrent: maxConcurrent}})
	require.NoError(t, err)
	return p
}

// pidAlive reports whether a pid still names a live process.
func pidAlive(pid int) bool { return platform.ProcessExists(pid) }

// pidRunning reports whether a pid names a process that is still running, as
// opposed to one that merely still holds its pid.
//
// A killed process that nobody has collected is a zombie, and a zombie answers
// every liveness question the portable API can ask — platform.ProcessExists
// says yes, and it is right to, because a reused pid is exactly what it exists
// to catch. "No survivors" means no running survivors, so the survivor checks
// use this.
func pidRunning(pid int) bool { return pidAlive(pid) && !pidIsZombie(pid) }

// killAndReap stops a process the test started itself, and collects it.
//
// The Wait is the load-bearing half. Killing a child does not remove it from
// the process table; it becomes a zombie until its parent collects the exit
// status. platform.ProcessExists — which pidAlive is — deliberately reports a
// zombie as existing, because for the pid-reuse guard it does still hold the
// pid. So killPID's awaitGone cannot ever see a child of this test binary go
// away, spins out its entire timeout, and for all of that time the process
// table holds a zombie that TestNoZombiesAfterAHundredShortLivedStarts,
// running in parallel, is right to fail on.
//
// Anything this suite spawns with exec.Command must go through here.
// Supervised processes are different: the supervisor's own monitor is blocked
// in cmd.Wait for each of them, so killPID is enough.
func killAndReap(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

// killPID stops a process the test started outside a supervisor's care, and
// waits for it to be gone.
//
// os.Process.Kill rather than a signal, so it works identically on Windows —
// and the wait matters most there: TerminateProcess returns before the handles
// are released, and the temp directory the process was writing into cannot be
// removed until they are.
//
// Only for a process something else will reap — a supervised child, whose
// monitor is sitting in cmd.Wait. For one this test started itself, use
// killAndReap.
func killPID(t *testing.T, pid int) {
	t.Helper()
	if pid <= 0 {
		return
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	_ = p.Kill()
	awaitGone(pid, 10*time.Second)
}

// awaitGone waits for a pid to stop running.
//
// pidRunning rather than pidAlive, so a child whose collector has not run yet
// does not hold this for the whole timeout. What the wait is for is the Windows
// case — TerminateProcess returns before the handles are released, and the temp
// directory the process was writing into cannot be removed until they are — and
// Windows has no zombies, so nothing is lost there. On Unix a zombie has
// already released everything it held.
func awaitGone(pid int, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !pidRunning(pid) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// grpcServerStreamStub satisfies the parts of grpc.ServerStream that the
// generated server-streaming interface embeds and this service never calls.
// Only Send and Context matter here; the rest exist so the recorder can be
// passed to the generated handler signature.
type grpcServerStreamStub struct{}

func (grpcServerStreamStub) SetHeader(metadata.MD) error  { return nil }
func (grpcServerStreamStub) SendHeader(metadata.MD) error { return nil }
func (grpcServerStreamStub) SetTrailer(metadata.MD)       {}
func (grpcServerStreamStub) SendMsg(any) error            { return nil }
func (grpcServerStreamStub) RecvMsg(any) error            { return nil }
