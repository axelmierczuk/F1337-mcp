package process

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// newRawSupervisor builds a supervisor that does not stop its processes when the
// test ends.
//
// The re-adoption tests need exactly that: a supervisor that goes away while its
// children keep running, which is what an agent upgrade looks like. Each test
// kills the survivors itself.
func newRawSupervisor(t *testing.T, dir string) *Supervisor {
	t.Helper()
	sup, err := newSupervisor(testConfig(dir), testPolicy(t, 16), slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sup.Close() })
	return sup
}

// TestReadoptionAcrossAnAgentRestart is the reason #15 exists: an agent upgrade
// must not take down every dev server in the fleet, and the agent that comes
// back has to work out which of its recorded children are still its children.
func TestReadoptionAcrossAnAgentRestart(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	first := newRawSupervisor(t, dir)
	r, err := first.start(startSpec{
		// A line every 50 milliseconds, for long enough to outlive the restart.
		argv:          helperArgv(t, "echo", "2000", "50", "tick"),
		name:          "survives-upgrade",
		env:           helperEnviron(),
		restartPolicy: sandboxdv1.RestartPolicy_RESTART_POLICY_NEVER,
		maxLogBytes:   1 << 18,
	}, false)
	require.NoError(t, err)

	id, pid := r.id, int(r.status().GetPid())
	t.Cleanup(func() { killPID(t, pid) })
	waitForLine(t, r, 20*time.Second, "tick 3")

	// The agent goes away. The process does not.
	require.NoError(t, first.Close())
	require.True(t, pidAlive(pid), "an agent restart must not take the process with it")

	second := newRawSupervisor(t, dir)
	adopted, ok := second.lookup(id)
	require.True(t, ok, "the process id must survive the restart")
	require.Equal(t, pid, int(adopted.status().GetPid()))
	require.True(t, isLive(adopted.currentState()), "state was %s", stateName(adopted.currentState()))
	require.Contains(t, adopted.status().GetAdoptionNote(), "re-adopted",
		"the decision has to be explained to whoever reads the status")

	// The history from before the restart is still readable.
	stream := &recordingStream{}
	require.NoError(t, second.streamLogs(context.Background(), adopted,
		logRequest{sel: selector{tail: 500}}, stream))
	require.Contains(t, strings.Join(stream.texts(), "\n"), "tick 0",
		"the log from before the restart must still be there")

	// And the logs keep growing: the process is still writing, and the new
	// agent picked the capture back up where the old one left off.
	before := lastTick(t, adopted)
	waitFor(t, 30*time.Second, "the re-adopted process's logs to keep growing", func() bool {
		return lastTick(t, adopted) > before
	})

	// A re-adopted process is still signalable, through a group handle this
	// agent never created.
	_, err = second.gracefulStop(adopted, 2*time.Second, true, true)
	require.NoError(t, err)
	waitFor(t, 10*time.Second, "the re-adopted process to stop", func() bool { return !pidAlive(pid) })
}

// lastTick is the highest "tick N" index captured so far.
func lastTick(t *testing.T, r *record) int {
	t.Helper()
	highest := -1
	for _, line := range r.buf.ringLines() {
		var n int
		if _, err := fmt.Sscanf(line.Text, "tick %d", &n); err == nil && n > highest {
			highest = n
		}
	}
	return highest
}

// TestCloseRecordsTheOffsetsTheTailersActuallyReached.
//
// Close stops the tailers and waits for them, and a read already in flight
// finishes inside that wait. An offset read before it therefore names a
// position the agent has already gone past, and persisting it tells the next
// agent to resume from bytes this one has already turned into log lines — so
// a re-adopted process's history opens with a duplicate of its own last few
// hundred lines, which is precisely the continuity #15 is about.
//
// The invariant is one-directional — what is persisted must never be behind
// what was captured — but the window it is violated in is narrow: the tailer
// advances its offset before it turns the bytes into lines, so a snapshot
// taken during the read is short by a chunk while one taken during the
// conversion is not. Measured against the unfixed code that is roughly one
// shutdown in eight, which is why this runs the shutdown many times rather than
// once. One violation in the batch fails it, and the magnitude is a whole
// 32 KiB read rather than the trailing byte a legitimate mid-line stop leaves.
func TestCloseRecordsTheOffsetsTheTailersActuallyReached(t *testing.T) {
	t.Parallel()

	// Enough shutdowns that a narrow window is not missed. No child process is
	// involved in any of them, so they are cheap: what is under test is the
	// agent's own bookkeeping when it stops reading, and a real process only
	// makes the timing less controlled.
	for i := range 128 {
		persisted, captured := closeMidDrain(t, i)
		require.Positive(t, captured, "the tailer should have captured something to be wrong about")
		// The -1 covers a final line the tailer flushed without its newline,
		// which is how a read that lands mid-line ends. What this guards
		// against is a whole read chunk out, not a byte.
		require.GreaterOrEqual(t, persisted, captured-1,
			"shutdown %d persisted a stdout offset %d bytes behind the output it had already captured (%d); the next agent replays the difference and the re-adopted log opens with a duplicate",
			i, captured-persisted, captured)
	}
}

// closeMidDrain runs one agent shutdown with the tailer part-way through a
// backlog, and reports the offset it persisted against the output it had
// already turned into log lines.
func closeMidDrain(t *testing.T, seq int) (persistedOffset, captured int64) {
	t.Helper()
	dir := t.TempDir()

	cfg := testConfig(dir)
	cfg.maxLogBytes = 64 << 20  // no rotation, so the history below is complete
	cfg.rawCapBytes = 512 << 20 // and no truncation of the transport file either

	sup, err := newSupervisor(cfg, testPolicy(t, 16), slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	id := fmt.Sprintf("closed-mid-drain-%04d", seq)
	recDir, err := sup.store.dir(id)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(recDir, 0o700))

	// The capture files a spawn would have left, pre-filled with a backlog
	// larger than the tailer works through in the moment it takes Close to
	// reach it. The tailer is therefore mid-file rather than idle at EOF when
	// the shutdown arrives, which is the state it is in on a busy host and the
	// only state in which the ordering here is observable at all.
	outPath, errPath := rawPaths(recDir)
	require.NoError(t, os.WriteFile(errPath, nil, 0o600))
	raw, err := os.Create(outPath) //nolint:gosec // the test's own temp directory
	require.NoError(t, err)
	w := bufio.NewWriterSize(raw, 1<<20)
	line := []byte(strings.Repeat("y", 120) + "\n")
	for written := 0; written < 1<<20; written += len(line) {
		_, err := w.Write(line)
		require.NoError(t, err)
	}
	require.NoError(t, w.Flush())
	require.NoError(t, raw.Close())

	file, err := newRotatingFile(filepath.Join(recDir, "log.jsonl"), cfg.maxLogBytes, cfg.retainSegments)
	require.NoError(t, err)

	r := newRecord(sup, id, recDir)
	r.buf = newLogBuffer(cfg.ringBufferLines, file)
	r.name, r.argv = id, []string{"pre-filled"}
	r.state = sandboxdv1.ProcessState_PROCESS_STATE_RUNNING
	capt, err := newCapture(recDir, r.buf, [2]int64{}, cfg.rawCapBytes,
		cfg.tailPollMin, cfg.tailPollMax, cfg.drainWindow)
	require.NoError(t, err)
	r.cap = capt

	sup.mu.Lock()
	sup.records[id] = r
	sup.order = append(sup.order, id)
	sup.mu.Unlock()
	capt.start(make(chan struct{}))

	waitFor(t, 20*time.Second, "the tailer to start on the backlog", func() bool {
		_, _, produced := r.buf.stats()
		return produced > 0
	})
	require.NoError(t, sup.Close())

	data, err := os.ReadFile(filepath.Join(recDir, recordFileName)) //nolint:gosec // the test's own temp directory
	require.NoError(t, err)
	var p persisted
	require.NoError(t, json.Unmarshal(data, &p))

	lines, err := readSegments(r.buf.segments(), 0)
	require.NoError(t, err)
	for _, l := range lines {
		if l.Stream == sandboxdv1.Stream_STREAM_STDOUT {
			captured += int64(len(l.Text)) + 1 // plus the newline the tailer consumed
		}
	}
	return p.CaptureOffsets[0], captured
}

// TestPIDReuseProducesOrphanedAndNoSignal is the test #15 exists for.
//
// The record names a pid that now belongs to an unrelated process. Adopting it
// on the pid alone would have the supervisor signalling something it does not
// own — on a machine that also runs real workloads, that is how fleet kills
// someone's database.
func TestPIDReuseProducesOrphanedAndNoSignal(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// An unrelated process, started outside any supervisor. It stands in for
	// whatever the OS handed the recycled pid to.
	exe, err := os.Executable()
	require.NoError(t, err)
	stranger := exec.Command(exe, "-helper", "sleep") //nolint:gosec // the command is this test binary
	stranger.Env = helperEnviron()
	require.NoError(t, stranger.Start())
	strangerPID := stranger.Process.Pid
	t.Cleanup(func() { killAndReap(t, stranger) })

	// Its real start identity, so the fabricated record can be given a
	// different one — which is exactly what a reused pid looks like.
	info, err := platform.StatProcess(strangerPID)
	require.NoError(t, err)

	st, err := newStore(dir)
	require.NoError(t, err)
	require.NoError(t, st.save(persisted{
		ID:            "reused-pid-0001",
		Name:          "was-a-dev-server",
		Argv:          []string{"some-server", "--port", "3000"},
		ArgvHash:      argvHash([]string{"some-server", "--port", "3000"}),
		PID:           strangerPID,
		StartID:       info.StartID + "-but-not-really",
		State:         "RUNNING",
		StartedAt:     time.Now().Add(-time.Hour),
		RestartPolicy: sandboxdv1.RestartPolicy_RESTART_POLICY_ALWAYS.String(),
		MaxRestarts:   5,
		MaxLogBytes:   1 << 18,
	}))

	sup := newRawSupervisor(t, dir)

	r, ok := sup.lookup("reused-pid-0001")
	require.True(t, ok, "a record whose process cannot be proven must not silently disappear")
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_ORPHANED, r.currentState())

	note := r.status().GetAdoptionNote()
	require.Contains(t, note, "reused")
	require.Contains(t, note, "not be signalled")

	// The stranger is untouched, and stays untouched.
	require.True(t, pidAlive(strangerPID), "the supervisor must not signal a process it does not own")

	// Even asked directly, it refuses.
	err = sup.signalRecord(r, platform.SignalKill, true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ORPHANED")
	time.Sleep(200 * time.Millisecond)
	require.True(t, pidAlive(strangerPID), "an explicit signal to an ORPHANED record must not reach the pid")

	// And it cannot be restarted into life either.
	require.Error(t, sup.restart(r, 100*time.Millisecond))
}

// TestRecordWhoseProcessIsGoneBecomesTerminal: never silently disappears, and
// never reports a success it cannot know about.
func TestRecordWhoseProcessIsGoneBecomesTerminal(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// A pid that existed and is now gone. Starting and reaping a real process
	// is the only way to get one that is genuinely unused.
	exe, err := os.Executable()
	require.NoError(t, err)
	gone := exec.Command(exe, "-helper", "exit", "0") //nolint:gosec // the command is this test binary
	gone.Env = helperEnviron()
	require.NoError(t, gone.Start())
	gonePID := gone.Process.Pid
	require.NoError(t, gone.Wait())

	st, err := newStore(dir)
	require.NoError(t, err)
	require.NoError(t, st.save(persisted{
		ID:          "departed-0001",
		Name:        "departed",
		Argv:        []string{"whatever"},
		PID:         gonePID,
		StartID:     "linux:whatever:12345",
		State:       "READY",
		StartedAt:   time.Now().Add(-time.Minute),
		MaxLogBytes: 1 << 18,
	}))

	sup := newRawSupervisor(t, dir)
	r, ok := sup.lookup("departed-0001")
	require.True(t, ok)
	require.True(t, isTerminal(r.currentState()), "state was %s", stateName(r.currentState()))
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_CRASHED, r.currentState(),
		"nothing recorded the exit status, so reporting a clean finish would be an invention")
	require.NotEmpty(t, r.status().GetAdoptionNote())
	require.Contains(t, r.status().GetAdoptionNote(), "no longer exists")
}

func TestAdoptionRefusesARecordWithNoStartIdentity(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	exe, err := os.Executable()
	require.NoError(t, err)
	stranger := exec.Command(exe, "-helper", "sleep") //nolint:gosec // the command is this test binary
	stranger.Env = helperEnviron()
	require.NoError(t, stranger.Start())
	t.Cleanup(func() { killAndReap(t, stranger) })

	st, err := newStore(dir)
	require.NoError(t, err)
	require.NoError(t, st.save(persisted{
		ID:          "no-identity-0001",
		Name:        "no-identity",
		Argv:        []string{"whatever"},
		PID:         stranger.Process.Pid,
		State:       "RUNNING",
		StartedAt:   time.Now(),
		MaxLogBytes: 1 << 18,
	}))

	sup := newRawSupervisor(t, dir)
	r, ok := sup.lookup("no-identity-0001")
	require.True(t, ok)
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_ORPHANED, r.currentState(),
		"a pid with nothing to compare against cannot be told apart from a reused one")
	require.Contains(t, r.status().GetAdoptionNote(), "no start identity")
}

func TestTerminalRecordsAreLoadedUnchanged(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	st, err := newStore(dir)
	require.NoError(t, err)
	require.NoError(t, st.save(persisted{
		ID:          "already-done-0001",
		Name:        "already-done",
		Argv:        []string{"whatever"},
		PID:         999999,
		State:       "EXITED",
		ExitCode:    0,
		StartedAt:   time.Now().Add(-time.Hour),
		ExitedAt:    time.Now().Add(-time.Minute),
		MaxLogBytes: 1 << 18,
	}))

	sup := newRawSupervisor(t, dir)
	r, ok := sup.lookup("already-done-0001")
	require.True(t, ok)
	require.Equal(t, sandboxdv1.ProcessState_PROCESS_STATE_EXITED, r.currentState())
	require.Empty(t, r.status().GetAdoptionNote(), "there was nothing to reason about")
}

// TestStateFileIsAlwaysParseable is the SIGKILL-mid-write property.
//
// The guarantee comes from writing a sibling temp file and renaming it, so no
// reader — including the next agent, on the startup path where every supervised
// process's fate is decided — can observe a partially written record. This
// asserts it the way it is actually observable: hammer the file with writes
// while reading it, and require that every read parses.
func TestStateFileIsAlwaysParseable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	st, err := newStore(dir)
	require.NoError(t, err)
	recordDir, err := st.dir("hammered-0001")
	require.NoError(t, err)
	path := filepath.Join(recordDir, recordFileName)

	base := persisted{
		ID: "hammered-0001", Name: "hammered", Argv: []string{"a"},
		State: "RUNNING", StartedAt: time.Now(), MaxLogBytes: 1 << 18,
	}
	require.NoError(t, st.save(base))

	stop := make(chan struct{})
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			p := base
			// Vary the length, so a partial write would produce a file that is
			// a prefix of a longer record rather than a same-length one.
			p.Name = strings.Repeat("n", i%512+1)
			p.RestartCount = uint32(i % 1000) //nolint:gosec // bounded by the modulus
			_ = st.save(p)
		}
	}()

	// Read until it has seen the file whole enough times to mean something,
	// not for a fixed second. A second is a machine-speed assertion: on a
	// loaded runner it buys fifty reads rather than a thousand, and the test
	// then fails for being on a slow machine rather than for observing half a
	// record — which is the only thing it is actually about.
	const wantReads = 100
	reads, refused := 0, 0
	deadline := time.Now().Add(30 * time.Second)
	for reads < wantReads && time.Now().Before(deadline) {
		data, err := os.ReadFile(path) //nolint:gosec // the test's own temp directory
		if err != nil {
			// The open failed. That is not the failure this test is about, and
			// on Windows it is expected: replacing a file is MoveFileEx with
			// MOVEFILE_REPLACE_EXISTING, and there is a window during which the
			// destination cannot be opened at all. The guarantee is that a
			// reader never sees *half* a record — an open that fails outright
			// has seen nothing, and the startup path that actually reads these
			// records runs when nothing is writing them.
			refused++
			continue
		}
		var p persisted
		require.NoError(t, json.Unmarshal(data, &p),
			"a reader must never observe a half-written record; got %d bytes: %q", len(data), data)
		require.Equal(t, "hammered-0001", p.ID)
		require.NotEmpty(t, p.Name, "a record with no name is a record written in halves")
		reads++
	}
	t.Logf("%d complete reads, %d opens refused while a rename was in flight", reads, refused)
	close(stop)
	writer.Wait()
	require.GreaterOrEqual(t, reads, wantReads, "the test should have observed the file many times")

	// And no temp files are left lying around for the loader to trip over.
	entries, err := os.ReadDir(recordDir)
	require.NoError(t, err)
	for _, entry := range entries {
		require.False(t, strings.HasSuffix(entry.Name(), ".tmp"),
			"leftover temp file %s", entry.Name())
	}
}

// TestUnparseableRecordDoesNotCostTheOtherProcesses: the agent has already lost
// the process whose record is corrupt; refusing to start would lose the rest.
func TestUnparseableRecordDoesNotCostTheOtherProcesses(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	st, err := newStore(dir)
	require.NoError(t, err)
	require.NoError(t, st.save(persisted{
		ID: "good-0001", Name: "good", Argv: []string{"a"},
		State: "EXITED", StartedAt: time.Now(), MaxLogBytes: 1 << 18,
	}))

	badDir := filepath.Join(dir, "processes", "corrupt-0001")
	require.NoError(t, os.MkdirAll(badDir, 0o700))
	// Truncated JSON: what a SIGKILL would leave if the write were not atomic.
	require.NoError(t, os.WriteFile(filepath.Join(badDir, recordFileName),
		[]byte(`{"process_id": "corrupt-0001", "name": "cor`), 0o600))

	loaded, problems := st.load()
	require.Len(t, loaded, 1)
	require.Equal(t, "good-0001", loaded[0].ID)
	require.Len(t, problems, 1)
	require.Contains(t, problems[0].Error(), "parse record")

	sup := newRawSupervisor(t, dir)
	_, ok := sup.lookup("good-0001")
	require.True(t, ok, "one unreadable record must not cost the agent the readable ones")
	_, ok = sup.lookup("corrupt-0001")
	require.False(t, ok)
}

func TestPersistedRecordCarriesTheAdoptionInputs(t *testing.T) {
	t.Parallel()
	ts := newTestSupervisor(t)

	r := ts.startHelper("persisted", "silent")
	waitFor(t, 5*time.Second, "the record to be written", func() bool {
		path := filepath.Join(r.dir, recordFileName)
		_, err := os.Stat(path)
		return err == nil
	})

	data, err := os.ReadFile(filepath.Join(r.dir, recordFileName)) //nolint:gosec // the test's own temp directory
	require.NoError(t, err)
	var p persisted
	require.NoError(t, json.Unmarshal(data, &p))

	require.Equal(t, r.id, p.ID)
	require.Equal(t, "persisted", p.Name)
	require.NotZero(t, p.PID)
	require.NotEmpty(t, p.StartID, "start identity is the whole pid-reuse guard")
	require.Equal(t, argvHash(p.Argv), p.ArgvHash)
	require.False(t, p.StartedAt.IsZero())
	require.NotEmpty(t, p.JobName, "the Windows job name has to survive the restart that reopens it")
}

func TestArgvHashMismatchIsNotedButDoesNotBlockAdoption(t *testing.T) {
	t.Parallel()

	p := persisted{
		ID: "x", PID: os.Getpid(), Argv: []string{"a", "b"},
		ArgvHash: "not-the-hash-of-a-b",
	}
	info, err := platform.StatProcess(os.Getpid())
	require.NoError(t, err)
	p.StartID = info.StartID

	sup := &Supervisor{}
	note, adopt := sup.adoptionDecision(p, sandboxdv1.ProcessState_PROCESS_STATE_RUNNING)
	require.True(t, adopt, "argv can legitimately change across a re-exec; it is a sanity check, not the test")
	require.Contains(t, note, "argv hash does not match")
}

// TestAdoptionRestoresTheSpawningAgentsJobName covers the Windows half of the
// fleet rebrand.
//
// A process's job object is named when it is spawned, and the rebrand changed
// the prefix that name is built from. An agent upgraded across the rename
// re-adopts processes whose jobs are still called "sandboxd-process-…", and it
// reaches a re-adopted tree by reopening the job *by name*. Recomputing the
// name from the current prefix would produce one no running job answers to, and
// every group signal to a surviving process — every stop, every restart — would
// fail on a host that did nothing wrong but upgrade.
//
// The name therefore comes off the persisted record rather than the constant.
// This runs on every platform because the bug is in the bookkeeping, not in the
// Win32 call: the field is persisted and restored identically everywhere.
func TestAdoptionRestoresTheSpawningAgentsJobName(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	exe, err := os.Executable()
	require.NoError(t, err)
	survivor := exec.Command(exe, "-helper", "sleep") //nolint:gosec // the command is this test binary
	survivor.Env = helperEnviron()
	require.NoError(t, survivor.Start())
	t.Cleanup(func() {
		_ = survivor.Process.Kill()
		_ = survivor.Wait()
	})

	const legacyJob = "sandboxd-process-upgraded-0001"
	st, err := newStore(dir)
	require.NoError(t, err)
	require.NoError(t, st.save(persisted{
		ID:          "upgraded-0001",
		Name:        "upgraded",
		Argv:        []string{"whatever"},
		PID:         survivor.Process.Pid,
		JobName:     legacyJob,
		State:       "READY",
		StartedAt:   time.Now().Add(-time.Minute),
		MaxLogBytes: 1 << 18,
	}))

	sup := newRawSupervisor(t, dir)
	r, ok := sup.lookup("upgraded-0001")
	require.True(t, ok)
	require.Equal(t, legacyJob, r.jobName,
		"a re-adopted process keeps the job name the agent that spawned it used")

	// And a process this agent starts is named with the current prefix, so the
	// compatibility path does not pin new processes to the old name.
	fresh, err := sup.start(startSpec{
		argv: helperArgv(t, "sleep"),
		name: "fresh",
		env:  helperEnviron(),
	}, false)
	require.NoError(t, err)
	require.Equal(t, jobObjectName(fresh.id), fresh.jobName)
	require.Contains(t, fresh.jobName, "fleet-process-")
}
