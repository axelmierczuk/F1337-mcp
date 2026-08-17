package process

import (
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

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/platform"
)

// newRawSupervisor builds a supervisor that does not stop its processes when the
// test ends.
//
// The re-adoption tests need exactly that: a supervisor that goes away while its
// children keep running, which is what an agent upgrade looks like. Each test
// kills the survivors itself.
func newRawSupervisor(t *testing.T, dir string) *Supervisor {
	t.Helper()
	sup, err := newSupervisor(testConfig(dir), slog.New(slog.NewTextHandler(io.Discard, nil)))
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

// TestPIDReuseProducesOrphanedAndNoSignal is the test #15 exists for.
//
// The record names a pid that now belongs to an unrelated process. Adopting it
// on the pid alone would have the supervisor signalling something it does not
// own — on a machine that also runs real workloads, that is how sandboxd kills
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
	t.Cleanup(func() {
		killPID(t, strangerPID)
		_ = stranger.Wait()
	})

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
	t.Cleanup(func() {
		killPID(t, stranger.Process.Pid)
		_ = stranger.Wait()
	})

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

	reads, refused := 0, 0
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
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
	require.Greater(t, reads, 100, "the test should have observed the file many times")

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
