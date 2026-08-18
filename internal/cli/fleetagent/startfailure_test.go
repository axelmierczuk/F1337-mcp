package fleetagent_test

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/cli/fleetagent"
)

// What a daemon that cannot start says, and where it says it.
//
// This is #98, and it is the shape this repository keeps producing: an accurate
// message arriving somewhere the operator cannot act on. `agent.yaml` with
// `listen: 0.0.0.0:8722` and `tls.enabled: false` is refused by the #85 guard in
// four precise lines naming the address, the consequence and three ways out —
// and started as a Windows service, the operator saw "Error 1053: the service
// did not respond to the start or control request in a timely fashion". The
// daemon exited before it could perform the SCM's start handshake, so the
// manager reported the silence as a timeout and the four lines went to a stderr
// the SCM discards.
//
// Everything below is driven from the argv an operator types. The one thing no
// runner can do is be a service manager, so that is the seam — see
// PinServiceManagerForTest — and it is the same boundary the install tests use.

// refusedConfig writes the configuration the operator had, in a directory the
// test owns: a plaintext agent on the address that binds every interface.
//
// It points the agent's own discovery at it too, because `service status` finds
// the record through the config it discovers, and "the daemon wrote it where
// status looks" is the claim these scenarios are for.
func refusedConfig(t *testing.T) (configPath, stateDir string) {
	t.Helper()
	dir := t.TempDir()
	stateDir = filepath.Join(dir, "state")
	configPath = filepath.Join(dir, "agent.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(
		"name: test-host\nlisten: 0.0.0.0:8722\n"+
			"state_dir: "+filepath.ToSlash(stateDir)+"\n"+
			"audit:\n  path: "+filepath.ToSlash(filepath.Join(dir, "logs", "audit.jsonl"))+"\n"), 0o600))
	t.Setenv("FLEET_AGENT_CONFIG", configPath)
	return configPath, stateDir
}

// servableConfig is the same thing on an address the guard allows, so that the
// managed path can be driven all the way to a listener.
func servableConfig(t *testing.T) (configPath, stateDir, address string) {
	t.Helper()
	dir := t.TempDir()
	stateDir = filepath.Join(dir, "state")
	configPath = filepath.Join(dir, "agent.yaml")
	address = net.JoinHostPort("127.0.0.1", freePort(t))
	require.NoError(t, os.WriteFile(configPath, []byte(
		"name: test-host\nlisten: "+address+"\n"+
			"state_dir: "+filepath.ToSlash(stateDir)+"\n"+
			"audit:\n  path: "+filepath.ToSlash(filepath.Join(dir, "logs", "audit.jsonl"))+"\n"), 0o600))
	t.Setenv("FLEET_AGENT_CONFIG", configPath)
	return configPath, stateDir, address
}

// accepting reports whether something is listening on addr.
func accepting(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// A daemon started by a service manager and refusing to serve tells the manager
// why, in the manager's own log, and records it for `service status`.
//
// Three separate claims, and the first is the one that turns 1053 into an
// answer: the failure happens *inside* the manager's start callback. kardianos
// reports SERVICE_START_PENDING to the SCM and then calls Start, so a Start that
// returns an error is a service that stopped with a service-specific exit code —
// in milliseconds, with a reason — rather than a process that vanished and a
// manager left to wait out its 30 seconds.
func TestServe_UnderAServiceManagerAFailureToStartIsReportedNotDiscarded(t *testing.T) {
	configPath, stateDir := refusedConfig(t)

	events, logged, stop, restore := fleetagent.PinServiceManagerForTest()
	defer restore()
	// A manager whose daemon started waits to be told to stop, so a failure that
	// is swallowed rather than returned parks this command there forever. Bounded
	// below, and released here, so that regression is a legible failure rather
	// than a package-wide timeout ten minutes later.
	defer stop()

	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	root := fleetagent.NewRootCommand(out)
	root.SetArgs([]string{"serve", "--config", configPath})
	root.SetErr(errOut)

	errs := make(chan error, 1)
	go func() { errs <- root.Execute() }()
	var err error
	select {
	case err = <-errs:
	case <-time.After(30 * time.Second):
		t.Fatal("`serve` did not return: a refusal inside the manager's Start has to come back out of its Run, " +
			"which is what makes it a stopped service with an exit code instead of a start that never answers")
	}
	require.Error(t, err, "0.0.0.0 with no mTLS must not serve")

	assert.Equal(t,
		[]string{fleetagent.ManagerRunForTest, fleetagent.ManagerStartFailedForTest},
		events(),
		"the manager has to be handed the daemon and told by Start that it failed; a daemon that "+
			"decides this before the manager is involved is the one the SCM reports as a timeout")

	messages := logged()
	require.Len(t, messages, 1, "the manager's log is told once, and only about a failure")
	// The whole refusal, remedy included. Paraphrasing it here is what put an
	// operator in front of a timeout about an address that nothing named.
	for _, want := range []string{
		"could not start",
		"refusing to serve without mTLS",
		"0.0.0.0:8722",
		"binds every interface",
		"tls.enabled: true",
		"--allow-unauthenticated-public",
		configPath,
	} {
		assert.Contains(t, messages[0], want,
			"the event log entry is the only place a service operator can read this")
	}

	// And the record, which is the half that covers a Scheduled Task: it is
	// started by `schtasks /Run`, which succeeds whatever the daemon does next.
	rec, readErr := fleetagent.ReadStartFailureForTest(stateDir)
	require.NoError(t, readErr)
	require.NotNil(t, rec, "a daemon that could not start has to leave the reason where `service status` looks")
	assert.Contains(t, rec.Error, "refusing to serve without mTLS")
	assert.Contains(t, rec.Error, "0.0.0.0:8722")
	assert.Equal(t, configPath, rec.Config, "and name the config it was started with")
	assert.Equal(t, os.Getpid(), rec.PID)
	assert.False(t, rec.At.IsZero(), "a record with no time cannot be reported as the *last* attempt")
}

// The other half: a daemon that starts under a manager serves, stops when the
// manager says so, and leaves no failure behind.
//
// Without this, "always report a failure" would pass the scenario above — and
// the stale record is its own wrong answer: an operator who fixed the config and
// restarted would be told by `status` that the fix had not taken.
func TestServe_UnderAServiceManagerItServesUntilTheManagerStopsIt(t *testing.T) {
	configPath, stateDir, address := servableConfig(t)

	// What the last failed start left behind. This start has to remove it.
	require.NoError(t, fleetagent.WriteStartFailureForTest(stateDir, fleetagent.StartFailureForTest{
		At:      time.Now().UTC().Add(-time.Hour),
		Config:  configPath,
		Version: "0.1.0",
		Error:   "an earlier refusal, already fixed",
	}))

	events, logged, stop, restore := fleetagent.PinServiceManagerForTest()
	defer restore()
	defer stop()

	codes := make(chan int, 1)
	go func() { codes <- fleetagent.Main([]string{"serve", "--config", configPath}, io.Discard) }()

	require.Eventually(t, func() bool { return accepting(address) }, 30*time.Second, 50*time.Millisecond,
		"the daemon the manager started never opened its listener")
	assert.NoFileExists(t, fleetagent.StartFailurePathForTest(stateDir),
		"the listener is open, so this start did not fail, and last time's record is a fault an operator has already fixed")

	stop()
	select {
	case code := <-codes:
		assert.Equal(t, 0, code, "a daemon the manager stopped exited cleanly")
	case <-time.After(30 * time.Second):
		t.Fatal("the daemon did not exit after the service manager asked it to stop")
	}

	assert.Equal(t,
		[]string{fleetagent.ManagerRunForTest, fleetagent.ManagerStartedForTest, fleetagent.ManagerStoppedForTest},
		events(), "the manager's whole lifecycle, in order")
	assert.Empty(t, logged(), "nothing failed, so nothing may be written to the manager's log")
}

// The loop an operator actually walks: the daemon fails, and the next command
// they run says why.
//
// Both halves are the real commands, and the record is a real file in a real
// state directory — which is the part a seam cannot check. `serve` resolves it
// from the config it was given and `status` re-discovers a config of its own, so
// "the daemon wrote it" and "status read it" are two claims about two paths that
// have to agree on one directory.
//
// This is also the task mechanism's whole story. A task's process is
// interactive, so kardianos is not in it at all: there is no manager to hand the
// failure to, and this record is the only place the reason exists.
func TestServeAndStatus_TheReasonAFailedStartSurvivesTheProcess(t *testing.T) {
	configPath, stateDir := refusedConfig(t)

	// No --config: the daemon discovers one, exactly as `serve` typed by hand
	// does, and the record has to name the config it *resolved* rather than the
	// empty flag it was given — that path is the only actionable thing in it.
	require.Equal(t, 1, fleetagent.Main([]string{"serve"}, io.Discard),
		"a plaintext agent on 0.0.0.0 must refuse to serve")

	defer fleetagent.PinInstalledForTest([]fleetagent.Mechanism{fleetagent.MechanismTask}, false)()

	out := &bytes.Buffer{}
	code := fleetagent.Main([]string{"service", "status"}, out)
	text := out.String()
	require.Equal(t, 0, code, "%s", text)

	assert.Contains(t, text, "LAST START FAILED")
	assert.Contains(t, text, "refusing to serve without mTLS",
		"the daemon's own words, not a paraphrase of them")
	assert.Contains(t, text, "0.0.0.0:8722", "and the address, which is the thing to change")
	assert.Contains(t, text, "--allow-unauthenticated-public", "and the remedy it came with")

	// The file to edit, which is the only actionable thing in the record — and
	// asserted against the record and against the line the failure block prints,
	// because `status` names a discovered config of its own two lines earlier.
	// Matched loosely, this assertion passed with the record naming nothing at
	// all: the mutation that stopped it recording the resolved path left the
	// whole suite green.
	rec, err := fleetagent.ReadStartFailureForTest(stateDir)
	require.NoError(t, err)
	require.NotNil(t, rec)
	assert.Equal(t, configPath, rec.Config,
		"`serve` was given no --config, so the record has to name the one the daemon resolved")
	assert.Contains(t, text, "  config:  "+configPath, "and the failure block has to print it")
}

// `service status` on a host whose agent failed to start, driven from the argv,
// with the record planted rather than produced.
//
// The planted half is what makes the *reporting* assertable on every runner: a
// record from a real Windows service carries a config path and a version this
// tree has no way to produce, and the record is the only thing status has.
func TestServiceStatus_SaysWhyTheLastStartFailed(t *testing.T) {
	stateDir := pinAgentConfig(t)
	defer fleetagent.PinInstalledForTest([]fleetagent.Mechanism{fleetagent.MechanismService}, false)()

	// The same host with nothing recorded says nothing. Without this, a block
	// printed unconditionally would pass everything below.
	clean := &bytes.Buffer{}
	require.Equal(t, 0, fleetagent.Main([]string{"service", "status"}, clean))
	assert.Contains(t, clean.String(), "installed, stopped")
	assert.NotContains(t, clean.String(), "LAST START FAILED",
		"an agent that was simply stopped has no failure to report")

	when := time.Date(2026, 8, 18, 9, 30, 0, 0, time.UTC)
	require.NoError(t, fleetagent.WriteStartFailureForTest(stateDir, fleetagent.StartFailureForTest{
		At:      when,
		Config:  `C:\ProgramData\fleet\agent.yaml`,
		Version: "0.1.0",
		PID:     4242,
		Error: "agent: refusing to serve without mTLS on an address that is neither loopback nor private:\n" +
			"0.0.0.0:8722 binds every interface on this host, including any public one",
	}))

	out := &bytes.Buffer{}
	code := fleetagent.Main([]string{"service", "status"}, out)
	text := out.String()
	require.Equal(t, 0, code, "%s", text)

	assert.Contains(t, text, "installed, stopped", "the headline an operator reads first is unchanged")
	assert.Contains(t, text, "LAST START FAILED")
	assert.Contains(t, text, when.Format(time.RFC3339),
		"when it happened, because a record outlives the attempt that wrote it")
	assert.Contains(t, text, "0.0.0.0:8722 binds every interface on this host",
		"and the daemon's reason verbatim, across both of its lines")
	assert.Contains(t, text, `C:\ProgramData\fleet\agent.yaml`)
	assert.Contains(t, text, "0.1.0", "the binary that failed, which an upgrade changes")
	assert.Contains(t, text, "1053",
		"the number the operator was shown instead, so they can connect the two")
	assert.Contains(t, text, "service start", "and what to run once it is fixed")
}

// A record that is there and cannot be read is not "no failure".
//
// The same rule readLiveRuntimeReport draws, and for the same reason: silence
// about a file that exists is how a command tells an operator everything is fine
// while being unable to ask the question. On Linux this is the ordinary case —
// `install` gives the state directory to the service account at 0750 — and the
// answer has to be the reason, not a clean bill of health.
func TestServiceStatus_SaysWhenItCannotReadTheFailedStartRecord(t *testing.T) {
	stateDir := pinAgentConfig(t)
	defer fleetagent.PinInstalledForTest([]fleetagent.Mechanism{fleetagent.MechanismService}, false)()

	require.NoError(t, os.WriteFile(fleetagent.StartFailurePathForTest(stateDir), []byte("{not json"), 0o644))

	out := &bytes.Buffer{}
	code := fleetagent.Main([]string{"service", "status"}, out)
	text := out.String()
	require.Equal(t, 0, code, "%s", text)
	assert.Contains(t, text, "could not read the record a failed start leaves behind",
		"a record status cannot read has to be reported as that, not as an agent with nothing wrong")
}

// The notes themselves, which is where the wording is pinned.
func TestStartFailureNotes(t *testing.T) {
	assert.Empty(t, fleetagent.StartFailureNotesForTest(nil),
		"a host whose agent never failed to start has nothing to be told")

	notes := fleetagent.StartFailureNotesForTest(&fleetagent.StartFailureForTest{
		At:      time.Date(2026, 8, 18, 9, 30, 0, 0, time.UTC),
		Config:  `C:\ProgramData\fleet\agent.yaml`,
		Version: "0.1.0",
		Error:   "line one\nline two",
	})
	joined := strings.Join(notes, "\n")
	assert.Contains(t, joined, "2026-08-18T09:30:00Z")
	assert.Contains(t, joined, "line one")
	assert.Contains(t, joined, "line two", "a multi-line refusal is reported in full or it is not the refusal")
	assert.Contains(t, joined, `C:\ProgramData\fleet\agent.yaml`)
	assert.Contains(t, joined, "0.1.0")
	assert.Contains(t, joined, "1053")
	assert.Contains(t, joined, "Task Scheduler",
		"both mechanisms discard it, and an operator on either has to know that is why this exists")
}

// A start the service manager refuses says where the daemon's own reason is.
//
// What the manager reports is about the manager — a timeout, a service-specific
// exit code, or, for a task, success — and none of those is the reason. `stop`
// says nothing of the kind, because there is no start to explain.
func TestServiceControl_AFailedStartNamesTheCommandThatHasTheReason(t *testing.T) {
	pinAgentConfig(t)
	failing := map[fleetagent.Mechanism]bool{fleetagent.MechanismService: true}

	calls, restore := fleetagent.PinRecordingRegistrationsForTest(
		[]fleetagent.Mechanism{fleetagent.MechanismService}, failing)
	defer restore()

	out := &bytes.Buffer{}
	root := fleetagent.NewRootCommand(out)
	root.SetArgs([]string{"service", "start"})
	root.SetErr(io.Discard)
	err := root.Execute()
	require.Error(t, err)
	assert.Equal(t, []string{"service:start"}, calls())
	assert.Contains(t, err.Error(), "service status",
		"the manager's error is not the daemon's reason, and this is the command that has it")
	restore()

	calls, restore = fleetagent.PinRecordingRegistrationsForTest(
		[]fleetagent.Mechanism{fleetagent.MechanismService}, failing)
	defer restore()

	stopOut := &bytes.Buffer{}
	stopRoot := fleetagent.NewRootCommand(stopOut)
	stopRoot.SetArgs([]string{"service", "stop"})
	stopRoot.SetErr(io.Discard)
	stopErr := stopRoot.Execute()
	require.Error(t, stopErr)
	assert.Equal(t, []string{"service:stop"}, calls())
	assert.NotContains(t, stopErr.Error(), "service status",
		"a stop that failed has no start to explain, and pointing at a start record would be noise")
}

// The message the manager's log is handed carries the error whole.
func TestStartupFailureMessage(t *testing.T) {
	assert.Empty(t, fleetagent.StartupFailureMessageForTest(nil))

	msg := fleetagent.StartupFailureMessageForTest(errors.New("because of the listen address"))
	assert.Contains(t, msg, fleetagent.ServiceName, "the event log entry has to name the product")
	assert.Contains(t, msg, "could not start")
	assert.Contains(t, msg, "because of the listen address")
}
