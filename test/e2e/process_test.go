//go:build integration

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestProcessLogsFollowReturnsAtItsDeadline checks the bound on a following
// read. An unbounded follow is indistinguishable from a hung agent, and the
// model has no way to recover from one.
//
// The assertion is on the flag the agent sets when the bound is what ended the
// stream — not on how long the call took. Timing the call would be measuring
// the test machine.
func TestProcessLogsFollowReturnsAtItsDeadline(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})
	s := f.connect(t)
	s.ok("fleet_select", map[string]any{"name": a.name})

	started := startProcess(t, s, map[string]any{
		"name": "chatty",
		"argv": []string{bins.helpers, "spew", "50", "tick"},
	})
	defer stopProcess(t, s, started)

	logs := structured[processLogsResult](t, s.okAs("fleet_process_logs", map[string]any{
		"process_id":     started.Process.ProcessID,
		"follow":         true,
		"follow_seconds": 2,
	}, callOptions{timeout: 90 * time.Second}))

	if !logs.FollowDeadlineReached {
		t.Fatalf("a follow that outlived a still-running process must report its deadline: %+v", logs)
	}
	if logs.LinesReturned == 0 {
		t.Fatalf("a follow of a process that is producing output returned nothing: %+v", logs)
	}
	if !contains(logs.Logs, "tick ") {
		t.Fatalf("the followed logs do not carry the process's output: %s", logs.Logs)
	}
}

// TestProcessRestartKeepsItsIdentityAndComesBackReady restarts a dev server
// through the tool a developer would use after changing a config file.
//
// A restart is a stop and a start with the same spec, and the contract is that
// it is the *same* process afterwards: same id, same name, a restart count that
// went up, and a readiness probe that passed again. Its probe here is a log
// pattern rather than a port, which is the other probe kind and the one that
// has to survive the log buffer being handed to a new run.
func TestProcessRestartKeepsItsIdentityAndComesBackReady(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})
	s := f.connect(t)
	s.ok("fleet_select", map[string]any{"name": a.name})

	port := freePort(t)
	started := startProcess(t, s, map[string]any{
		"name": "web-dev",
		"argv": []string{bins.helpers, "serve", strconv.Itoa(port), "first"},
		"ready_probe": map[string]any{
			"log_pattern":     "listening on",
			"timeout_seconds": 30,
		},
	})
	defer stopProcess(t, s, started)

	if started.Ready == nil || !*started.Ready {
		t.Fatalf("a log_pattern probe did not report readiness: %+v", started)
	}
	firstPID := started.Process.PID

	restarted := structured[processStartResult](t, s.okAs("fleet_process_restart", map[string]any{
		"process_id":            started.Process.ProcessID,
		"ready_timeout_seconds": 30,
	}, callOptions{timeout: 120 * time.Second}))

	if restarted.ReadyError != "" {
		t.Fatalf("the restarted process did not become ready: %s\n%s", restarted.ReadyError, restarted.RecentLogs)
	}
	if restarted.Ready == nil || !*restarted.Ready {
		t.Fatalf("a restart of a process with a probe must report readiness: %+v", restarted)
	}
	if restarted.Process.ProcessID != started.Process.ProcessID {
		t.Fatalf("the restart minted a new process id %q, was %q", restarted.Process.ProcessID, started.Process.ProcessID)
	}
	// The counter deliberately does not move. It bounds the restarts the
	// supervisor performs under the restart policy, and charging an explicit
	// request against that budget would let a developer restarting their dev
	// server by hand exhaust the automatic recovery they will need when it
	// crashes at three in the morning.
	if restarted.Process.RestartCount != started.Process.RestartCount {
		t.Fatalf("an explicit restart charged the restart policy's budget: count went from %d to %d",
			started.Process.RestartCount, restarted.Process.RestartCount)
	}
	if restarted.Process.PID == firstPID {
		t.Fatalf("the restart reports the pid of the run it replaced (%d)", firstPID)
	}
	if firstPID > 0 {
		waitFor(t, 30*time.Second, "the replaced run to be gone", func() (bool, string) {
			if !processAlive(int(firstPID)) {
				return true, ""
			}
			return false, fmt.Sprintf("pid %d is still alive after its process was restarted", firstPID)
		})
	}

	// It is serving again, which is the claim readiness makes and the only one
	// worth checking from outside the agent.
	fwd := structured[forwardResult](t, s.ok("fleet_forward", map[string]any{"remote_port": port}))
	if got := httpGet(t, "http://"+fwd.LocalAddress+"/"); got != "first" {
		t.Fatalf("the restarted server answered %q", got)
	}
	s.ok("fleet_forward", map[string]any{"remote_port": port, "stop": true})

	// And the log history of both runs is there: a restart that reset the
	// buffer would lose the output that explains why it was restarted.
	logs := readLogs(t, s, started.Process.ProcessID)
	if strings.Count(logs.Logs, "listening on "+strconv.Itoa(port)) < 2 {
		t.Fatalf("the logs do not carry both runs:\n%s", logs.Logs)
	}
}

// TestSupervisedProcessSurvivesAndIsReadoptedAfterAnAgentCrash runs the
// re-adoption path for real.
//
// Four pid-as-identity defects have been found in this path by inspection. It
// has never been run: no test in this repository has killed an agent and asked
// the next one what happened to the process the last one was supervising.
func TestSupervisedProcessSurvivesAndIsReadoptedAfterAnAgentCrash(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})
	s := f.connect(t)
	s.ok("fleet_select", map[string]any{"name": a.name})

	started := startProcess(t, s, map[string]any{
		"name": "survivor",
		"argv": []string{bins.helpers, "spew", "100", "before-and-after"},
	})
	pid := int(started.Process.PID)
	if pid <= 0 {
		t.Fatalf("the agent reported no pid for a process it just started: %+v", started.Process)
	}
	t.Cleanup(func() { killPID(pid) })

	// Wait for output to exist before the crash, so "the logs survived" is a
	// claim about something that was there.
	waitFor(t, 30*time.Second, "the process to produce output", func() (bool, string) {
		logs := readLogs(t, s, started.Process.ProcessID)
		return contains(logs.Logs, "before-and-after 1"), "logs so far: " + logs.Logs
	})
	before := highestLineNumber(t, readLogs(t, s, started.Process.ProcessID).Logs)

	// SIGKILL, not a drain: a supervised process must survive an agent that
	// died, not only one that shut down politely.
	a.kill()
	if !processAlive(pid) {
		t.Fatalf("pid %d died with the agent; supervised processes are meant to outlive it", pid)
	}

	f.restart(a)

	// The MCP server's pooled channel reconnects on its own — nothing here
	// re-selects or re-dials, because a user would not have to.
	var list processListResult
	waitFor(t, 60*time.Second, "the restarted agent to answer", func() (bool, string) {
		res := s.call("fleet_process_list", nil, callOptions{})
		if res.IsError {
			return false, resultText(res)
		}
		list = structured[processListResult](t, res)
		return true, ""
	})

	found := findProcess(list.Processes, started.Process.ProcessID)
	if found == nil {
		t.Fatalf("the restarted agent does not know process %s: %+v", started.Process.ProcessID, list.Processes)
	}
	if found.State != "running" && found.State != "ready" {
		t.Fatalf("re-adopted process is in state %q, want it still running: %+v", found.State, found)
	}
	if int(found.PID) != pid {
		t.Fatalf("re-adopted process reports pid %d, want the pid it was started with (%d)", found.PID, pid)
	}
	if !contains(found.AdoptionNote, "re-adopted") {
		t.Fatalf("re-adopted process carries no adoption note saying so: %q", found.AdoptionNote)
	}
	if !contains(a.logs(), "re-adopted process") {
		t.Fatalf("the agent did not log the re-adoption:\n%s", a.logs())
	}

	// The history the previous agent captured is still there...
	after := readLogs(t, s, started.Process.ProcessID)
	if !contains(after.Logs, "before-and-after 1") {
		t.Fatalf("the logs from before the crash did not survive it:\n%s", after.Logs)
	}

	// ...and capture resumed rather than stopped, which is the half that a
	// record restored without a tailer would quietly fail.
	waitFor(t, 30*time.Second, "output produced after the re-adoption", func() (bool, string) {
		logs := readLogs(t, s, started.Process.ProcessID)
		now := highestLineNumber(t, logs.Logs)
		if now > before {
			return true, ""
		}
		return false, fmt.Sprintf("highest line number is still %d (was %d before the crash)", now, before)
	})

	// And the supervisor still owns it: a stop issued after re-adoption has to
	// reach a process this agent never forked, and has to be reported as having
	// reached it.
	stop := structured[processSignalResult](t, s.okAs("fleet_process_signal", map[string]any{
		"process_id":      started.Process.ProcessID,
		"graceful_stop":   true,
		"grace_seconds":   5,
		"disable_restart": true,
	}, callOptions{timeout: 60 * time.Second}))
	if liveProcessState(stop.Process.State) {
		t.Fatalf("stopping a re-adopted process left it in state %q: %+v", stop.Process.State, stop.Process)
	}
	waitFor(t, 30*time.Second, "the re-adopted process to stop", func() (bool, string) {
		if !processAlive(pid) {
			return true, ""
		}
		return false, fmt.Sprintf("pid %d is still alive", pid)
	})
}

// TestStaleRecordIsOrphanedRatherThanSignalled forces the pid-reuse case.
//
// The record is edited so that its pid still exists but its start identity does
// not match — which is exactly what a reused pid looks like to the next agent.
// The supervisor must refuse to claim it, and must never signal it: on a busy
// host the process behind a reused pid is somebody else's.
func TestStaleRecordIsOrphanedRatherThanSignalled(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})
	s := f.connect(t)
	s.ok("fleet_select", map[string]any{"name": a.name})

	started := startProcess(t, s, map[string]any{
		"name": "impostor",
		"argv": []string{bins.helpers, "sleep"},
	})
	pid := int(started.Process.PID)
	t.Cleanup(func() { killPID(pid) })

	// Shut the agent down cleanly. Supervised processes are deliberately not
	// touched by a drain, so the pid stays live and stays the same.
	a.stop(t)
	if !processAlive(pid) {
		t.Fatalf("pid %d did not survive an agent shutdown", pid)
	}

	recordPath := processRecordPath(t, a, started.Process.ProcessID)
	record := readRecord(t, recordPath)
	if record["start_id"] == nil || record["start_id"] == "" {
		t.Fatalf("the supervisor recorded no start identity, so the pid-reuse guard has nothing to compare: %v", record)
	}
	if got := int(record["pid"].(float64)); got != pid {
		t.Fatalf("record holds pid %d, process has pid %d", got, pid)
	}
	// The one edit: same pid, different start identity. This is a pid the
	// agent can still see, running a process it did not start.
	record["start_id"] = "e2e-forced-mismatch"
	writeRecord(t, recordPath, record)

	f.restart(a)

	var found *processDetail
	waitFor(t, 60*time.Second, "the restarted agent to report the stale process", func() (bool, string) {
		res := s.call("fleet_process_list", nil, callOptions{})
		if res.IsError {
			return false, resultText(res)
		}
		list := structured[processListResult](t, res)
		found = findProcess(list.Processes, started.Process.ProcessID)
		if found == nil {
			return false, fmt.Sprintf("not in the listing: %+v", list.Processes)
		}
		return true, ""
	})

	if found.State != "orphaned" {
		t.Fatalf("a record whose start identity does not match must be orphaned, got %q: %+v", found.State, found)
	}
	if !contains(found.AdoptionNote, "reused") || !contains(found.AdoptionNote, "will not be signalled") {
		t.Fatalf("the adoption note does not explain the refusal: %q", found.AdoptionNote)
	}
	if !processAlive(pid) {
		t.Fatalf("pid %d was killed by an agent that could not prove it owned it", pid)
	}

	// And the refusal holds at the point it matters: a caller asking for the
	// process to be signalled is told no, rather than having the signal
	// delivered to whatever now holds that pid.
	msg := s.fails("fleet_process_signal", map[string]any{
		"process_id": started.Process.ProcessID, "graceful_stop": true,
	})
	if !contains(msg, "ORPHANED") {
		t.Fatalf("signalling an orphaned process should be refused by name, got: %s", msg)
	}
	if !processAlive(pid) {
		t.Fatalf("pid %d was signalled despite the record being orphaned", pid)
	}
}

// startProcess starts a supervised process and fails the test if it did not
// come up.
func startProcess(t *testing.T, s *session, args map[string]any) processStartResult {
	t.Helper()

	res := s.okAs("fleet_process_start", args, callOptions{timeout: 120 * time.Second})
	out := structured[processStartResult](t, res)
	if out.ReadyError != "" {
		t.Fatalf("process %q did not become ready: %s\nrecent logs:\n%s", args["name"], out.ReadyError, out.RecentLogs)
	}
	if out.Process.ProcessID == "" {
		t.Fatalf("fleet_process_start returned no process id: %+v", out)
	}
	return out
}

// stopProcess stops a supervised process and suppresses the restart policy, so
// a scenario's cleanup cannot be undone by the supervisor.
func stopProcess(t *testing.T, s *session, started processStartResult) {
	t.Helper()

	res := s.call("fleet_process_signal", map[string]any{
		"process_id":      started.Process.ProcessID,
		"graceful_stop":   true,
		"grace_seconds":   2,
		"disable_restart": true,
	}, callOptions{timeout: 60 * time.Second})
	if res.IsError {
		t.Logf("stopping %s: %s", started.Process.Name, resultText(res))
	}
}

func readLogs(t *testing.T, s *session, processID string) processLogsResult {
	t.Helper()
	res := s.okAs("fleet_process_logs", map[string]any{"process_id": processID, "tail_lines": 200},
		callOptions{timeout: 60 * time.Second})
	return structured[processLogsResult](t, res)
}

// liveProcessState reports whether a rendered state means the process is still
// there, in the vocabulary a client sees rather than the wire enum's.
func liveProcessState(state string) bool {
	switch state {
	case "starting", "ready", "running", "restarting":
		return true
	default:
		return false
	}
}

func findProcess(list []processDetail, id string) *processDetail {
	for i := range list {
		if list[i].ProcessID == id {
			return &list[i]
		}
	}
	return nil
}

// lineNumber matches the counter the spew helper prints, so a test can assert
// that output kept coming without asserting when it came.
var lineNumber = regexp.MustCompile(`(?m)\b([a-z-]+) (\d+)$`)

func highestLineNumber(t *testing.T, logs string) int {
	t.Helper()

	highest := 0
	for _, m := range lineNumber.FindAllStringSubmatch(logs, -1) {
		n, err := strconv.Atoi(m[2])
		if err != nil {
			continue
		}
		if n > highest {
			highest = n
		}
	}
	return highest
}

// processRecordPath is where the supervisor persisted one process's record.
//
// The layout is the product's, not the harness's: reaching into it is the only
// way to force the pid-reuse case, which needs a record that disagrees with the
// world in a specific way no API can produce.
func processRecordPath(t *testing.T, a *agent, processID string) string {
	t.Helper()

	path := filepath.Join(a.stateDir(), "processes", processID, "record.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("no persisted record at %s: %v", path, err)
	}
	return path
}

func readRecord(t *testing.T, path string) map[string]any {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return record
}

func writeRecord(t *testing.T, path string, record map[string]any) {
	t.Helper()

	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatalf("encode record: %v", err)
	}
	writeFile(t, path, data)
}
