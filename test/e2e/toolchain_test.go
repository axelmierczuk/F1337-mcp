//go:build integration

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The claim #74 asks an implementation to prove, made against the shipped
// binary in its own process rather than against a function.
//
// A daemon confined out of seeing per-user installations is up, answers Health,
// and fails every command a model gives it. The daemon writes down what it can
// actually reach at every start, and `service status` reads that file back;
// these scenarios plant a program that exists nowhere but under the agent's own
// home directory and check what the file says about it.
//
// The suite already gives every agent its own HOME — see the comment on
// agent.home — which is what makes the question askable here at all.

// runtimeReport is the daemon's record of the environment it was started in,
// decoded from state/runtime.json. Only the fields these scenarios assert on.
type runtimeReport struct {
	PID     int    `json:"pid"`
	StartID string `json:"start_id"`
	Account string `json:"account"`
	Home    string `json:"home"`
	Profile struct {
		Visibility  string   `json:"visibility"`
		Ran         string   `json:"ran"`
		Unreachable []string `json:"unreachable"`
	} `json:"profile"`
}

// readRuntimeReport reads what the daemon that is running now recorded about
// itself.
//
// The daemon writes it before agent.New binds the listener, so an agent this
// suite has waited for a dial on has already written one; nothing here waits on
// a duration. The pid
// check is the load-bearing part: the file outlives the process that wrote it,
// and these scenarios restart the daemon on purpose — reading the previous
// run's record would report on an environment nobody planted anything in, and
// would do it by passing.
func readRuntimeReport(t *testing.T, a *agent) runtimeReport {
	t.Helper()
	path := filepath.Join(a.stateDir(), "runtime.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the daemon did not record %s, which is what `service status` reads: %v\n%s", path, err, a.logs())
	}
	var report runtimeReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("parse %s: %v\n%s", path, err, data)
	}
	if report.PID != a.proc.pid() {
		t.Fatalf("%s was written by pid %d; the daemon running now is pid %d, so this record answers for a process that is gone\n%s",
			path, report.PID, a.proc.pid(), a.logs())
	}
	return report
}

// plantToolchain writes a runnable program into dir and returns its path.
//
// The program creates marker when it runs, so "found" and "ran" are two
// different assertions. This suite is POSIX-only by existing design, which is
// why a shell script is enough here and is not in the unit tests.
func plantToolchain(t *testing.T, dir, marker string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}
	// Named cargo because that is a name the daemon's own probe list knows and
	// will therefore try to run. The marker is baked in rather than taken from
	// an argument: the probe passes the arguments the real cargo takes, and the
	// point is that this program exits zero under them and leaves evidence.
	path := filepath.Join(dir, "cargo")
	writeExecutable(t, path, "#!/bin/sh\ntouch \""+marker+"\"\nexit 0\n")
	return path
}

func writeExecutable(t *testing.T, path, script string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// withPathPrefix returns env with dir prepended to PATH.
func withPathPrefix(env []string, dir string) []string {
	out := make([]string, 0, len(env))
	for _, entry := range env {
		if strings.HasPrefix(entry, "PATH=") {
			out = append(out, "PATH="+dir+string(os.PathListSeparator)+strings.TrimPrefix(entry, "PATH="))
			continue
		}
		out = append(out, entry)
	}
	return out
}

// TestAgentSeesItsOwnPerUserToolchain is proof that a command this daemon
// spawns reaches what the operator installed under their own profile.
//
// Not "PATH is non-empty": a Windows service in session 0 has a PATH, it is the
// machine's, and that is exactly the failure. The program planted here exists
// nowhere but under the agent's home directory, and the marker it writes exists
// only if the daemon executed it.
func TestAgentSeesItsOwnPerUserToolchain(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("workstation", enrollOptions{})

	binDir := filepath.Join(a.home, ".cargo", "bin")
	marker := filepath.Join(a.home, "cargo-ran")
	planted := plantToolchain(t, binDir, marker)
	a.env = withPathPrefix(a.env, binDir)

	// enroll starts the daemon, and the daemon records what it can reach at
	// start — so the toolchain has to be planted and the PATH set before the
	// process that will report on them exists. Stopped the way a service
	// manager stops it and started again: the same agent, with the same config
	// and state directory, and a listener the old process has finished with.
	restartAgentCleanly(t, f, a)

	report := readRuntimeReport(t, a)
	if report.Home != a.home {
		t.Fatalf("the daemon recorded home %q, this agent was started with %q", report.Home, a.home)
	}
	if report.PID == 0 || report.StartID == "" {
		t.Fatalf("without a pid and a start identity `service status` refuses the report: %+v", report)
	}
	if report.Profile.Visibility != "visible" {
		t.Fatalf("a toolchain installed under the daemon's own home and on its PATH must be visible, got %q (unreachable: %v)",
			report.Profile.Visibility, report.Profile.Unreachable)
	}
	if report.Profile.Ran != planted {
		t.Fatalf("the daemon reported running %q, the only per-user program installed is %q", report.Profile.Ran, planted)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("%s was reported as having run, but it left no evidence of running: %v", planted, err)
	}
}

// The failure the reported install had, in the shape this suite can reproduce:
// the toolchain is installed, PATH is populated, and PATH does not reach it.
//
// The daemon has to say so. An agent that reports itself healthy while every
// command fails is the whole of #74.
func TestAgentReportsAToolchainItCannotReach(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("confined", enrollOptions{})

	binDir := filepath.Join(a.home, ".cargo", "bin")
	marker := filepath.Join(a.home, "cargo-ran")
	plantToolchain(t, binDir, marker)
	// PATH is left exactly as it was: populated, and without the per-user
	// directory on it.

	restartAgentCleanly(t, f, a)

	report := readRuntimeReport(t, a)
	if report.Profile.Visibility != "hidden" {
		t.Fatalf("a toolchain installed under the daemon's home and off its PATH must be reported hidden, got %q", report.Profile.Visibility)
	}
	if report.Profile.Ran != "" {
		t.Fatalf("nothing was reachable, so nothing may be reported as having run: %q", report.Profile.Ran)
	}
	if !contains(strings.Join(report.Profile.Unreachable, " "), binDir) {
		t.Fatalf("the report has to name what an operator can act on; %v does not mention %s", report.Profile.Unreachable, binDir)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("%s is not on the daemon's PATH and must not have been run", marker)
	}

	// And the daemon says it in its own log, where an operator looking at a
	// failing agent will be.
	if !contains(a.logs(), "cannot reach the toolchains") {
		t.Fatalf("the daemon has to say so at startup, not only in a file:\n%s", a.logs())
	}
}

// restartAgentCleanly stops the daemon the way a service manager does and
// starts it again.
//
// fleet.restart kills, which leaves the listening socket to the kernel to
// reclaim; the replacement can then lose the bind while the port still answers
// a dial, and the scenario reads the record the dead daemon left behind.
func restartAgentCleanly(t *testing.T, f *fleet, a *agent) {
	t.Helper()
	a.stop(t)
	f.startAgent(a)
}
