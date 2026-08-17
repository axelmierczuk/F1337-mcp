//go:build integration

package e2e

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// pidLine matches the identity each level of the helper tree prints.
var pidLine = regexp.MustCompile(`(?m)^pid (\d+)$`)

// TestExecTimeoutKillsTheWholeProcessTree runs a command that outlives its
// timeout and spawns children that would outlive their parent, and then proves
// that none of them survived.
//
// Signalling the leader alone is the failure this guards against: killing
// `npm run dev` without its group leaves the bundler holding the port, and the
// caller sees a successful timeout and a port that is still busy. A Windows
// variant of this went further and terminated an *unrelated* process through
// pid reuse, which is why this scenario also keeps a bystander running.
func TestExecTimeoutKillsTheWholeProcessTree(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})
	s := f.connect(t)
	s.ok("fleet_select", map[string]any{"name": a.name})

	// A process the agent has nothing to do with, started before the command
	// and expected to be there after it. Its only job is to be a pid the sweep
	// must not touch.
	bystander := start(t, "bystander", bins.helpers, []string{"sleep"}, procOptions{})

	res := structured[execResult](t, s.okAs("fleet_exec", map[string]any{
		"argv":            []string{bins.helpers, "tree", "2"},
		"timeout_seconds": 2,
	}, callOptions{timeout: 120 * time.Second}))

	if !res.TimedOut {
		t.Fatalf("a command that never exits should have been killed for overrunning: %+v", res)
	}

	pids := parsePIDs(t, res.Stdout)
	if len(pids) != 3 {
		t.Fatalf("expected three levels of the tree to announce themselves, got %v from:\n%s", pids, res.Stdout)
	}

	// Every process the command created, by the identity it reported itself.
	for _, pid := range pids {
		waitFor(t, 30*time.Second, fmt.Sprintf("pid %d to be gone", pid), func() (bool, string) {
			if !processAlive(pid) {
				return true, ""
			}
			return false, fmt.Sprintf("pid %d is still alive after the timeout killed its group", pid)
		})
	}

	// And nothing else in the group either — the enumerable namespace this can
	// be asserted against without a container. The command was placed in its
	// own session and process group, so the group id is the leader's pid and
	// membership of it is a complete list of what the command left behind.
	//
	// The container variant of this scenario enumerates the whole PID namespace
	// instead; see TestExecTimeoutKillsTheWholeProcessTreeInContainer.
	leader := pids[0]
	waitFor(t, 30*time.Second, "the command's process group to empty", func() (bool, string) {
		members := processGroupMembers(t, leader)
		if len(members) == 0 {
			return true, ""
		}
		return false, fmt.Sprintf("process group %d still holds %v", leader, members)
	})

	if !bystander.running() {
		t.Fatalf("a process outside the command's group did not survive the timeout kill")
	}
	if !processAlive(bystander.pid()) {
		t.Fatalf("pid %d, which the agent never started, was killed", bystander.pid())
	}

	// The agent itself is unharmed, which is not free: the sweep runs in the
	// agent's own process and a group signal aimed one level too high would
	// take it out.
	if !a.proc.running() {
		t.Fatalf("the agent died sweeping the process group:\n%s", a.logs())
	}
	s.ok("fleet_exec", map[string]any{"argv": []string{"true"}})
}

// TestExecTimeoutReportsWhatItDid checks the caller's side of the same event: a
// killed command has to come back saying it was killed, not looking like a
// command that exited.
func TestExecTimeoutReportsWhatItDid(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})
	s := f.connect(t)
	s.ok("fleet_select", map[string]any{"name": a.name})

	res := structured[execResult](t, s.okAs("fleet_exec", map[string]any{
		"argv":            []string{bins.helpers, "spew", "50", "still-going"},
		"timeout_seconds": 2,
	}, callOptions{timeout: 120 * time.Second}))

	if !res.TimedOut {
		t.Fatalf("the result does not report the timeout: %+v", res)
	}
	if res.Note == "" {
		t.Fatalf("a killed command came back with no note explaining the result: %+v", res)
	}
	if !contains(res.Stdout, "still-going 1") {
		t.Fatalf("output produced before the kill was lost: %q", res.Stdout)
	}
}

// parsePIDs pulls the identities the helper tree announced.
func parsePIDs(t *testing.T, out string) []int {
	t.Helper()

	var pids []int
	for _, m := range pidLine.FindAllStringSubmatch(out, -1) {
		pid, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("unparseable pid %q", m[1])
		}
		pids = append(pids, pid)
	}
	return pids
}

// processGroupMembers lists every process still in a process group.
//
// `ps -A -o pid=,pgid=` is the portable spelling across the BSD ps on macOS and
// the procps one on Linux; -e means something else entirely on macOS, which is
// the kind of difference that makes a test pass for the wrong reason.
func processGroupMembers(t *testing.T, pgid int) []int {
	t.Helper()

	out, err := exec.Command("ps", "-A", "-o", "pid=,pgid=").Output()
	if err != nil {
		t.Fatalf("enumerate processes: %v", err)
	}

	var members []int
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		pid, err1 := strconv.Atoi(fields[0])
		group, err2 := strconv.Atoi(fields[1])
		if err1 != nil || err2 != nil {
			continue
		}
		if group == pgid {
			members = append(members, pid)
		}
	}
	return members
}
