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
var pidLine = regexp.MustCompile(`(?m)^pid (\d+) pgid (\d+)$`)

// treeProc is one level of the helper tree, as it reported itself.
type treeProc struct {
	pid  int
	pgid int
}

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

	// Registered before the first assertion rather than after the last
	// precondition, because the assertions are what fail. The tree sleeps until
	// something kills it, so a run that gave up here would leave three
	// processes on the machine and three more the next time — and the two
	// checks below are exactly the ones that fire when the agent has *not*
	// killed it, which is when the survivors are certain rather than merely
	// possible.
	//
	// Only when the scenario failed, and then only because it failed: on the
	// passing path these pids are already gone and could belong to somebody
	// else by now.
	procs := parseTree(t, res.Stdout)
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		for _, p := range procs {
			killPID(p.pid)
		}
	})

	if !res.TimedOut {
		t.Fatalf("a command that never exits should have been killed for overrunning: %+v", res)
	}
	if len(procs) != 3 {
		t.Fatalf("expected three levels of the tree to announce themselves, got %v from:\n%s", procs, res.Stdout)
	}

	// Checked before anything is asserted about the group, because it is what
	// makes those assertions mean anything. The leader reported its own group
	// id, so this is checkable rather than assumed: an agent that stopped
	// putting a command in its own session would leave the leader in the
	// *agent's* group, nothing would ever have had a group id equal to the
	// leader's pid, and "the group is empty" below would pass while a survivor
	// sat somewhere this test never looks.
	leader := procs[0]
	if leader.pgid != leader.pid {
		t.Fatalf("the command's leader (pid %d) is in group %d rather than leading its own; "+
			"the group assertion below would be vacuous, and a timeout cannot reach descendants through a group it does not lead",
			leader.pid, leader.pgid)
	}
	for _, p := range procs[1:] {
		if p.pgid != leader.pgid {
			t.Fatalf("pid %d is in group %d, not the tree's group %d: the group swept is not this tree's",
				p.pid, p.pgid, leader.pgid)
		}
	}

	// Every process the command created, by the identity it reported itself.
	for _, p := range procs {
		waitFor(t, 30*time.Second, fmt.Sprintf("pid %d to be gone", p.pid), func() (bool, string) {
			if !processAlive(p.pid) {
				return true, ""
			}
			return false, fmt.Sprintf("pid %d is still alive after the timeout killed its group", p.pid)
		})
	}

	// And nothing else in the group either — the enumerable namespace this can
	// be asserted against without a container. The command was placed in its
	// own session and process group, so the group id is the leader's pid and
	// membership of it is a complete list of what the command left behind.
	//
	// The container variant of this scenario enumerates the whole PID namespace
	// instead; see TestExecTimeoutKillsTheWholeProcessTreeInContainer.
	waitFor(t, 30*time.Second, "the command's process group to empty", func() (bool, string) {
		members := processGroupMembers(t, leader.pgid)
		if len(members) == 0 {
			return true, ""
		}
		return false, fmt.Sprintf("process group %d still holds %v", leader.pgid, members)
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

// parseTree pulls the identities the helper tree announced, in the order it
// announced them: the leader first, because each level prints itself before
// spawning the next.
func parseTree(t *testing.T, out string) []treeProc {
	t.Helper()

	var procs []treeProc
	for _, m := range pidLine.FindAllStringSubmatch(out, -1) {
		pid, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("unparseable pid %q", m[1])
		}
		pgid, err := strconv.Atoi(m[2])
		if err != nil {
			t.Fatalf("unparseable pgid %q", m[2])
		}
		procs = append(procs, treeProc{pid: pid, pgid: pgid})
	}
	return procs
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

// TestExecSweepsADescendantThatOutlivedItsCommand runs a command that succeeds
// and leaves a descendant behind, and proves the descendant went with the call
// while an unrelated process group did not.
//
// This is the sweep's own scenario and the one the kill path never sees. Every
// other tree assertion in this suite runs a command that is still alive when
// the agent decides to kill it, so the group is signalled while its leader is
// running and the id it names is beyond question. Here nothing killed anything:
// the command exited on its own, and the only thing that reaches what it left
// is the sweep at the end of the RPC.
//
// The bystander is the half of it #91 is about. The sweep names a process group
// id, which is a pid, and a pid the kernel has taken back can be handed to
// somebody else's session leader — so a sweep sent a moment too late is a
// SIGKILL to a stranger's whole process group. There is no way to force that
// here without control of pid allocation, so this asserts the property that
// makes it impossible rather than the event: a process the agent never started
// is still running afterwards, and so is the agent.
func TestExecSweepsADescendantThatOutlivedItsCommand(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})
	s := f.connect(t)
	s.ok("fleet_select", map[string]any{"name": a.name})

	// Its own session leader, started before the command and expected to be
	// there after it. Its only job is to hold a process group the sweep must
	// not touch.
	bystander := start(t, "bystander", bins.helpers, []string{"sleep"}, procOptions{})

	res := structured[execResult](t, s.okAs("fleet_exec", map[string]any{
		"argv": []string{bins.helpers, "orphan"},
	}, callOptions{timeout: 120 * time.Second}))

	procs := parseTree(t, res.Stdout)
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		for _, p := range procs {
			killPID(p.pid)
		}
	})

	// The command succeeded, which is what makes this the sweep's scenario and
	// not the timeout's: nothing here was killed for overrunning or for losing
	// its caller.
	if res.TimedOut {
		t.Fatalf("the command exited on its own; a timeout here means it never got to leave a descendant: %+v", res)
	}
	if res.ExitCode != 0 {
		t.Fatalf("the command exited %d, so what follows is about a failed command rather than a successful one: %+v", res.ExitCode, res)
	}
	if len(procs) != 2 {
		t.Fatalf("expected the command and its descendant to announce themselves, got %v from:\n%s", procs, res.Stdout)
	}

	// Checked before anything is asserted about the group, for the same reason
	// as the timeout scenario: a command that is not in a session of its own
	// has no group for its descendant to be in, and every assertion below would
	// pass while the descendant sat somewhere this test never looks.
	leader, descendant := procs[0], procs[1]
	if leader.pgid != leader.pid {
		t.Fatalf("the command's leader (pid %d) is in group %d rather than leading its own; "+
			"the sweep has no group to aim at and the assertions below would be vacuous",
			leader.pid, leader.pgid)
	}
	if descendant.pgid != leader.pgid {
		t.Fatalf("the descendant (pid %d) is in group %d, not the command's group %d: the group swept is not the one it is in",
			descendant.pid, descendant.pgid, leader.pgid)
	}

	waitFor(t, 30*time.Second, fmt.Sprintf("the descendant (pid %d) to be gone", descendant.pid), func() (bool, string) {
		if !processAlive(descendant.pid) {
			return true, ""
		}
		return false, fmt.Sprintf("pid %d outlived the call that started it: the sweep did not reach it", descendant.pid)
	})

	// And nothing else in the group either. The command led its own session, so
	// membership of that group is a complete list of what it left behind.
	waitFor(t, 30*time.Second, "the command's process group to empty", func() (bool, string) {
		members := processGroupMembers(t, leader.pgid)
		if len(members) == 0 {
			return true, ""
		}
		return false, fmt.Sprintf("process group %d still holds %v", leader.pgid, members)
	})

	// The other half: a group the agent has no business signalling was not
	// signalled. On a developer's machine this is their editor or their build.
	if !bystander.running() {
		t.Fatalf("a process group outside the command's did not survive the sweep")
	}
	if !processAlive(bystander.pid()) {
		t.Fatalf("pid %d, which the agent never started, was killed by the sweep", bystander.pid())
	}

	// Including the agent's own, which is one level up from the command's and
	// what a sweep aimed one level too high would take out.
	if !a.proc.running() {
		t.Fatalf("the agent died sweeping the process group:\n%s", a.logs())
	}
	s.ok("fleet_exec", map[string]any{"argv": []string{"true"}})
}
