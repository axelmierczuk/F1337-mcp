//go:build linux

package process

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestNoZombiesAfterAHundredShortLivedStarts reads the process table, which is
// the only assertion that actually proves the children were reaped.
//
// "Every record reached a terminal state" does not prove it: a supervisor that
// noticed the exit some other way and never called Wait would pass that and
// still accumulate a zombie per start until the agent hits its process limit.
// Linux is where the evidence is readable, so this is where the test lives; the
// portable half is TestManyShortLivedStartsLeaveNothingBehind.
// It asserts on the zombies these hundred starts left, not on the zombies in
// the table. The package runs its tests in parallel, so "the table is clean"
// is a fact about the whole binary that this test cannot establish and has no
// business failing on: a leak in a sibling test made this one red on main
// while the sibling passed. TestMain owns that assertion now, once, after
// everything has finished — which is also the only place it is deterministic.
func TestNoZombiesAfterAHundredShortLivedStarts(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a hundred processes")
	}
	t.Parallel()

	before := map[int]bool{}
	for _, pid := range zombieChildPIDs() {
		before[pid] = true
	}

	ts := newTestSupervisor(t, func(c *testSupervisorOptions) { c.maxConcurrent = 200 })

	const runs = 100
	records := startShortLived(t, ts, "reaped", runs)
	require.Len(t, records, runs)

	// Which pids this test is actually responsible for. Without this the
	// failure message cannot tell "the supervisor did not reap" from "another
	// test in this package left one lying around", and the two have nothing to
	// do with each other — the first is #11's criterion failing, the second is
	// a cleanup that killed a child and never collected it. main has already
	// been red for the second while reading like the first.
	mine := map[int]bool{}
	for _, r := range records {
		if pid := int(r.status().GetPid()); pid > 0 {
			mine[pid] = true
		}
	}

	// The wait that produced the exit status is the same call that reaps, so by
	// the time the states have settled the reaping has happened. A short retry
	// covers the scheduler, not a missing Wait.
	var ours, others []int
	for range 50 {
		ours, others = nil, nil
		for _, pid := range zombieChildPIDs() {
			switch {
			case mine[pid]:
				ours = append(ours, pid)
			case !before[pid]:
				others = append(others, pid)
			}
		}
		if len(ours) == 0 && len(others) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	require.Emptyf(t, ours,
		"the supervisor left %d of its own %d children unreaped: %v — #11's criterion", len(ours), runs, ours)
	t.Fatalf("%d zombie children appeared while this test ran but none of them is one of its own: %v — "+
		"another test in this package started a process and killed it without collecting it", len(others), others)
}

// TestKillingAChildIsNotCollectingIt is the mechanism behind the failure that
// kept main red, kept as a test because the explanation is counter-intuitive
// and the next person to write a cleanup will reach for the same helper.
//
// A killed child stays in the process table until its parent collects it, and
// platform.ProcessExists reports it as existing — correctly, and on purpose,
// because for the pid-reuse guard a zombie does still hold the pid. So a
// "wait for it to be gone" loop built on that can never finish for a child of
// this binary, and every test using one held a zombie for its whole timeout
// while the rest of the suite ran beside it.
func TestKillingAChildIsNotCollectingIt(t *testing.T) {
	t.Parallel()

	exe, err := os.Executable()
	require.NoError(t, err)
	child := exec.Command(exe, "-helper", "sleep") //nolint:gosec // the command is this test binary
	child.Env = helperEnviron()
	require.NoError(t, child.Start())
	pid := child.Process.Pid

	require.NoError(t, child.Process.Kill())
	waitFor(t, 10*time.Second, "the killed child to become a zombie", func() bool { return pidIsZombie(pid) })

	require.True(t, pidAlive(pid), "a zombie still holds its pid, which is why a liveness check cannot see it go")
	require.False(t, pidRunning(pid), "but it is not running, which is what a survivor check is asking")

	// So the helper the suite waits with must not be built on liveness alone.
	started := time.Now()
	awaitGone(pid, 10*time.Second)
	require.Less(t, time.Since(started), 2*time.Second,
		"awaitGone spun on a zombie; every cleanup that calls it then holds one for its whole timeout, "+
			"and a parallel test reading the process table is right to fail on it")

	// Collecting it is what removes it.
	require.Error(t, child.Wait(), "it was killed, so Wait reports the signal")
	waitFor(t, 10*time.Second, "the collected child to leave the process table", func() bool { return !pidAlive(pid) })
}

// pidIsZombie reports whether a pid names a process that has exited and is
// waiting to be collected.
//
// It is the difference between "gone" and "answers kill(pid, 0)". A zombie
// holds its pid forever — which is exactly why platform.ProcessExists counts it
// as existing, because for the pid-reuse guard it does — so a survivor check
// built on that alone can never see a killed process leave. This repository has
// been bitten by that once already, in #34.
func pidIsZombie(pid int) bool {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat")) //nolint:gosec // reading the process table is the point
	if err != nil {
		return false
	}
	state, _, ok := parseStatStateAndPPID(data)
	return ok && state == 'Z'
}

// zombieChildPIDs reads /proc and returns the pids of this process's children
// that are in state Z.
func zombieChildPIDs() []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	self := os.Getpid()
	var zombies []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat")) //nolint:gosec // reading the process table is the point
		if err != nil {
			continue // it exited while we were walking
		}
		state, ppid, ok := parseStatStateAndPPID(data)
		if !ok || ppid != self || state != 'Z' {
			continue
		}
		zombies = append(zombies, pid)
	}
	return zombies
}

// parseStatStateAndPPID pulls fields 3 and 4 out of /proc/<pid>/stat.
//
// Field 2 is the executable name in parentheses and is not escaped, so a
// process named "foo (bar) baz" produces "1234 (foo (bar) baz) Z 1 ...".
// Splitting on spaces and indexing is the classic way to read the wrong field;
// scanning back from the last ')' is not.
func parseStatStateAndPPID(data []byte) (state byte, ppid int, ok bool) {
	end := bytes.LastIndexByte(data, ')')
	if end < 0 || end+2 >= len(data) {
		return 0, 0, false
	}
	fields := bytes.Fields(data[end+2:])
	if len(fields) < 2 {
		return 0, 0, false
	}
	parent, err := strconv.Atoi(string(fields[1]))
	if err != nil {
		return 0, 0, false
	}
	return fields[0][0], parent, true
}

func TestParseStatStateAndPPID(t *testing.T) {
	t.Parallel()

	state, ppid, ok := parseStatStateAndPPID([]byte("1234 (helper) Z 42 1234 0 0 -1 4194560"))
	require.True(t, ok)
	require.Equal(t, byte('Z'), state)
	require.Equal(t, 42, ppid)

	// The name with its own parentheses and spaces: the case that breaks a
	// naive split.
	state, ppid, ok = parseStatStateAndPPID([]byte("7 (foo (bar) baz) R 99 7 0"))
	require.True(t, ok)
	require.Equal(t, byte('R'), state)
	require.Equal(t, 99, ppid)

	_, _, ok = parseStatStateAndPPID([]byte("nonsense"))
	require.False(t, ok)
}
