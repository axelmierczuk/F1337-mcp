//go:build linux

package process

import (
	"bytes"
	"os"
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
func TestNoZombiesAfterAHundredShortLivedStarts(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a hundred processes")
	}
	t.Parallel()

	require.Empty(t, zombieChildren(t), "the test started with zombies already present")

	ts := newTestSupervisor(t, func(c *supervisorConfig) { c.maxConcurrent = 200 })

	const runs = 100
	require.Len(t, startShortLived(t, ts, "reaped", runs), runs)

	// The wait that produced the exit status is the same call that reaps, so by
	// the time the states have settled the reaping has happened. A short retry
	// covers the scheduler, not a missing Wait.
	var zombies []int
	for range 50 {
		zombies = zombieChildren(t)
		if len(zombies) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%d zombie children left in the process table after %d starts: %v", len(zombies), runs, zombies)
}

// zombieChildren reads /proc and returns the pids of this process's children
// that are in state Z.
func zombieChildren(t *testing.T) []int {
	t.Helper()

	entries, err := os.ReadDir("/proc")
	require.NoError(t, err)

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
