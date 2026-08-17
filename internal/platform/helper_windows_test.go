package platform_test

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The Windows suite supervises this test binary rather than PowerShell.
//
// It used to supervise PowerShell, and that is what made
// TestJobObject_KillKillsTheTree flaky on windows-latest. PowerShell is the
// slowest thing on a Windows host to reach its first statement — it loads the
// CLR, probes the module path, and JITs before it runs a line — and how long
// that takes is a function of how busy the machine is, not of anything the
// test controls. `go test ./...` runs GOMAXPROCS test binaries at once, several
// of this module's packages spawn processes throughout their suites, and under
// -race on a four-vCPU runner that is enough to make PowerShell's start
// latency unbounded. Run 32031510002 spent its entire 60-second budget waiting
// for PowerShell to write two numbers and failed a job-object test without
// ever reaching a job object; every other heavy package in that same run was
// two to five times slower than usual, which is what the failure actually was.
//
// Re-executing this binary costs one CreateProcess against an image the OS
// already has resident — it is the image this process is running — so the
// fixture stops measuring how loaded the runner is and goes back to measuring
// the job object. It is also what internal/agent/process and
// internal/agent/exec already do, and for the same reason.

// helperEnv marks a copy of this binary that was started as a helper rather
// than as a test run. It is read before flag.Parse, so the helper's own
// arguments never reach the testing package's flag set.
const helperEnv = "SANDBOXD_PLATFORM_TEST_HELPER"

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) != "" {
		helperMain()
		return
	}
	os.Exit(m.Run())
}

// helperMain is the entry point of a re-executed copy of this binary. The
// arguments after the "-helper" separator are the mode and its arguments.
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
		// The grandchild. Nothing asks it for anything: it has to exist, and
		// go on existing until something kills it.
		time.Sleep(time.Hour)

	case "tree":
		treeMain()

	default:
		fmt.Fprintln(os.Stderr, "unknown helper mode", args[0])
		os.Exit(2)
	}
}

// treeMain is the leader of the supervised tree: it spawns a grandchild,
// reports both pids on stdout, and stays alive to be killed.
//
// The go-ahead it waits for on stdin is load-bearing, not tidiness. A child is
// assigned to its job object after CreateProcess returns rather than atomically
// with it — see the assignment race in ProcessGroup's own documentation — so a
// leader that spawned its grandchild the instant it started could win that race
// and leave the grandchild outside the job. The PowerShell fixture was safe
// from that only by being slow, which is the same property that made it flaky.
// This one states the requirement instead: the test writes the go-ahead once
// Adopt has returned, so the grandchild is created after the assignment landed
// and the test is about whether killing the job kills the tree rather than
// about who won a microsecond-wide race.
func treeMain() {
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		fmt.Fprintln(os.Stderr, "helper: no go-ahead on stdin:", err)
		os.Exit(1)
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper: locating this binary:", err)
		os.Exit(1)
	}

	grandchild := exec.Command(exe, "-helper", "sleep")
	grandchild.Env = append(os.Environ(), helperEnv+"=1")
	if err := grandchild.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "helper: starting the grandchild:", err)
		os.Exit(1)
	}

	// os.Stdout is unbuffered, so this reaches the pipe on this line.
	fmt.Printf("%d %d\n", os.Getpid(), grandchild.Process.Pid)
	time.Sleep(time.Hour)
}

// helperCommand builds the command that re-executes this test binary in the
// given helper mode.
func helperCommand(t *testing.T, mode string) *exec.Cmd {
	t.Helper()

	exe, err := os.Executable()
	require.NoError(t, err)

	cmd := exec.Command(exe, "-helper", mode)
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	// A helper that cannot do its job says so on the test's own stderr, which
	// is the CI log. The fixture this replaces had nowhere to say anything: a
	// PowerShell that failed outright and a PowerShell that was merely slow
	// produced the same message after the same 60 seconds.
	cmd.Stderr = os.Stderr
	return cmd
}
