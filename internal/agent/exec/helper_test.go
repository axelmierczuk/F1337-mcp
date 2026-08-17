package exec

import (
	"fmt"
	"os"
	osexec "os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The tests run commands, and the commands have to exist on Linux, macOS and
// Windows. Rather than reaching for `sh` — which is absent on one of the three
// — the test binary re-executes itself in a helper mode selected by an
// environment variable. That also makes the awkward cases (a process that
// ignores SIGTERM, one that spawns a grandchild, one that writes more output
// than any cap) something this repository controls rather than something it
// hopes /bin/sh will do the same way everywhere.
const helperEnv = "SANDBOXD_EXEC_TEST_HELPER"

func TestMain(m *testing.M) {
	if mode := os.Getenv(helperEnv); mode != "" {
		os.Exit(helperMain(mode, os.Args[1:]))
	}
	os.Exit(m.Run())
}

// selfArgv is an argv that re-runs the test binary. Which helper mode it
// enters is decided by helperEnvFor in the request's environment.
func selfArgv(args ...string) []string {
	self, err := os.Executable()
	if err != nil {
		panic("exec test: cannot find the test binary: " + err.Error())
	}
	return append([]string{self}, args...)
}

// helperEnvFor is the environment entry that selects a helper mode.
func helperEnvFor(mode string) string { return helperEnv + "=" + mode }

func helperMain(mode string, args []string) int {
	switch mode {
	case "exit":
		// exit <code>
		code, _ := strconv.Atoi(arg(args, "0"))
		return code

	case "echo":
		fmt.Print(strings.Join(args, " "))
		return 0

	case "streams":
		// Interleaved writes to both streams, so a test can assert ordering
		// within each one without assuming anything about ordering between
		// them — which is not a property the OS provides.
		for i := range 3 {
			fmt.Fprintf(os.Stdout, "out%d\n", i)
			fmt.Fprintf(os.Stderr, "err%d\n", i)
		}
		return 0

	case "spew":
		// spew <bytes>: write that many bytes to stdout, then exit 0. The
		// point is that it exits: a command whose output is capped must still
		// terminate, and it only does if the agent keeps draining the pipe.
		total, _ := strconv.Atoi(arg(args, "1048576"))
		line := strings.Repeat("x", 63) + "\n"
		for written := 0; written < total; written += len(line) {
			if _, err := os.Stdout.WriteString(line); err != nil {
				return 1
			}
		}
		return 0

	case "sleep":
		// sleep <seconds>
		secs, _ := strconv.ParseFloat(arg(args, "60"), 64)
		time.Sleep(time.Duration(secs * float64(time.Second)))
		return 0

	case "spawn":
		// spawn <pidfile>: start a child that outlives this process on its
		// own, print its pid, and wait. The child writes its pid to the file
		// and gets no inherited pipes, so the test can find it without the
		// agent's output drain depending on it.
		return spawnHelper(arg(args, ""))

	case "env":
		// env <NAME>: print one variable's value, or nothing when unset. Used
		// to prove what the base environment carries and what it does not.
		fmt.Print(os.Getenv(arg(args, "")))
		return 0

	case "envdump":
		for _, entry := range os.Environ() {
			fmt.Println(entry)
		}
		return 0

	case "cwd":
		dir, err := os.Getwd()
		if err != nil {
			return 1
		}
		fmt.Print(dir)
		return 0

	case "cat":
		// Copy stdin to stdout, proving stdin was written and then closed: a
		// stdin that stayed open would hang here instead of returning.
		if _, err := os.Stdout.ReadFrom(os.Stdin); err != nil {
			return 1
		}
		return 0

	case "ignore-term":
		return ignoreTermHelper()

	default:
		fmt.Fprintf(os.Stderr, "unknown helper mode %q\n", mode)
		return 2
	}
}

// arg returns the helper's first argument, or a default. Every mode takes at
// most one.
func arg(args []string, fallback string) string {
	if len(args) > 0 {
		return args[0]
	}
	return fallback
}

// spawnHelper starts a grandchild and reports its pid, then sleeps.
//
// The grandchild is started without inheriting this process's stdout, so it
// cannot hold the agent's output pipe open. What it does hold is membership of
// the process group, which is the whole point: killing the leader alone leaves
// it running, and the test asserts it does not.
func spawnHelper(pidFile string) int {
	self, err := os.Executable()
	if err != nil {
		return 1
	}
	child := osexec.Command(self, "600") //nolint:gosec // the test binary re-executing itself
	child.Env = append(os.Environ(), helperEnvFor("sleep"))
	child.Stdout = nil
	child.Stderr = nil
	if err := child.Start(); err != nil {
		return 1
	}
	if pidFile != "" {
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
			return 1
		}
	}
	fmt.Println(child.Process.Pid)
	time.Sleep(600 * time.Second)
	return 0
}
