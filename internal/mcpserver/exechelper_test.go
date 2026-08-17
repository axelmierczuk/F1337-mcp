package mcpserver_test

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The exec tests run real commands, and the commands have to exist on Linux,
// macOS and Windows. Rather than reaching for `sh` — absent on one of the
// three — the test binary re-executes itself in a helper mode selected by an
// environment variable, which is also how internal/agent/exec tests itself.
// The awkward cases (a process that outlives its caller, one that writes more
// output than any cap) then belong to this repository rather than to whatever
// /bin/sh happens to do on the day.
const helperEnv = "SANDBOXD_MCP_TEST_HELPER"

func TestMain(m *testing.M) {
	if mode := os.Getenv(helperEnv); mode != "" {
		os.Exit(helperMain(mode, os.Args[1:]))
	}
	os.Exit(m.Run())
}

// selfArgv is an argv that re-runs the test binary. Which helper mode it
// enters is decided by helperEnvFor in the request's environment.
func selfArgv(args ...string) []any {
	self, err := os.Executable()
	if err != nil {
		panic("mcpserver test: cannot find the test binary: " + err.Error())
	}
	argv := make([]any, 0, len(args)+1)
	argv = append(argv, self)
	for _, arg := range args {
		argv = append(argv, arg)
	}
	return argv
}

// helperEnvFor is the environment entry that selects a helper mode.
func helperEnvFor(mode string) []any { return []any{helperEnv + "=" + mode} }

func helperMain(mode string, args []string) int {
	switch mode {
	case "exit":
		code, _ := strconv.Atoi(arg(args, 0, "0"))
		return code

	case "fail":
		// Writes a diagnosis to stderr and a line of progress to stdout, then
		// fails: the shape of every compiler and test runner there is.
		fmt.Fprintln(os.Stdout, "running 3 tests")
		fmt.Fprintln(os.Stderr, "main.go:7:2: undefined: doesNotExist")
		return 2

	case "streams":
		fmt.Fprint(os.Stdout, "to stdout\n")
		fmt.Fprint(os.Stderr, "to stderr\n")
		return 0

	case "quiet":
		return 0

	case "cat":
		if _, err := io.Copy(os.Stdout, os.Stdin); err != nil {
			return 1
		}
		return 0

	case "spew":
		total, _ := strconv.Atoi(arg(args, 0, "1048576"))
		line := strings.Repeat("x", 63) + "\n"
		for written := 0; written < total; written += len(line) {
			if _, err := os.Stdout.WriteString(line); err != nil {
				return 1
			}
		}
		return 0

	case "sleep":
		secs, _ := strconv.ParseFloat(arg(args, 0, "60"), 64)
		time.Sleep(time.Duration(secs * float64(time.Second)))
		return 0

	case "mark":
		// mark <file> <seconds>: record this process's pid where the test can
		// find it, then stay alive. It is what lets a cancellation test look
		// for a process that really was spawned rather than trusting the API
		// it is testing to say it killed one.
		path := arg(args, 0, "")
		if path == "" {
			return 2
		}
		if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
			return 2
		}
		secs, _ := strconv.ParseFloat(arg(args, 1, "60"), 64)
		time.Sleep(time.Duration(secs * float64(time.Second)))
		return 0

	default:
		fmt.Fprintf(os.Stderr, "unknown helper mode %q\n", mode)
		return 3
	}
}

func arg(args []string, i int, fallback string) string {
	if i < len(args) {
		return args[i]
	}
	return fallback
}

// readPID waits for the mark helper to record its pid.
func readPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if data, err := os.ReadFile(path); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
				return pid
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the helper never recorded its pid in %s", path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
