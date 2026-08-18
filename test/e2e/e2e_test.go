//go:build integration

// Package e2e runs the product end to end.
//
// Every other test in this repository stops at a seam: the agent's services are
// exercised over bufconn, the MCP tools against fake clients, the CA against a
// signed leaf nobody ever handshakes with. This package starts the real
// binaries — `fleetctl`, two `fleet-agent` daemons on different ports, and
// `fleet-mcp` driven over stdio JSON-RPC exactly as an agent CLI drives it —
// and asserts on what a client sees.
//
// # What it needs
//
// A Go toolchain and a loopback interface. Nothing else: no Docker, no root,
// no network. The suite builds the three binaries once per run into a
// temporary directory and enrolls every sandbox against a CA it creates and
// throws away.
//
// The one exception is [TestExecTimeoutKillsTheWholeProcessTreeInContainer],
// which re-runs one scenario inside a Linux container so that "nothing
// survived" can be asserted against a whole PID namespace rather than against a
// process group. It skips unless FLEET_E2E_DOCKER=1. See README.md.
//
// # Assertions
//
// On recorded facts and observable state, never on how long something took.
// Two tests in internal/agent/process were rewritten because they timed
// wall-clock gaps that bracketed a process teardown; the same mistake here,
// where every assertion crosses three processes and a TLS handshake, would
// produce a suite nobody trusts. [waitFor] polls for a condition with a
// generous deadline and reports what it last saw; nothing sleeps a fixed
// duration and then asserts.
package e2e

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// bins are the binaries under test, built once by TestMain.
var bins binaries

// containerScenarioRan is set by the container scenario when it has actually
// run, so that a run which asked for a container and got none fails.
//
// The container scenario already asserts that the *inner* run executed, because
// `go test` prints a bare PASS for a run that skipped everything. The same hole
// exists one level up and nothing here could see it: `make test-integration-docker`
// selects the outer scenario with `-run InContainer`, free text that duplicates a
// test name with nothing tying the two together, and `go test` reports a pattern
// matching nothing as "ok … [no tests to run]" and exits zero. Renaming the outer
// scenario therefore turned the target — and the CI job that is the only place
// the container scenario ever runs — green having containerised nothing.
//
// TestMain is the only place that can catch it, because by the time any test
// body runs the pattern has already decided which bodies there are.
var containerScenarioRan atomic.Bool

// binaries locates the built commands.
type binaries struct {
	agent    string
	mcp      string
	fleetctl string
	// tui is what `fleetctl tui` hands the terminal to. No scenario executes
	// it directly; it is here so that its absence is a build failure.
	tui string
	// helpers is the workload the scenarios run on a sandbox: a dev server, a
	// process that keeps talking, a process tree. See testdata/helpers.
	helpers string
}

// repoRoot is the module root, found by walking up from the test's working
// directory until go.mod appears.
var repoRoot string

func TestMain(m *testing.M) {
	code, err := runMain(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

// runMain does TestMain's work with errors instead of exits, so the temporary
// build directory is removed on every path out.
func runMain(m *testing.M) (int, error) {
	root, err := findRepoRoot()
	if err != nil {
		return 0, err
	}
	repoRoot = root

	dir, err := os.MkdirTemp("", "fleet-e2e-bin")
	if err != nil {
		return 0, fmt.Errorf("create build directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	if bins, err = buildBinaries(dir); err != nil {
		return 0, err
	}
	if runtime.GOOS == "windows" {
		// Said out loud, once, because `go test` reports a package whose every
		// test skipped as "ok" — and an "ok" that ran nothing is the exact
		// shape of the failures this suite was written to catch. The skips
		// themselves are only visible under -v.
		fmt.Fprintf(os.Stderr,
			"e2e: every scenario in this package skips on %s; this run proves nothing about a Windows agent. See test/e2e/README.md.\n",
			runtime.GOOS)
	}
	code := m.Run()

	// A run that asked for the container scenario and never reached one is a
	// failure, not a pass. See containerScenarioRan. Only when the run was
	// otherwise green: a non-zero code already says something went wrong, and
	// the scenario does not record itself when it fails. The in-container guard
	// is for the inner run, which is started with FLEET_E2E_IN_CONTAINER=1 and
	// skips the outer half by design.
	if code == 0 && os.Getenv(dockerEnv) == "1" && os.Getenv(inContainerEnv) != "1" && !containerScenarioRan.Load() {
		return 0, fmt.Errorf(
			"%s=1 asked for the container scenario and no container scenario ran: the -run pattern that "+
				"selected this test binary (see the test-integration-docker target) matches nothing. `go test` "+
				"reports an unmatched -run as \"ok … [no tests to run]\" and exits zero, so without this check "+
				"the target and its CI job would have passed having containerised nothing",
			dockerEnv)
	}
	return code, nil
}

// buildBinaries compiles every command into dir.
//
// The binaries are built rather than run through `go run` so that a test can
// start, kill and restart a daemon without a compile step in the middle of the
// scenario it is measuring — and so that the pid the test holds is the agent's
// own, not a `go run` wrapper that would swallow the signal.
func buildBinaries(dir string) (binaries, error) {
	targets := []string{"./cmd/...", "./test/e2e/testdata/helpers"}
	for _, target := range targets {
		// -buildvcs=false because the build has to work where git will not
		// answer. The container scenario mounts this repository into an image
		// running as root, git refuses a working tree owned by another uid, and
		// `go build` turns that refusal into "error obtaining VCS status" — a
		// build failure caused entirely by stamping a commit hash into a binary
		// that is deleted at the end of the run.
		//
		// No scenario asserts what the version string *is*, and none may: these
		// binaries carry internal/version's unstamped defaults. One asserts that
		// the two sources of it agree, which those defaults are enough for — the
		// bug it covers was "dev" against "dev (unknown, built unknown)", both
		// of them unstamped values.
		cmd := exec.Command("go", "build", "-buildvcs=false", "-o", dir+string(os.PathSeparator), target)
		cmd.Dir = repoRoot
		if out, err := cmd.CombinedOutput(); err != nil {
			return binaries{}, fmt.Errorf("build %s: %w\n%s", target, err, out)
		}
	}
	b := binaries{
		agent:    filepath.Join(dir, exeName("fleet-agent")),
		mcp:      filepath.Join(dir, exeName("fleet-mcp")),
		fleetctl: filepath.Join(dir, exeName("fleetctl")),
		// tui is never run by name: `fleetctl tui` finds it beside fleetctl,
		// which is what this directory arranges. Named here so that a build
		// which stopped producing it is reported now, rather than as a `tui`
		// scenario failing later with a message about a missing helper.
		tui:     filepath.Join(dir, exeName("fleet-tui")),
		helpers: filepath.Join(dir, exeName("helpers")),
	}
	for _, path := range []string{b.agent, b.mcp, b.fleetctl, b.tui, b.helpers} {
		if _, err := os.Stat(path); err != nil {
			return binaries{}, fmt.Errorf("built binary missing: %w", err)
		}
	}
	return b, nil
}

func exeName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod above %s", dir)
		}
		dir = parent
	}
}

// requireSupportedHost skips every scenario on a platform the suite cannot
// drive yet.
//
// The workloads the scenarios run on a sandbox are POSIX: `sh -c`, `cat`,
// `true`, and a process tree whose members are killed by group. A Windows agent
// is a supported target of the product and is covered by the unit tests on the
// CI matrix — internal/platform's job objects, signals and path handling all
// have Windows tests — but nothing here has been written to drive one, and a
// suite that half-skipped its way through Windows would report a coverage it
// does not have. See README.md.
func requireSupportedHost(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the end-to-end suite drives sandbox workloads with POSIX commands; a Windows sandbox needs its own scenarios (see test/e2e/README.md)")
	}
}

// waitFor polls until cond reports true, and fails the test with the last
// detail cond returned if the deadline passes first.
//
// Every wait in this package goes through here. The rule the suite follows is
// that an assertion may depend on a fact being *eventually* observable, and may
// never depend on when: a scenario that crosses three processes, a TLS
// handshake and a filesystem has no meaningful upper bound on any single step,
// and a test that asserts one produces a failure that says nothing about the
// product.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() (bool, string)) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var detail string
	for {
		ok, d := cond()
		if ok {
			return
		}
		detail = d
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s: %s", timeout, what, detail)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// freePort returns a loopback port nothing is listening on.
//
// It closes the listener before returning, so the port is only probably still
// free — the usual race, and unavoidable for a daemon that takes its address
// from a config file written before it starts. Callers pass the port to a
// process that binds it immediately and then wait for the bind to be
// observable, so the race closes in the one place it could matter.
func freePort(t *testing.T) int {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a loopback port: %v", err)
	}
	port := lis.Addr().(*net.TCPAddr).Port
	if err := lis.Close(); err != nil {
		t.Fatalf("release the reserved port: %v", err)
	}
	return port
}

// dialable reports whether something is accepting TCP connections at addr.
func dialable(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// contains is strings.Contains, named for how the assertions read.
func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }
