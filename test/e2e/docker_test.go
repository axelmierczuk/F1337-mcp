//go:build integration

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Everything in this file is the container half of the suite: one scenario that
// a container makes stronger, and the plumbing that runs it.
//
// The rest of the suite deliberately does not need Docker. An integration suite
// that only runs in CI stops being run, and a scenario that cannot run on the
// machine where the code is being written is a scenario nobody consults while
// they break it.
//
// What the container buys here is a PID namespace small enough to enumerate
// exhaustively. Outside one, "nothing survived" can only be asserted against
// the command's process group — which is the right question and not quite the
// whole one, because a process that escaped its group by calling setsid would
// pass it. Inside one, the claim is absolute: no process anywhere in the
// namespace is running the workload.
const (
	// dockerEnv opts in to the container scenario.
	dockerEnv = "FLEET_E2E_DOCKER"
	// inContainerEnv marks the inner run, so the same test binary knows which
	// half of the pair it is.
	inContainerEnv = "FLEET_E2E_IN_CONTAINER"
	// containerImage carries a Go toolchain and nothing else; the suite builds
	// the binaries it needs from the mounted source.
	containerImage = "golang:1.25"
)

// TestExecTimeoutKillsTheWholeProcessTreeInContainer re-runs the tree-kill
// scenario inside a Linux container, where survivors can be ruled out across a
// whole PID namespace.
//
// It skips unless FLEET_E2E_DOCKER=1. See README.md.
func TestExecTimeoutKillsTheWholeProcessTreeInContainer(t *testing.T) {
	if os.Getenv(inContainerEnv) == "1" {
		t.Skip("already inside the container: this is the outer half of the pair")
	}
	if os.Getenv(dockerEnv) != "1" {
		t.Skipf("set %s=1 to run the container scenario (it pulls %s and builds inside it)", dockerEnv, containerImage)
	}

	modCache := goEnv(t, "GOMODCACHE")
	args := []string{
		"run", "--rm",
		"--volume", repoRoot + ":/src",
		// The module cache is mounted so the inner build does not have to
		// reach the network. A container test that downloads the dependency
		// graph fails for reasons that have nothing to do with the product.
		"--volume", modCache + ":/go/pkg/mod",
		"--workdir", "/src",
		"--env", inContainerEnv + "=1",
		containerImage,
		"go", "test", "-tags", "integration", "-count=1", "-v",
		"-run", "TestNoProcessSurvivesTheTimeoutInsideThisNamespace",
		"./test/e2e/",
	}

	cmd := exec.Command("docker", args...)
	out, err := cmd.CombinedOutput()
	t.Logf("docker run output:\n%s", out)
	if err != nil {
		t.Fatalf("the containerised scenario failed: %v", err)
	}
	if !contains(string(out), "PASS") {
		t.Fatalf("the containerised scenario did not report a pass:\n%s", out)
	}
}

// TestNoProcessSurvivesTheTimeoutInsideThisNamespace is the inner half: the
// same timeout, asserted against every process in the namespace rather than
// against one process group.
func TestNoProcessSurvivesTheTimeoutInsideThisNamespace(t *testing.T) {
	if os.Getenv(inContainerEnv) != "1" {
		t.Skipf("this scenario is the inner half of the container pair; run the suite with %s=1", dockerEnv)
	}
	if runtime.GOOS != "linux" {
		t.Skipf("the namespace enumeration reads /proc, which %s does not have", runtime.GOOS)
	}

	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})
	s := f.connect(t)
	s.ok("fleet_select", map[string]any{"name": a.name})

	// Nothing else in this namespace runs the workload, so its absence
	// afterwards is a complete statement.
	if running := namespaceProcessesRunning(t, bins.helpers); len(running) != 0 {
		t.Fatalf("the workload was already running before the scenario started: %v", running)
	}

	res := structured[execResult](t, s.okAs("fleet_exec", map[string]any{
		"argv":            []string{bins.helpers, "tree", "3"},
		"timeout_seconds": 2,
	}, callOptions{timeout: 120 * time.Second}))

	if !res.TimedOut {
		t.Fatalf("a command that never exits should have been killed for overrunning: %+v", res)
	}
	if pids := parsePIDs(t, res.Stdout); len(pids) != 4 {
		t.Fatalf("expected four levels of the tree to announce themselves, got %v from:\n%s", pids, res.Stdout)
	}

	waitFor(t, 30*time.Second, "every process of the tree to leave the namespace", func() (bool, string) {
		running := namespaceProcessesRunning(t, bins.helpers)
		if len(running) == 0 {
			return true, ""
		}
		return false, "still running: " + strings.Join(running, ", ")
	})

	// The agent survived the sweep it performed, and still answers.
	if !a.proc.running() {
		t.Fatalf("the agent died sweeping the process group:\n%s", a.logs())
	}
	s.ok("fleet_exec", map[string]any{"argv": []string{"true"}})
}

// namespaceProcessesRunning lists every process in this PID namespace whose
// command line names the given executable.
//
// /proc rather than ps: the container image carries a Go toolchain and nothing
// else, and a test that needed procps installed would be testing the image.
func namespaceProcessesRunning(t *testing.T, executable string) []string {
	t.Helper()

	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatalf("read /proc: %v", err)
	}

	var found []string
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			// The process ended between the readdir and the read, which is the
			// ordinary case for anything short-lived and the answer this
			// function wanted anyway.
			continue
		}
		cmdline := strings.ReplaceAll(strings.TrimRight(string(raw), "\x00"), "\x00", " ")
		if strings.Contains(cmdline, executable) {
			found = append(found, strconv.Itoa(pid)+": "+cmdline)
		}
	}
	return found
}

func goEnv(t *testing.T, name string) string {
	t.Helper()

	out, err := exec.Command("go", "env", name).Output()
	if err != nil {
		t.Fatalf("go env %s: %v", name, err)
	}
	return strings.TrimSpace(string(out))
}
