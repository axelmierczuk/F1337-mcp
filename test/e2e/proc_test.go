//go:build integration

package e2e

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// syncBuffer collects a child's output from the goroutine os/exec writes it on,
// while a test reads it from its own.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// proc is a child process the test drives: a control plane, an agent daemon,
// or the MCP server.
//
// Output is captured rather than inherited so that a failing scenario can print
// what the daemon said. A daemon logs to stderr by design — stdout carries
// JSON-RPC for the MCP server and nothing at all for the others — so the two
// streams are kept apart.
type proc struct {
	name string
	cmd  *exec.Cmd
	out  *syncBuffer
	err  *syncBuffer

	// done closes when Wait returns, so a test can ask whether the process is
	// still up without racing the reaper goroutine.
	done    chan struct{}
	waitErr error
}

// procOptions configures a spawned child.
type procOptions struct {
	// env replaces the child's whole environment. Empty inherits the test's,
	// which is what the control plane and the MCP server want; an agent daemon
	// always names its own, because the environment it holds is the identity
	// its exec'd commands inherit.
	env []string
	// dir is the child's working directory. Empty inherits the test's.
	dir string
}

// start launches a child and reaps it in the background.
func start(t *testing.T, name, bin string, args []string, opts procOptions) *proc {
	t.Helper()

	cmd := exec.Command(bin, args...)
	cmd.Env = opts.env
	cmd.Dir = opts.dir

	p := &proc{
		name: name,
		cmd:  cmd,
		out:  &syncBuffer{},
		err:  &syncBuffer{},
		done: make(chan struct{}),
	}
	cmd.Stdout = p.out
	cmd.Stderr = p.err

	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	go func() {
		p.waitErr = cmd.Wait()
		close(p.done)
	}()

	t.Cleanup(func() {
		p.kill()
		if t.Failed() {
			t.Logf("%s stdout:\n%s", name, p.out.String())
			t.Logf("%s stderr:\n%s", name, p.err.String())
		}
	})
	return p
}

// pid is the child's process id.
func (p *proc) pid() int { return p.cmd.Process.Pid }

// running reports whether the child is still alive.
func (p *proc) running() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

// terminate asks the child to shut down the way a service manager would, and
// waits for it to go.
func (p *proc) terminate(t *testing.T) {
	t.Helper()
	if !p.running() {
		return
	}
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal %s: %v", p.name, err)
	}
	p.awaitExit(t, 30*time.Second)
}

// kill ends the child without giving it a chance to drain. It is what
// t.Cleanup uses, and what the crash scenarios use deliberately.
func (p *proc) kill() {
	if !p.running() {
		return
	}
	_ = p.cmd.Process.Kill()
	select {
	case <-p.done:
	case <-time.After(10 * time.Second):
	}
}

// awaitExit waits for the child to be reaped.
func (p *proc) awaitExit(t *testing.T, timeout time.Duration) {
	t.Helper()
	select {
	case <-p.done:
	case <-time.After(timeout):
		t.Fatalf("%s did not exit within %s\nstderr:\n%s", p.name, timeout, p.err.String())
	}
}

// stderr is everything the child has written to stderr so far.
func (p *proc) stderr() string { return p.err.String() }

// stdout is everything the child has written to stdout so far.
func (p *proc) stdout() string { return p.out.String() }

// runCLI runs a command to completion and returns its combined output,
// failing the test if it exits non-zero.
func runCLI(t *testing.T, bin string, args []string, env []string) string {
	t.Helper()

	out, err := tryCLI(bin, args, env)
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", filepathBase(bin), strings.Join(args, " "), err, out)
	}
	return out
}

// tryCLI is runCLI for a command that is expected to fail.
func tryCLI(bin string, args []string, env []string) (string, error) {
	cmd := exec.Command(bin, args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func filepathBase(path string) string {
	if i := strings.LastIndexAny(path, `/\`); i >= 0 {
		return path[i+1:]
	}
	return path
}

// processAlive reports whether a pid names a live process.
//
// It is only ever asked about a pid this suite started, and only to prove that
// something the agent should not have signalled is still there — never to
// decide that a pid *is* a particular process, which is the mistake the
// supervisor's own start-identity check exists to avoid.
func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// Signal 0 asks the kernel the question without delivering anything. On
	// Windows FindProcess itself fails for a dead pid, so this reduces to the
	// error above.
	return p.Signal(syscall.Signal(0)) == nil
}

// killPID ends a process the test started through the product — a supervised
// process outlives its agent by design, so nothing else would.
func killPID(pid int) {
	if pid <= 0 {
		return
	}
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Kill()
	}
}

// envWith returns a child environment built from name=value pairs.
func envWith(pairs ...string) []string {
	env := make([]string, 0, len(pairs))
	env = append(env, pairs...)
	return env
}

func envEntry(key, value string) string { return fmt.Sprintf("%s=%s", key, value) }
