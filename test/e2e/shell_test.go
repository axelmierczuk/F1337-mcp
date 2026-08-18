//go:build integration

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aymanbagabas/go-pty"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// `fleetctl shell`, driven the way an operator drives it.
//
// These scenarios run the real command on a real pseudo-terminal: the test
// allocates a terminal, starts `fleetctl` attached to it, types into it, and
// reads what comes back. Everything in between is the product — raw mode, the
// mTLS stream, the agent's own pseudo-terminal, the process group on the far
// end — which is the point. A shell's bugs live in exactly those joins, and a
// scenario that drove the session through a Go API instead would miss the two
// that matter most: the local terminal is never put back, and a resize never
// reaches the far end.

// shellClient is `fleetctl shell` running on a terminal this scenario drives.
type shellClient struct {
	t   *testing.T
	tty platform.PTY
	cmd *pty.Cmd

	output *syncBuffer
	done   chan struct{}
	err    error
}

// openShell starts `fleetctl shell` with args, attached to a fresh terminal.
func (f *fleet) openShell(t *testing.T, size [2]int, args ...string) *shellClient {
	t.Helper()

	if !platform.PTYSupported() {
		t.Skip("no pseudo-terminal available on this host")
	}
	tty, err := platform.OpenPTY()
	if err != nil {
		t.Fatalf("allocate a terminal for the client: %v", err)
	}
	if err := tty.Resize(size[0], size[1]); err != nil {
		t.Fatalf("size the client's terminal: %v", err)
	}

	cmd := tty.Command(bins.fleetctl, append([]string{"shell"}, args...)...)
	cmd.Env = f.ctlEnv()

	c := &shellClient{t: t, tty: tty, cmd: cmd, output: &syncBuffer{}, done: make(chan struct{})}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start fleetctl shell: %v", err)
	}

	// One reader, started before anything is typed, so nothing the session
	// prints is missed between starting and the first assertion.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := tty.Read(buf)
			if n > 0 {
				_, _ = c.output.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer close(c.done)
		c.err = cmd.Wait()
	}()

	t.Cleanup(func() {
		c.kill()
		// Unconditionally, and not inside kill: a scenario whose client exited
		// on its own has nothing to kill and still allocated a terminal, and a
		// pseudo-terminal per scenario that nothing releases is a leak in the
		// harness rather than in the product. Closing twice is safe here — this
		// is the test's own pty, and go-pty guards the second Unix close.
		_ = c.tty.Close()
		if t.Failed() {
			t.Logf("fleetctl shell terminal:\n%s", c.printed())
		}
	})
	return c
}

// typed sends bytes to the client's terminal as if the operator had typed them.
func (c *shellClient) typed(text string) {
	c.t.Helper()
	if _, err := c.tty.Write([]byte(text)); err != nil {
		c.t.Fatalf("type into the client's terminal: %v", err)
	}
}

// typedLine sends a line, ending it the way a terminal does.
//
// Carriage return, not newline: Enter is CR on a terminal, and the line
// discipline is what turns it into the NL a program reads. Sending NL types a
// line that was never entered — harmlessly here, where every scenario is POSIX,
// and not at all harmlessly on a Windows console, which is why the unit tests
// spell it the same way.
func (c *shellClient) typedLine(text string) { c.typed(text + "\r") }

// resized changes the size of the client's own terminal, which is what a person
// dragging a window corner does.
func (c *shellClient) resized(columns, rows int) {
	c.t.Helper()
	if err := c.tty.Resize(columns, rows); err != nil {
		c.t.Fatalf("resize the client's terminal: %v", err)
	}
}

// printed is everything the client has rendered so far.
func (c *shellClient) printed() string { return c.output.String() }

// awaitOutput waits for the client to render something containing want.
func (c *shellClient) awaitOutput(want string) {
	c.t.Helper()
	waitFor(c.t, 60*time.Second, "the session to print "+strconv.Quote(want), func() (bool, string) {
		if contains(c.printed(), want) {
			return true, ""
		}
		return false, "so far it printed:\n" + c.printed()
	})
}

// awaitExit waits for the client to exit and returns its status.
func (c *shellClient) awaitExit() int {
	c.t.Helper()
	select {
	case <-c.done:
	case <-time.After(60 * time.Second):
		c.t.Fatalf("fleetctl shell did not exit; it printed:\n%s", c.printed())
	}
	if c.cmd.ProcessState == nil {
		c.t.Fatalf("fleetctl shell produced no exit status: %v", c.err)
	}
	return c.cmd.ProcessState.ExitCode()
}

// running reports whether the client is still up.
func (c *shellClient) running() bool {
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

// kill ends the client the way closing a terminal window does, without letting
// it shut the session down cleanly. The terminal is released by the caller's
// cleanup, which runs whether or not there was anything left to kill.
func (c *shellClient) kill() {
	if !c.running() {
		return
	}
	if c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
	select {
	case <-c.done:
	case <-time.After(30 * time.Second):
	}
}

// TestShellRunsOnTheSelectedSandboxAndReturnsItsExitCode is the whole feature in
// one scenario: an operator chooses a host, opens a shell on it, runs something
// that proves it ran *there*, and exits with a status the CLI passes on.
func TestShellRunsOnTheSelectedSandboxAndReturnsItsExitCode(t *testing.T) {
	f := newFleet(t)
	alpha := f.enroll("alpha", enrollOptions{})
	beta := f.enroll("beta", enrollOptions{})

	// The same file name in each agent's home directory with different
	// contents. `fleet_exec` scenarios use this to tell the two hosts apart,
	// and a shell session with no working directory starts in the same place.
	for _, a := range []*agent{alpha, beta} {
		writeFile(t, filepath.Join(a.home, markerFile), []byte(a.name+"\n"))
	}

	// The sticky selection, chosen with the shipped command and then not named
	// again: the second rule of the resolution order, end to end.
	out := runCLI(t, bins.fleetctl, []string{"select", beta.name}, f.ctlEnv())
	if !contains(out, beta.name) {
		t.Fatalf("`fleetctl select` did not report what it selected: %s", out)
	}

	c := f.openShell(t, [2]int{100, 40})

	// Every string asserted on below is one a program printed. A terminal
	// echoes what is typed at it, so matching typed text would hold for a
	// session in which nothing ever ran.
	c.typedLine("cat " + markerFile)
	c.awaitOutput(beta.name)
	if contains(c.printed(), alpha.name) {
		t.Fatalf("the session reached the wrong sandbox:\n%s", c.printed())
	}

	c.typedLine("exit 3")
	if code := c.awaitExit(); code != 3 {
		t.Fatalf("fleetctl exited %d; the remote shell's status has to be the CLI's own", code)
	}
}

// TestShellSessionIsAuditedWithoutItsContents is the assertion this feature
// exists to satisfy.
//
// A shell is the most direct remote-code-execution surface in the product, so
// the record of who opened one matters more here than anywhere else — and the
// contents must never be in it. A session carries passwords, tokens and
// whatever the operator pastes; a log that captured them would be a credential
// store nobody meant to build, on the least protected host in the fleet.
func TestShellSessionIsAuditedWithoutItsContents(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})

	// Two secrets that exist in different places. The typed one reaches the
	// host only as bytes on the session; the printed one exists only as the
	// host's own output, since `echo` of a shell expansion is not text anybody
	// typed.
	const (
		typedSecret = "hunter2-typed-into-the-shell"
		printedOnly = "printed-only-"
	)

	c := f.openShell(t, [2]int{100, 40}, a.name)
	c.typedLine("echo " + printedOnly + "$((6*7))")
	c.awaitOutput(printedOnly + "42")

	c.typedLine("echo " + typedSecret + " > /dev/null")
	c.typedLine("exit 0")
	if code := c.awaitExit(); code != 0 {
		t.Fatalf("fleetctl shell exited %d", code)
	}

	auditPath := filepath.Join(a.dir, "logs", "audit.jsonl")
	var record map[string]any
	waitFor(t, 30*time.Second, "the session to reach the audit log", func() (bool, string) {
		data, err := os.ReadFile(auditPath)
		if err != nil {
			return false, "no audit log at " + auditPath
		}
		for _, line := range strings.Split(string(data), "\n") {
			if !contains(line, "ShellService/Shell") {
				continue
			}
			if err := json.Unmarshal([]byte(line), &record); err != nil {
				return false, "unparseable record: " + line
			}
			return true, ""
		}
		return false, "no shell record yet"
	})

	if got := record["principal"]; got != "fleet-mcp" {
		t.Fatalf("the session is attributed to %v, want the authenticated control identity", got)
	}
	if got := record["sandbox"]; got != a.name {
		t.Fatalf("the record names sandbox %v, want %q", got, a.name)
	}
	if got := record["outcome"]; got != "ok" {
		t.Fatalf("the record reports outcome %v", got)
	}
	if _, ok := record["time"].(string); !ok {
		t.Fatalf("the record does not say when the session started: %+v", record)
	}
	if _, ok := record["duration_ms"].(float64); !ok {
		t.Fatalf("the record does not say how long the session ran, so its end cannot be derived: %+v", record)
	}
	if code, ok := record["exit_code"].(float64); !ok || code != 0 {
		t.Fatalf("the record does not carry the session's exit status: %+v", record)
	}

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read the audit log: %v", err)
	}
	if contains(string(data), typedSecret) {
		t.Fatalf("the audit log captured what the operator typed:\n%s", data)
	}
	if contains(string(data), printedOnly+"42") {
		t.Fatalf("the audit log captured what the session printed:\n%s", data)
	}
	// And neither reached the daemon's own log, which lands on the same disk
	// with none of the audit log's handling.
	if logs := a.logs(); contains(logs, typedSecret) || contains(logs, printedOnly+"42") {
		t.Fatalf("the agent's own log captured the session's contents:\n%s", logs)
	}
}

// TestShellCtrlCInterruptsTheRemoteProgramRatherThanTheClient covers the
// keystroke a shell is unusable without.
//
// In raw mode Ctrl-C is never a signal on the operator's machine: it is byte
// 0x03 on the wire, and the terminal on the far end turns it into a SIGINT for
// whatever is in the foreground there. Both halves are asserted — the remote
// program is interrupted, and the client is still running afterwards.
func TestShellCtrlCInterruptsTheRemoteProgramRatherThanTheClient(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})

	c := f.openShell(t, [2]int{100, 40}, a.name)

	// A program that talks forever, in the foreground. Its own output is what
	// says it is running — a terminal echoes what is typed at it, so matching
	// the command line would hold for a session in which nothing ever started.
	c.typedLine(bins.helpers + " spew 100 tick")
	c.awaitOutput("tick 1")

	c.typed("\x03")

	// One assertion covers both halves of the criterion, and neither is
	// reachable without the other. The shell only reads this next line once the
	// program in front of it has ended, so an interrupt that never reached the
	// far end leaves it unread forever; and a client that took Ctrl-C as a
	// local signal is not there to send it. The marker is arithmetic, so the
	// answer is something the host computed rather than something echoed back.
	c.typedLine("echo after=$((21+21))")
	c.awaitOutput("after=42")

	if !c.running() {
		t.Fatal("Ctrl-C killed the client; in raw mode it is a byte on the wire and never a local signal")
	}

	c.typedLine("exit 0")
	if code := c.awaitExit(); code != 0 {
		t.Fatalf("the shell exited %d after an interrupt it should have survived", code)
	}
}

// sizeLine matches what the winsize helper prints.
var sizeLine = regexp.MustCompile(`size (\d+)x(\d+)`)

// TestShellResizeReflowsTheRemoteProgram follows a window resize all the way
// through.
//
// The scenario resizes its own terminal; the client's SIGWINCH handler turns
// that into a resize message; the agent applies it to the session's terminal;
// and a program running inside the session reports the new size. Without it
// every full-screen program on the far end renders to whatever width the
// session opened at, forever — `top` wraps every row and `vi` puts its status
// line in the middle of the screen.
func TestShellResizeReflowsTheRemoteProgram(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})

	c := f.openShell(t, [2]int{100, 40}, a.name, "--", bins.helpers, "winsize")

	// The size the session opened at, applied before the command started.
	c.awaitOutput("size 100x40")

	c.resized(132, 50)
	c.awaitOutput("size 132x50")

	// And the sizes are the ones this terminal actually has, rather than
	// anything the client invented.
	matches := sizeLine.FindAllStringSubmatch(c.printed(), -1)
	if len(matches) < 2 {
		t.Fatalf("expected the program to report at least two sizes, got %d:\n%s", len(matches), c.printed())
	}
}

// TestShellClosingTheClientKillsTheRemoteTree is the guarantee that keeps a
// disconnected session from leaving processes behind on somebody's machine.
//
// A shell is a process spawner by definition, so "the session ended" has to
// mean the tree ended. The client is killed outright rather than asked to exit:
// a closed laptop lid and a killed terminal emulator are what this is for, and
// neither gives the CLI a chance to say goodbye.
func TestShellClosingTheClientKillsTheRemoteTree(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})

	// A process the agent has nothing to do with, started before the session
	// and expected to be there after it. Its only job is to be a pid the
	// teardown must not touch — this repository has shipped a group kill that
	// terminated an unrelated process through pid reuse.
	bystander := start(t, "bystander", bins.helpers, []string{"sleep"}, procOptions{})

	c := f.openShell(t, [2]int{100, 40}, a.name, "--", bins.helpers, "tree", "2")

	var procs []treeProc
	waitFor(t, 60*time.Second, "every level of the tree to announce itself", func() (bool, string) {
		// Without the carriage returns: a terminal ends every line with CRLF,
		// and the identity pattern the exec scenarios share anchors on the end
		// of a line. A tree that announced itself perfectly would otherwise
		// parse as no tree at all, and this scenario would report a timeout
		// with the answer printed underneath it.
		procs = parseTree(t, withoutCR(c.printed()))
		if len(procs) == 3 {
			return true, ""
		}
		return false, fmt.Sprintf("so far %d levels announced themselves:\n%s", len(procs), c.printed())
	})

	// Registered before the assertions rather than after the last
	// precondition, because the assertions are what fail: a run that gave up
	// here would leave three processes on the machine, and three more next
	// time. Only on failure — on the passing path these pids are already gone
	// and could belong to somebody else by now.
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		for _, p := range procs {
			killPID(p.pid)
		}
	})

	// Checked before anything is asserted about the group, because it is what
	// makes those assertions mean anything: if the session's leader did not
	// lead a group of its own, "the group is empty" would be a claim about a
	// group that never existed.
	leader := procs[0]
	if leader.pgid != leader.pid {
		t.Fatalf("the session's leader (pid %d) is in group %d rather than leading its own; "+
			"the group assertion below would be vacuous", leader.pid, leader.pgid)
	}
	for _, p := range procs[1:] {
		if p.pgid != leader.pgid {
			t.Fatalf("pid %d is in group %d, not the session's group %d", p.pid, p.pgid, leader.pgid)
		}
	}

	c.kill()

	for _, p := range procs {
		waitFor(t, 60*time.Second, fmt.Sprintf("pid %d to be gone", p.pid), func() (bool, string) {
			if !processAlive(p.pid) {
				return true, ""
			}
			return false, fmt.Sprintf("pid %d outlived the session that started it", p.pid)
		})
	}
	waitFor(t, 60*time.Second, "the session's process group to empty", func() (bool, string) {
		members := processGroupMembers(t, leader.pgid)
		if len(members) == 0 {
			return true, ""
		}
		return false, fmt.Sprintf("process group %d still holds %v", leader.pgid, members)
	})

	if !bystander.running() || !processAlive(bystander.pid()) {
		t.Fatalf("pid %d, which the agent never started, was killed with the session", bystander.pid())
	}
	if !a.proc.running() {
		t.Fatalf("the agent died tearing the session down:\n%s", a.logs())
	}
}

// TestShellRefusesWhenStdinIsNotATerminal is the check that keeps an
// interactive command out of a script.
//
// A shell whose input is a pipe cannot be driven: the far end would sit at a
// prompt nobody can answer until the agent's idle timeout reaped it. The
// message names the tool that runs a command and collects its output, because
// that is what the caller wanted.
func TestShellRefusesWhenStdinIsNotATerminal(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})

	out, err := tryCLI(bins.fleetctl, []string{"shell", a.name}, f.ctlEnv())
	if err == nil {
		t.Fatalf("`fleetctl shell` with no terminal succeeded:\n%s", out)
	}
	if !contains(out, "not a terminal") || !contains(out, "fleet_exec") {
		t.Fatalf("the refusal does not say what to use instead:\n%s", out)
	}
}

// withoutCR drops the carriage returns a terminal puts at the end of every
// line, so output captured from one can be matched against patterns written for
// a pipe.
func withoutCR(s string) string { return strings.ReplaceAll(s, "\r", "") }
