//go:build integration

package e2e

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aymanbagabas/go-pty"
)

// `fleetctl tui`, driven the only way it can honestly be driven: on a real
// pseudo-terminal, with the real binary, against real agents.
//
// The unit tests in internal/tui cover the model and the frames — state
// transitions, confirmation gating, refresh scheduling, and the rendered output
// at a dozen sizes. What they cannot cover is the half of this feature that is
// not Go values: whether the program can get a terminal, draw on it, and give
// it back. That is what is here.

// TestTUIDrawsTheFleetAndGivesTheTerminalBack is the whole feature in one
// scenario: two enrolled sandboxes, a supervised process on one of them, one
// of them going away while the view is watching, and an operator who quits.
//
// The sandbox that goes away is the point of the fleet half, and it goes away
// *after* the view has already drawn it as serving. That ordering is the only
// place the background health loop can be observed: the pool probes once when
// a channel is first dialed, so a view that never probed again would draw this
// fleet exactly the same way for the first ten seconds and then be wrong about
// it forever. It also covers the other half — that a machine which stops
// answering renders as unhealthy rather than stalling or blanking the view,
// which is the failure mode a twenty-machine fleet makes certain, because a
// fleet that size always has one machine that is asleep.
func TestTUIDrawsTheFleetAndGivesTheTerminalBack(t *testing.T) {
	f := newFleet(t)
	live := f.enroll("build-box", enrollOptions{})
	fading := f.enroll("gone-box", enrollOptions{})

	s := f.connect(t)
	s.ok("fleet_select", map[string]any{"name": live.name})
	started := startProcess(t, s, map[string]any{
		"name": "chatty",
		"argv": []string{bins.helpers, "spew", "50", "tick"},
	})
	defer stopProcess(t, s, started)

	// A short refresh so the second probe lands inside this test rather than
	// inside the operator's attention span. What is under test is that there
	// is a second probe at all.
	tui := startTUI(t, f, tuiArgs("--refresh", "2s"))

	tui.waitForScreen(t, "the fleet pane to list both sandboxes", live.name, fading.name)
	tui.waitForScreen(t, "both sandboxes to be reported serving", "2 serving")

	// The processes pane is reading the same agent the MCP server just started
	// a process on, through the same client. Its output is what proves the pane
	// is a view of the product rather than of a fixture.
	tui.waitForScreen(t, "the processes pane to show the supervised process", started.Process.Name)
	tui.waitForScreen(t, "the logs pane to follow the process's output", "tick ")

	// And now one of them goes away, with the view already watching it.
	fading.proc.kill()
	tui.waitForScreen(t, "the sandbox that went away to be re-probed and reported unreachable", "unreachable")

	// The rest of the view is still there: one dead machine does not blank it.
	tui.waitForScreen(t, "the live sandbox to still be drawn", live.name, started.Process.Name)

	tui.send("q")
	tui.awaitExit(t, 30*time.Second)

	if code := tui.exitStatus(t); code != 0 {
		t.Fatalf("quitting the TUI exited %d\nscreen:\n%s", code, tui.screen())
	}
	tui.requireTerminalRestored(t)
}

// TestTUIGivesTheTerminalBackOnSIGTERM covers the exit path nobody chooses: a
// service manager, a timeout, or an operator in another window.
//
// It is the same assertion as the quit path and a different code path to reach
// it — the signal cancels the command's context rather than producing a
// keystroke — and it is the one the issue calls out, because a full-screen
// program killed with the terminal in raw mode leaves a shell that does not
// echo and does not respond to ^C.
func TestTUIGivesTheTerminalBackOnSIGTERM(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})

	tui := startTUI(t, f)
	tui.waitForScreen(t, "the fleet pane to draw", a.name)

	// Through os.FindProcess rather than syscall.Kill: this file has to
	// typecheck under GOOS=windows, where syscall.Kill does not exist, and a
	// runtime skip cannot save a package that does not compile. The suite's
	// proc helper signals the same way for the same reason.
	target, err := os.FindProcess(tui.pid(t))
	if err != nil {
		t.Fatalf("find the TUI process: %v", err)
	}
	if err := target.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal the TUI: %v", err)
	}
	tui.awaitExit(t, 30*time.Second)

	// Exit zero: the operator asked it to stop, and a wrapper script that read
	// a requested shutdown as a failure would be wrong every time.
	if code := tui.exitStatus(t); code != 0 {
		t.Fatalf("SIGTERM made the TUI exit %d\nscreen:\n%s", code, tui.screen())
	}
	tui.requireTerminalRestored(t)
}

// TestTUIWithoutATerminalSaysWhatToUseInstead.
//
// A full-screen program whose output is a pipe emits escape sequences and no
// frames, which reads as a hang. The assertion is on the sentence, not on the
// exit code: a `tui` that failed for some other reason would also exit
// non-zero, and this is about what the operator is told.
func TestTUIWithoutATerminalSaysWhatToUseInstead(t *testing.T) {
	f := newFleet(t)
	f.enroll("build-box", enrollOptions{})

	out, err := tryCLI(bins.fleetctl, []string{"tui"}, f.ctlEnv())
	if err == nil {
		t.Fatalf("`fleetctl tui` with no terminal succeeded:\n%s", out)
	}
	if !strings.Contains(out, "needs a terminal") {
		t.Fatalf("the refusal does not say a terminal is what is missing:\n%s", out)
	}
	if !strings.Contains(out, "fleetctl list --json") {
		t.Fatalf("the refusal does not name the scriptable view to use instead:\n%s", out)
	}
}

// -------------------------------------------------------------- harness

// tuiSession is `fleetctl tui` running on a pseudo-terminal.
//
// The program under test is not the direct child. A shell is, and it records
// the terminal's mode with `stty -g` before starting the TUI and again after it
// exits — which is what makes "the terminal was restored" an observation rather
// than a claim. Two other things fall out of that arrangement, both necessary:
// the shell is the session leader, so the pty is not revoked out from under the
// test when the program exits (macOS does exactly that), and the exit status is
// recorded by something that outlives the process it belongs to.
type tuiSession struct {
	pty  pty.Pty
	cmd  *pty.Cmd
	out  *syncBuffer
	dir  string
	done chan error
}

// tuiScript is what the shell runs. Deliberately without `set -e`: a non-zero
// TUI is a result this test wants recorded, not a reason to skip recording it.
//
// FLEET_TUI_ARGS is unquoted on purpose: it is a scenario's own flags, split on
// whitespace by the shell, and there is no scenario that needs one with a space
// in it.
const tuiScript = `
stty -g > "$FLEET_TUI_DIR/before"
"$FLEET_TUI_BIN" tui $FLEET_TUI_ARGS &
echo $! > "$FLEET_TUI_DIR/pid"
wait $!
echo $? > "$FLEET_TUI_DIR/status"
stty -g > "$FLEET_TUI_DIR/after"
`

// tuiArgs is extra flags for the `tui` command, passed through startTUI's
// environment the same way everything else about the run is.
func tuiArgs(args ...string) string { return envEntry("FLEET_TUI_ARGS", strings.Join(args, " ")) }

func startTUI(t *testing.T, f *fleet, extraEnv ...string) *tuiSession {
	t.Helper()

	term, err := pty.New()
	if err != nil {
		t.Fatalf("allocate a pseudo-terminal: %v", err)
	}
	// 80x24 is the size the issue names, so it is the size this runs at.
	if err := term.Resize(80, 24); err != nil {
		t.Fatalf("size the pseudo-terminal: %v", err)
	}

	dir := t.TempDir()
	s := &tuiSession{pty: term, out: &syncBuffer{}, dir: dir, done: make(chan error, 1)}

	cmd := term.Command("/bin/sh", "-c", tuiScript)
	cmd.Env = append(f.ctlEnv(),
		envEntry("FLEET_TUI_DIR", dir),
		envEntry("FLEET_TUI_BIN", bins.fleetctl),
		// A terminal that claims colour and a UTF-8 locale, which is what an
		// operator's ssh session forwards. The program's behaviour without
		// either is a decision made from the environment and unit-tested in
		// internal/tui; what is being exercised here is the ordinary case.
		envEntry("TERM", "xterm-256color"),
		envEntry("LANG", "en_US.UTF-8"),
	)
	// Appended last, so a scenario about a terminal without colour or without
	// a UTF-8 locale can replace what the ordinary case sets.
	cmd.Env = append(cmd.Env, extraEnv...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the TUI on a pseudo-terminal: %v", err)
	}
	s.cmd = cmd

	// Everything the terminal is sent, kept so an assertion can look at the
	// screen and a failure can print it.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := term.Read(buf)
			if n > 0 {
				_, _ = s.out.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	go func() { s.done <- cmd.Wait() }()

	t.Cleanup(func() {
		killPID(s.readPID())
		select {
		case <-s.done:
		case <-time.After(10 * time.Second):
		}
		_ = term.Close()
		if t.Failed() {
			t.Logf("terminal:\n%s", s.screen())
		}
	})
	return s
}

// screen is everything the program has written to the terminal, with the escape
// sequences stripped so a failure prints something a person can read.
func (s *tuiSession) screen() string { return stripEscapes(s.out.String()) }

// send types at the terminal.
func (s *tuiSession) send(keys string) {
	_, _ = s.pty.Write([]byte(keys))
}

// waitForScreen waits until every fragment has appeared on the terminal.
//
// On what was drawn, never on how long it took to draw: the view refreshes on
// its own schedule, a health probe crosses a TLS handshake, and this suite runs
// on machines under load. Eventually-observable is the standard here; see
// waitFor.
func (s *tuiSession) waitForScreen(t *testing.T, what string, fragments ...string) {
	t.Helper()
	waitFor(t, 60*time.Second, what, func() (bool, string) {
		screen := s.screen()
		for _, fragment := range fragments {
			if !strings.Contains(screen, fragment) {
				return false, fmt.Sprintf("%q has not appeared; the terminal holds:\n%s", fragment, screen)
			}
		}
		return true, ""
	})
}

func (s *tuiSession) awaitExit(t *testing.T, timeout time.Duration) {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(timeout):
		t.Fatalf("the TUI did not exit within %s\nterminal:\n%s", timeout, s.screen())
	}
}

// pid is the process id of `fleetctl tui` itself, which the shell recorded.
func (s *tuiSession) pid(t *testing.T) int {
	t.Helper()
	waitFor(t, 30*time.Second, "the TUI to report its process id", func() (bool, string) {
		return s.readPID() > 0, "no pid recorded yet"
	})
	return s.readPID()
}

func (s *tuiSession) readPID() int {
	raw, err := os.ReadFile(filepath.Join(s.dir, "pid"))
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return 0
	}
	return pid
}

func (s *tuiSession) exitStatus(t *testing.T) int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(s.dir, "status"))
	if err != nil {
		t.Fatalf("the shell recorded no exit status for the TUI: %v", err)
	}
	code, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("the recorded exit status %q is not a number", raw)
	}
	return code
}

// requireTerminalRestored compares the terminal's mode before the TUI ran with
// its mode after.
//
// `stty -g` is the terminal's whole settings word: echo, canonical mode, the
// interrupt character, every flag a full-screen program turns off. A program
// that left the terminal in raw mode differs here in exactly the way an
// operator would discover it — a shell that no longer echoes what they type and
// no longer answers ^C.
func (s *tuiSession) requireTerminalRestored(t *testing.T) {
	t.Helper()

	before := s.readMode(t, "before")
	after := s.readMode(t, "after")
	if before != after {
		t.Fatalf("the terminal was not restored\nbefore: %s\nafter:  %s", before, after)
	}
}

func (s *tuiSession) readMode(t *testing.T, which string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(s.dir, which))
	if err != nil {
		t.Fatalf("the terminal's mode %s the run was not recorded: %v", which, err)
	}
	mode := strings.TrimSpace(string(raw))
	if mode == "" {
		t.Fatalf("the terminal's mode %s the run was recorded empty", which)
	}
	return mode
}

// stripEscapes removes ANSI escape sequences, so an assertion sees the text a
// terminal would have shown rather than the instructions for showing it.
func stripEscapes(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != 0x1b {
			b.WriteByte(s[i])
			i++
			continue
		}
		i++
		if i < len(s) && (s[i] == '[' || s[i] == ']' || s[i] == '(') {
			opener := s[i]
			i++
			// CSI and friends end at the first byte in 0x40..0x7e. An OSC ends
			// at a BEL *or* at a string terminator, which is ESC \ — and a
			// stripper that knows only about BEL swallows the whole rest of the
			// stream when it meets one, because the terminal's colour query
			// (OSC 11) is ST-terminated. That is not a hypothetical: it is what
			// this function did first, and it made every screen read empty.
			for i < len(s) {
				c := s[i]
				i++
				if opener == ']' {
					if c == 0x07 || c == 0x9c {
						break
					}
					if c == 0x1b && i < len(s) && s[i] == '\\' {
						i++
						break
					}
					continue
				}
				if c >= 0x40 && c <= 0x7e {
					break
				}
			}
			continue
		}
		// A two-character escape; the second character is the whole of it.
		i++
	}
	return b.String()
}

// -------------------------------------------------- the hand-off itself

// handOffScript drives `fleetctl tui` the way the operator's shell does, and
// records the pid that shell is given.
//
// Backgrounded and waited on rather than run in the foreground, because `$!` is
// the only way to ask a shell what pid it thinks this command has — and that
// pid against the one the helper reports is the whole exec assertion.
const handOffScript = `
"$FLEET_CTL" tui $FLEET_HANDOFF_ARGS &
echo $! > "$FLEET_HANDOFF_DIR/shell-pid"
wait $!
echo $? > "$FLEET_HANDOFF_DIR/status"
`

// handOffArgs are the flags the operator types after the subcommand, and every
// one of them is a flag whose value the far side cannot recover on its own.
//
// --refresh and --timeout are durations the helper has no way to guess, and
// --registry names the file the whole view is read from. They are given values
// nothing else in this suite uses, so a match cannot be a coincidence.
var handOffArgs = []string{"--refresh", "7s", "--timeout", "11s", "--registry", "/nowhere/registry.yaml"}

// TestTheHandOffKeepsTheCommandLineAndTheProcess is the two promises
// `fleetctl tui` makes about handing over, neither of which anything else here
// observes.
//
// **The argv reaches the helper unchanged.** This is the answer #44 is owed.
// `tui` takes --ca-dir, --cert and --key — the operator's credential paths —
// along with --registry, --timeout and --refresh, and the reason there is no
// second place to misconfigure a fleet is that these are forwarded verbatim
// rather than re-serialised from parsed flags. Dropping every one of them on
// the way across passed the whole suite, unit and end-to-end, before this
// scenario existed: the view came up on the *default* config directory and
// registry and drew a plausible screen, which is precisely the silent
// divergence that argument promises cannot happen.
//
// **The hand-off is an exec, not a child.** The pid the shell recorded has to
// be the process that ends up drawing, or a signal sent to it reaches a wrapper
// and leaves the view holding a terminal nothing will put back — and the exit
// status the shell reads has to be the view's own.
//
// The helper is a stub rather than the real fleet-tui because the subject is
// the hand-off. A stub is the only thing that can report what argv it was
// handed and which pid it was handed it as; the real binary is driven by every
// other scenario in this file.
func TestTheHandOffKeepsTheCommandLineAndTheProcess(t *testing.T) {
	requireSupportedHost(t)

	record := t.TempDir()
	install := t.TempDir()
	installFleetctl(t, install)
	installStubHelper(t, install)

	term, err := pty.New()
	if err != nil {
		t.Fatalf("allocate a pseudo-terminal: %v", err)
	}
	if err := term.Resize(80, 24); err != nil {
		t.Fatalf("size the pseudo-terminal: %v", err)
	}
	t.Cleanup(func() { _ = term.Close() })

	cmd := term.Command("/bin/sh", "-c", handOffScript)
	cmd.Env = envWith(
		envEntry("FLEET_CTL", filepath.Join(install, exeName("fleetctl"))),
		envEntry("FLEET_HANDOFF_DIR", record),
		envEntry("FLEET_HANDOFF_ARGS", strings.Join(handOffArgs, " ")),
		envEntry("FLEET_CONFIG_DIR", record),
		envEntry("PATH", os.Getenv("PATH")),
		envEntry("HOME", record),
		envEntry("TMPDIR", os.TempDir()),
		envEntry("TERM", operatorTerm),
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start `fleetctl tui` on a pseudo-terminal: %v", err)
	}
	// Drained rather than read: nothing is asserted on the screen here, but a
	// terminal nobody reads fills up and stops the writer.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := term.Read(buf); err != nil {
				return
			}
		}
	}()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})

	// On the status file having *content*, not on it existing: `echo $? >`
	// creates it and then writes it, and a read between the two would compare
	// against an empty string and call the mismatch a failure of the product.
	waitFor(t, 30*time.Second, "the hand-off to complete", func() (bool, string) {
		raw, err := os.ReadFile(filepath.Join(record, "status"))
		return err == nil && len(bytes.TrimSpace(raw)) > 0,
			"the shell has not finished waiting on `fleetctl tui`"
	})

	// Unchanged, and compared as one string because that is what was forwarded:
	// a scenario that checked the flags were "present" would pass for an argv
	// that had been taken apart and put back together in a different order.
	want := strings.Join(append([]string{"tui"}, handOffArgs...), " ")
	if got := recorded(t, record, "argv"); got != want {
		t.Errorf("the helper was handed `%s`, but the operator typed `fleetctl %s`;\n"+
			"the command line is forwarded unchanged so that there is one implementation of every flag "+
			"— including the credential paths — rather than a second one on the far side (#44)",
			got, want)
	}

	// One process, and it is the one the operator's shell will signal.
	shellPID, helperPID := recorded(t, record, "shell-pid"), recorded(t, record, "helper-pid")
	if shellPID != helperPID {
		t.Errorf("the shell was given pid %s and the helper ran as pid %s: the hand-off forked instead of exec'ing.\n"+
			"A wrapper between the operator's shell and the program holding the terminal is one more place "+
			"`terminal restored on every exit path` can be broken", shellPID, helperPID)
	}

	// And the status the shell reads is the helper's own, not a wrapper's
	// summary of it.
	if got := recorded(t, record, "status"); got != stubHelperStatus {
		t.Errorf("the shell read exit status %s; the helper exited %s", got, stubHelperStatus)
	}
}

// stubHelperStatus is what the stub helper exits with: an unremarkable number
// that nothing else in this suite produces, so reading it back means it came
// from the helper rather than from something failing on the way.
const stubHelperStatus = "17"

// installFleetctl puts the real fleetctl into dir under its own name, so that
// "the helper beside fleetctl" resolves to dir and not to the build directory
// where the real fleet-tui lives.
//
// Linked rather than copied where the filesystem allows it: this is a 20 MiB
// binary and the link is the same file by another name, which is all the lookup
// looks at.
func installFleetctl(t *testing.T, dir string) {
	t.Helper()

	path := filepath.Join(dir, exeName("fleetctl"))
	if err := os.Link(bins.fleetctl, path); err == nil {
		return
	}
	source, err := os.ReadFile(bins.fleetctl)
	if err != nil {
		t.Fatalf("read fleetctl: %v", err)
	}
	if err := os.WriteFile(path, source, 0o755); err != nil { //nolint:gosec // a copy of a binary this test just built
		t.Fatalf("install fleetctl into %s: %v", dir, err)
	}
}

// installStubHelper writes a fleet-tui that reports what it was handed.
//
// It records its own pid and argv and exits with a known status, which is the
// whole of what this scenario needs to know about the far side.
func installStubHelper(t *testing.T, dir string) {
	t.Helper()

	script := "#!/bin/sh\n" +
		`printf '%s' "$$" > "$FLEET_HANDOFF_DIR/helper-pid"` + "\n" +
		`printf '%s' "$*" > "$FLEET_HANDOFF_DIR/argv"` + "\n" +
		"exit " + stubHelperStatus + "\n"
	if err := os.WriteFile(filepath.Join(dir, exeName("fleet-tui")), []byte(script), 0o755); err != nil { //nolint:gosec // a stub standing in for an installed binary
		t.Fatalf("install the stub helper into %s: %v", dir, err)
	}
}

// recorded reads one of the files the shell or the helper wrote.
func recorded(t *testing.T, dir, name string) string {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("the hand-off recorded no %s: %v", name, err)
	}
	return strings.TrimSpace(string(raw))
}
