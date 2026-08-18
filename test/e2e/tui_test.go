//go:build integration

package e2e

import (
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
// scenario: two enrolled sandboxes, one of them dead, a supervised process on
// the live one, and an operator who quits.
//
// The unreachable sandbox is the point of the fleet half. A view that probed
// sandboxes one after another, or that failed the listing when one did not
// answer, would show nothing at all here — and that is the failure mode a
// twenty-machine fleet makes certain, because a fleet that size always has one
// machine that is asleep.
func TestTUIDrawsTheFleetAndGivesTheTerminalBack(t *testing.T) {
	f := newFleet(t)
	live := f.enroll("build-box", enrollOptions{})
	dead := f.enroll("gone-box", enrollOptions{})

	s := f.connect(t)
	s.ok("fleet_select", map[string]any{"name": live.name})
	started := startProcess(t, s, map[string]any{
		"name": "chatty",
		"argv": []string{bins.helpers, "spew", "50", "tick"},
	})
	defer stopProcess(t, s, started)

	// And now one of them goes away, with the TUI already about to look at it.
	dead.proc.kill()

	tui := startTUI(t, f)

	tui.waitForScreen(t, "the fleet pane to list both sandboxes", live.name, dead.name)
	tui.waitForScreen(t, "the dead sandbox to be reported unreachable", "unreachable")
	tui.waitForScreen(t, "the live sandbox to be reported serving", "serving")

	// The processes pane is reading the same agent the MCP server just started
	// a process on, through the same client. Its output is what proves the pane
	// is a view of the product rather than of a fixture.
	tui.waitForScreen(t, "the processes pane to show the supervised process", started.Process.Name)
	tui.waitForScreen(t, "the logs pane to follow the process's output", "tick ")

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
const tuiScript = `
stty -g > "$FLEET_TUI_DIR/before"
"$FLEET_TUI_BIN" tui &
echo $! > "$FLEET_TUI_DIR/pid"
wait $!
echo $? > "$FLEET_TUI_DIR/status"
stty -g > "$FLEET_TUI_DIR/after"
`

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
