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
	awaitScreen(t, s.screen, what, fragments...)
}

// awaitScreen waits until everything a terminal has been sent contains every
// fragment. Shared by the two harnesses in this file.
func awaitScreen(t *testing.T, screen func() string, what string, fragments ...string) {
	t.Helper()
	waitFor(t, 60*time.Second, what, func() (bool, string) {
		drawn := screen()
		for _, fragment := range fragments {
			if !strings.Contains(drawn, fragment) {
				return false, fmt.Sprintf("%q has not appeared; the terminal holds:\n%s", fragment, drawn)
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
//
// The flags arrive as the shell's own positional parameters and are passed on
// with "$@" rather than through an unquoted variable, so that this scenario can
// type a value with a space in it and an empty one. A command line split on
// whitespace by the harness could not tell a forwarded argument from a
// re-serialised one, which is the whole subject below.
const handOffScript = `
"$FLEET_CTL" tui "$@" &
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
//
// The awkward ones are here deliberately, because "forwarded unchanged" is a
// claim about the argv as a list and every cheap way of getting it wrong keeps
// the words and loses the structure. A value with a space in it separates a
// forwarded argument from a command line joined and re-split. An empty value is
// the argument a re-serialiser drops without leaving a gap. A repeated flag is
// the one a rebuild from parsed values collapses to the winner, which is
// invisible unless both crossings are recorded.
//
// The last three are about what could quietly re-encode on the way rather than
// about what could be dropped. A value that contains the brackets and the
// newline the helper records with is the one case where the rendering alone is
// ambiguous — `[]\n[]` is one argument holding "]\n[" and it is equally two
// arguments holding "" and "" — so the count is recorded beside it and the
// ambiguity is closed rather than stepped around. A value that begins with two
// dashes is the one a re-serialiser turns into a flag of its own. And a byte
// that is not valid UTF-8 sits in the registry path because an argv is bytes: a
// hand-off that ever put the command line through a text encoding — quoting it,
// JSON, anything that replaces what it cannot represent — would keep every word
// and change that one byte, which is a path to a file that no longer exists.
var handOffArgs = []string{
	"--refresh", "3s", "--refresh", "7s",
	"--timeout", "11s",
	"--registry", "/nowhere/fleet registry\xff.yaml",
	"--cert", "]\n[",
	"--key", "--not-a-flag",
	"--ca-dir", "",
}

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
	helper := installStubHelper(t, install)

	// $0 then the operator's flags, which is what makes them "$@" inside the
	// script rather than a string it has to split.
	runOnATerminal(t, handOffScript, handOffArgs, envWith(
		envEntry("FLEET_CTL", filepath.Join(install, exeName("fleetctl"))),
		envEntry("FLEET_HANDOFF_DIR", record),
		envEntry("FLEET_CONFIG_DIR", record),
		envEntry("PATH", os.Getenv("PATH")),
		envEntry("HOME", record),
		envEntry("TMPDIR", os.TempDir()),
		envEntry("TERM", operatorTerm),
	))

	// On the status file having *content*, not on it existing: `echo $? >`
	// creates it and then writes it, and a read between the two would compare
	// against an empty string and call the mismatch a failure of the product.
	waitFor(t, 30*time.Second, "the hand-off to complete", func() (bool, string) {
		raw, err := os.ReadFile(filepath.Join(record, "status"))
		return err == nil && len(bytes.TrimSpace(raw)) > 0,
			"the shell has not finished waiting on `fleetctl tui`"
	})

	// Argument by argument, with each one bracketed, because the claim is about
	// the argv as a list. Comparing the arguments joined by spaces — which is
	// what this scenario did first — cannot tell the forwarded list from the
	// same words handed over as one long argument: `printf '%s' "$*"` renders
	// both identically, and flattening the command line that way passed here
	// while the view came up unable to parse its own flags. Bracketed so that an
	// empty argument and a trailing space are visible in the failure too.
	// How many, before what: the rendering below is ambiguous for exactly one
	// shape — an argument holding "]\n[" reads as two holding "]" and "[" —
	// and this scenario types that shape on purpose. One number closes it.
	if got, want := recorded(t, record, "argc"), strconv.Itoa(len(handOffArgs)+1); got != want {
		t.Errorf("the helper was handed %s arguments; `fleetctl tui` was typed with %s", got, want)
	}

	want := bracketed(append([]string{"tui"}, handOffArgs...))
	if got := recorded(t, record, "argv"); got != want {
		t.Errorf("the helper was handed\n%s\nbut the operator typed `fleetctl tui` with\n%s\n"+
			"the command line is forwarded unchanged so that there is one implementation of every flag "+
			"— including the credential paths — rather than a second one on the far side (#44)",
			got, want)
	}

	// And argv[0] is the file the lookup resolved, not the helper's bare name.
	// This is the identity the far side of a hand-off has on a host where
	// os.Executable cannot answer — a chroot, a container image without /proc —
	// and it is the only thing that stops a fleetctl installed under the
	// helper's name from exec'ing itself for ever there. Invisible from any host
	// with a /proc, which is every host this suite runs on: os.Executable
	// answers there before argv[0] is ever consulted, so handing over the bare
	// name left the whole repository green.
	if got := recorded(t, record, "argv0"); got != helper {
		t.Errorf("the helper was handed argv[0] %q; the hand-off resolved it to %q.\n"+
			"On a host that cannot say what binary is running, argv[0] is the only thing the far side "+
			"can name itself from — and a helper that cannot name itself execs itself again", got, helper)
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
func installFleetctl(t *testing.T, dir string) {
	t.Helper()
	installFleetctlAs(t, dir, "fleetctl")
}

// installFleetctlAs is installFleetctl under a name of the caller's choosing,
// which is how a scenario arranges the install that names fleetctl after its
// own helper.
//
// Linked rather than copied where the filesystem allows it: this is a 20 MiB
// binary and the link is the same file by another name, which is all the lookup
// looks at.
func installFleetctlAs(t *testing.T, dir, name string) string {
	t.Helper()

	path := filepath.Join(dir, exeName(name))
	if err := os.Link(bins.fleetctl, path); err == nil {
		return path
	}
	return copyFleetctlAs(t, dir, name)
}

// copyFleetctlAs is installFleetctlAs with the link ruled out — a second file,
// with its own inode, holding the same bytes.
//
// The distinction is the whole of the scenario below. A link is one file under
// two names and os.SameFile says so; a copy is two files, and no amount of
// looking at them tells fleetctl that the one it is about to exec is itself.
func copyFleetctlAs(t *testing.T, dir, name string) string {
	t.Helper()

	path := filepath.Join(dir, exeName(name))
	source, err := os.ReadFile(bins.fleetctl)
	if err != nil {
		t.Fatalf("read fleetctl: %v", err)
	}
	if err := os.WriteFile(path, source, 0o755); err != nil { //nolint:gosec // a copy of a binary this test just built
		t.Fatalf("install fleetctl into %s as %s: %v", dir, name, err)
	}
	return path
}

// installStubHelper puts a fleet-tui into dir that reports what it was handed.
//
// It is a copy of the suite's own helpers binary, whose `tui` mode records the
// far side's argv, argument count, pid and argv[0] and exits with a known
// status. `tui` is the subcommand `fleetctl tui` forwards, so nothing has to be
// arranged for it to be the mode that runs.
//
// A compiled program rather than the `#!/bin/sh` script this was, and that is
// the whole reason it changed: a script cannot observe argv[0]. The kernel
// drops the caller's argv[0] when it runs one and substitutes the script's own
// path, so a scenario written with a script could not see what the hand-off put
// there — which is the identity the far side falls back on when the host cannot
// say what is running, and the only thing standing between a mis-installed
// fleetctl and an exec loop on such a host.
func installStubHelper(t *testing.T, dir string) string {
	t.Helper()

	path := filepath.Join(dir, exeName("fleet-tui"))
	if err := os.Link(bins.helpers, path); err == nil {
		return path
	}
	source, err := os.ReadFile(bins.helpers)
	if err != nil {
		t.Fatalf("read the helpers binary: %v", err)
	}
	if err := os.WriteFile(path, source, 0o755); err != nil { //nolint:gosec // a stand-in for an installed binary
		t.Fatalf("install the stub helper into %s: %v", dir, err)
	}
	return path
}

// bracketed renders an argv the way the stub helper records one: one argument
// per line, wrapped so that an empty argument is a line and a value with a
// space in it is one line rather than two.
func bracketed(args []string) string {
	var b strings.Builder
	for _, a := range args {
		b.WriteString("[" + a + "]\n")
	}
	return strings.TrimSpace(b.String())
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

// terminalRun is a shell script running on a pseudo-terminal nobody types at.
//
// A shell rather than the command itself, for the reason the harness above
// gives: it is the session leader, so macOS does not revoke the pty out from
// under the test the moment the command exits, and it outlives the command it
// ran, so it can record what happened afterwards. Everything written to the
// terminal is kept, which is both what an assertion reads and what a failure
// prints.
type terminalRun struct {
	out *syncBuffer
}

// runOnATerminal starts script on a fresh 80x24 pseudo-terminal, with args as
// its positional parameters and env as the whole environment.
func runOnATerminal(t *testing.T, script string, args, env []string) *terminalRun {
	t.Helper()

	term, err := pty.New()
	if err != nil {
		t.Fatalf("allocate a pseudo-terminal: %v", err)
	}
	if err := term.Resize(80, 24); err != nil {
		t.Fatalf("size the pseudo-terminal: %v", err)
	}

	// $0 then the script's own positional parameters, so a value with a space
	// in it survives the shell.
	cmd := term.Command("/bin/sh", append([]string{"-c", script, "sh"}, args...)...)
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the shell on a pseudo-terminal: %v", err)
	}

	r := &terminalRun{out: &syncBuffer{}}
	// Read continuously rather than at the end: a terminal nobody reads fills
	// up and stops the program writing to it.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := term.Read(buf)
			if n > 0 {
				_, _ = r.out.Write(buf[:n])
			}
			if err != nil {
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
		_ = term.Close()
		if t.Failed() {
			t.Logf("terminal:\n%s", r.screen())
		}
	})
	return r
}

// screen is everything the terminal has been sent, with the escape sequences
// stripped.
func (r *terminalRun) screen() string { return stripEscapes(r.out.String()) }

func (r *terminalRun) awaitScreen(t *testing.T, what string, fragments ...string) {
	t.Helper()
	awaitScreen(t, r.screen, what, fragments...)
}

// ------------------------------------------ the install without the helper

// missingHelperScript is a workstation where only fleetctl was installed,
// driven the way an operator would meet it: the command that needs the helper,
// then a command that does not, then the same command with its output
// redirected.
//
// Statuses are printed rather than inferred from the output, because "it said
// something about a missing binary" and "it failed" are two different claims
// and this scenario makes both.
const missingHelperScript = `
"$FLEET_CTL" tui
printf 'TUI-STATUS[%s]\n' "$?"
"$FLEET_CTL" list
printf 'LIST-STATUS[%s]\n' "$?"
"$FLEET_CTL" tui > "$FLEET_MISSING_DIR/piped" 2>&1
printf 'PIPED-STATUS[%s]\n' "$?"
printf 'DONE\n'
`

// TestWithoutTheHelperTuiSaysWhatToInstallAndTheRestIsUnaffected is the cost
// this PR accepted, driven from the command an operator types.
//
// `go install .../cmd/fleetctl@latest` on its own now yields a `fleetctl tui`
// that cannot draw, and the whole of what makes that acceptable is the sentence
// it prints instead. Everything about that sentence was asserted by calling
// findHelper directly, and nothing connected it to the command: replacing the
// hand-off's error with a silent `return nil` — an operator typing `fleetctl
// tui` and getting their prompt back, no view and no reason — left this
// repository green, unit and end-to-end.
//
// So: a real fleetctl, alone in a directory, on a real terminal, with a PATH
// that has no helper on it either. The refusal has to name the binary, say
// where it looked, give the line that installs it, and say that the rest of the
// CLI is unaffected — and then `fleetctl list` has to actually work, because a
// scenario that only read the sentence would pass for a fleetctl that was
// broken in the way the sentence promises it is not.
func TestWithoutTheHelperTuiSaysWhatToInstallAndTheRestIsUnaffected(t *testing.T) {
	requireSupportedHost(t)

	record := t.TempDir()
	// fleetctl and nothing else — no helper beside it, and the same directory
	// as PATH, so the two places the lookup knows about are both this one.
	install := t.TempDir()
	installFleetctl(t, install)

	run := runOnATerminal(t, missingHelperScript, nil, envWith(
		envEntry("FLEET_CTL", filepath.Join(install, exeName("fleetctl"))),
		envEntry("FLEET_MISSING_DIR", record),
		envEntry("FLEET_CONFIG_DIR", record),
		envEntry("PATH", install),
		envEntry("HOME", record),
		envEntry("TMPDIR", os.TempDir()),
		envEntry("TERM", operatorTerm),
	))
	run.awaitScreen(t, "the workstation to finish all three commands", "DONE")

	screen := run.screen()
	for _, want := range []string{
		"fleet-tui",
		"not next to fleetctl or on PATH",
		"go install github.com/axelmierczuk/fleet-mcp/cmd/fleet-tui@latest",
		"`fleetctl list` and `fleetctl info` need nothing extra",
		"TUI-STATUS[1]",
	} {
		if !strings.Contains(screen, want) {
			t.Errorf("`fleetctl tui` without its helper does not say %q; the terminal holds:\n%s", want, screen)
		}
	}

	// The other half of what the refusal claims, checked rather than repeated.
	for _, want := range []string{"no sandboxes enrolled", "LIST-STATUS[0]"} {
		if !strings.Contains(screen, want) {
			t.Errorf("`fleetctl list` did not work on an install with no helper, which is what the refusal says is unaffected: %q is missing from:\n%s",
				want, screen)
		}
	}

	// And which refusal comes first when both apply. Redirected output is not a
	// terminal, and that is the operator's own command being wrong rather than
	// their install being incomplete — so it is what they are told about, and
	// they are told it whether or not the helper is installed.
	piped := recorded(t, record, "piped")
	if !strings.Contains(piped, "needs a terminal") || !strings.Contains(piped, "fleetctl list --json") {
		t.Errorf("`fleetctl tui` with its output redirected, on an install with no helper, said:\n%s\n"+
			"the terminal is what is wrong with that command, and the answer to it does not depend on the helper", piped)
	}
	if !strings.Contains(screen, "PIPED-STATUS[1]") {
		t.Errorf("`fleetctl tui` with its output redirected did not fail; the terminal holds:\n%s", screen)
	}
}

// selfHelperScript runs a fleetctl that was installed under its helper's name,
// and prints something afterwards.
//
// The something afterwards is the assertion: the defect this covers is a
// process that never gets there.
const selfHelperScript = `
"$FLEET_CTL" tui
printf 'STATUS[%s]\n' "$?"
printf 'DONE\n'
`

// TestAFleetctlInstalledAsItsOwnHelperRefusesInsteadOfLooping.
//
// The hand-off is an exec, and an exec into oneself is invisible: a fleetctl
// installed as fleet-tui — `cp`, `mv` or `ln -s` by a packager who read
// "fleet-tui is fleetctl's own command tree" as "the same binary" — finds
// itself beside itself and execs itself, for ever. Same pid, no child, no exit,
// nothing written: `fleetctl tui` simply never comes back, which is the failure
// this command was split out of `fleetctl` to stop. Measured before the guard
// existed, this scenario's shell was still waiting when the test gave up.
//
// End-to-end rather than only at [findHelperVia], because what is wrong with
// the old behaviour is not the value that function returns — it is that the
// process never terminates, and only a real run can say that it does. PATH is
// the install directory, so the lookup meets the same binary in both of the
// places it knows about.
func TestAFleetctlInstalledAsItsOwnHelperRefusesInsteadOfLooping(t *testing.T) {
	requireSupportedHost(t)

	record := t.TempDir()
	install := t.TempDir()
	selfNamed := installFleetctlAs(t, install, "fleet-tui")

	run := runOnATerminal(t, selfHelperScript, nil, envWith(
		envEntry("FLEET_CTL", selfNamed),
		envEntry("FLEET_CONFIG_DIR", record),
		envEntry("PATH", install),
		envEntry("HOME", record),
		envEntry("TMPDIR", os.TempDir()),
		envEntry("TERM", operatorTerm),
	))
	run.awaitScreen(t, "the command to come back at all, rather than exec into itself for ever", "DONE")

	screen := run.screen()
	for _, want := range []string{"this same binary", "go install github.com/axelmierczuk/fleet-mcp/cmd/fleet-tui@latest", "STATUS[1]"} {
		if !strings.Contains(screen, want) {
			t.Errorf("a fleetctl installed as its own helper does not say %q; the terminal holds:\n%s", want, screen)
		}
	}
}

// TestAFleetctlCopiedToItsHelpersNameRefusesInsteadOfLooping is the same
// mistake spelled the way the refusal itself puts first, and the only one no
// amount of looking can answer in a single process.
//
// `cp fleetctl fleet-tui` leaves two files. They are not the same path and they
// are not the same inode, so a fleetctl standing beside that copy has nothing
// to see: it hands over, correctly as far as it can tell. What stops the loop
// is one step later — [execHelper] passes the resolved path as argv[0], so the
// copy's own view of what is running names the very file it is about to choose
// again, and the second attempt refuses. One hand-off, then the sentence.
//
// Which is why this is driven and not reasoned about. The mechanism is a
// property of two processes and lives in neither: the unit tests of findHelper
// cannot see it, and every existing scenario arranges a link or a rename, which
// is caught in the first process and would stay green with the second-hop
// answer gone. What that regression looks like is not a wrong value — it is
// `fleetctl tui` never coming back, so the assertion is that it does.
func TestAFleetctlCopiedToItsHelpersNameRefusesInsteadOfLooping(t *testing.T) {
	requireSupportedHost(t)

	record := t.TempDir()
	install := t.TempDir()
	installFleetctl(t, install)
	copyFleetctlAs(t, install, "fleet-tui")

	run := runOnATerminal(t, selfHelperScript, nil, envWith(
		envEntry("FLEET_CTL", filepath.Join(install, exeName("fleetctl"))),
		envEntry("FLEET_CONFIG_DIR", record),
		envEntry("PATH", install),
		envEntry("HOME", record),
		envEntry("TMPDIR", os.TempDir()),
		envEntry("TERM", operatorTerm),
	))
	run.awaitScreen(t, "the command to come back at all, rather than exec a copy of itself for ever", "DONE")

	screen := run.screen()
	for _, want := range []string{"this same binary", "go install github.com/axelmierczuk/fleet-mcp/cmd/fleet-tui@latest", "STATUS[1]"} {
		if !strings.Contains(screen, want) {
			t.Errorf("a fleetctl copied to its helper's name does not say %q; the terminal holds:\n%s", want, screen)
		}
	}
}
