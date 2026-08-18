//go:build integration

package e2e

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aymanbagabas/go-pty"
)

// What a fleetctl command does to the terminal before it does anything else.
//
// This is #73, and it is invisible everywhere else. `fleetctl tui` links
// bubbletea, whose package init asks the terminal for its background colour and
// reads for up to five seconds waiting for the answer — and a package init runs
// in every process that links the package, whatever subcommand was typed. On a
// real emulator the answer arrives in about a millisecond and nothing shows. On
// a terminal that does not answer — a bare pty, a CI log, a serial console —
// every `fleetctl version` cost five seconds and ate whatever was typed
// meanwhile.
//
// So the terminal here answers nothing. That is the whole point of the fixture,
// and it is deliberately not what openShell does: that harness answers the
// query because a terminal is a thing that answers, which is right for driving
// a shell session and would hide this entirely.
//
// Nothing below is timed. A stopwatch assertion would be this suite's other
// recurring failure, and it is not needed: a command that interrogates the
// terminal leaves two marks that are facts rather than durations — the query it
// wrote, and the line that is missing from the input queue afterwards.

// typedWhileStarting is what the operator types while the command is starting.
//
// For `fleetctl shell` this is their first keystrokes. The stall is annoying;
// this half is data loss, which is why it is asserted separately from the query
// rather than being treated as the same finding.
const typedWhileStarting = "TYPED-WHILE-STARTING"

// startupScript is what the shell runs, and every line of it is load-bearing.
//
// The shell rather than the command directly, for two reasons this suite has
// already met: it is the session leader, so macOS does not revoke the pty out
// from under the test the moment the command exits, and it outlives the command
// so that it can read the terminal afterwards. That read is the assertion — a
// line still in the input queue is a line the command did not swallow.
//
// The command keeps the terminal for its stdout. Redirecting it would make
// every case here pass against the very defect they exist to find: termenv only
// queries a stdout that is a terminal, so a scenario that pointed it at
// /dev/null would be asserting nothing at all.
const startupScript = `
printf 'READY\n'
"$FLEET_BIN" $FLEET_ARGS
printf 'DONE\n'
IFS= read -r line
printf 'READBACK[%s]\n' "$line"
`

// silentSession is a fleetctl command running on a terminal that never answers.
type silentSession struct {
	pty  pty.Pty
	cmd  *pty.Cmd
	out  *syncBuffer
	done chan struct{}
}

// startOnASilentTerminal runs `fleetctl args...` on a fresh pseudo-terminal
// whose only writer is this test, and whose only write is the typed line.
func startOnASilentTerminal(t *testing.T, configDir string, args ...string) *silentSession {
	t.Helper()

	term, err := pty.New()
	if err != nil {
		t.Fatalf("allocate a pseudo-terminal: %v", err)
	}
	if err := term.Resize(80, 24); err != nil {
		t.Fatalf("size the pseudo-terminal: %v", err)
	}

	s := &silentSession{pty: term, out: &syncBuffer{}, done: make(chan struct{})}

	cmd := term.Command("/bin/sh", "-c", startupScript)
	cmd.Env = envWith(
		envEntry("FLEET_CONFIG_DIR", configDir),
		envEntry("PATH", os.Getenv("PATH")),
		envEntry("HOME", configDir),
		envEntry("TMPDIR", os.TempDir()),
		// A terminal that claims colour, which is what makes the query
		// worth making: TERM=dumb, screen or tmux is the one case termenv
		// declines to ask at all, and a scenario that ran under one would
		// be green on `main`.
		envEntry("TERM", operatorTerm),
		envEntry("FLEET_BIN", bins.fleetctl),
		envEntry("FLEET_ARGS", strings.Join(args, " ")),
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the command on a pseudo-terminal: %v", err)
	}
	s.cmd = cmd

	// Read, and never write. Started before anything else so that the query,
	// if one is made, is recorded rather than raced with.
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
	go func() {
		defer close(s.done)
		_ = cmd.Wait()
	}()

	t.Cleanup(func() {
		// A command that swallowed the typed line leaves the shell blocked in
		// `read` forever, so this is not tidiness: without it a failing run
		// hangs on the shell rather than reporting what it found.
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		select {
		case <-s.done:
		case <-time.After(10 * time.Second):
		}
		_ = term.Close()
		if t.Failed() {
			t.Logf("terminal received %q", s.received())
		}
	})
	return s
}

// received is every byte the command sent to the terminal, escape sequences
// intact — which is the point, since the assertion is about a sequence.
func (s *silentSession) received() string { return s.out.String() }

// awaitTerminal waits for the terminal to have received want.
func (s *silentSession) awaitTerminal(t *testing.T, what, want string) {
	t.Helper()
	waitFor(t, 60*time.Second, what, func() (bool, string) {
		if strings.Contains(s.received(), want) {
			return true, ""
		}
		return false, "the terminal has received: " + strconv.Quote(s.received())
	})
}

// typed sends bytes to the terminal as if the operator had typed them.
func (s *silentSession) typed(t *testing.T, text string) {
	t.Helper()
	if _, err := s.pty.Write([]byte(text)); err != nil {
		t.Fatalf("type into the terminal: %v", err)
	}
}

// TestNoCommandInterrogatesTheTerminalAtStartup is #73.
//
// Two commands rather than one because the defect was never about a command: a
// package init runs in every process this binary starts, so `version` and
// `list` either both pay for the view's dependency or neither does. One of them
// passing while the other failed would mean something stranger than the bug.
func TestNoCommandInterrogatesTheTerminalAtStartup(t *testing.T) {
	requireSupportedHost(t)

	cases := []struct {
		name string
		args []string
		// printed is something only a run that actually got as far as doing
		// its job prints. Without it every assertion below would hold for a
		// fleetctl that failed to start at all.
		printed string
	}{
		{"version", []string{"version"}, "platform:"},
		{"list", []string{"list"}, "no sandboxes enrolled"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := startOnASilentTerminal(t, t.TempDir(), tc.args...)

			// Typed once the shell is up, so the line lands in the window the
			// command's own startup owns rather than before the shell has
			// even reached it.
			s.awaitTerminal(t, "the shell to reach the command", "READY")
			s.typed(t, typedWhileStarting+"\r")

			s.awaitTerminal(t, "the command to finish", "DONE")

			// It ran, and it did its job. Everything after this is about what
			// it did to the terminal on the way.
			if !strings.Contains(s.received(), tc.printed) {
				t.Fatalf("`fleetctl %s` printed nothing recognisable, so the rest of this scenario would prove nothing about it; the terminal received %q",
					strings.Join(tc.args, " "), s.received())
			}

			// The stall, as a fact rather than a duration: the five seconds
			// were spent waiting for an answer to these, and a command that
			// never asks never waits.
			for what, sequence := range map[string]string{
				"an OSC 11 background-colour query": terminalQuery,
				"a cursor-position request":         cursorQuery,
			} {
				if strings.Contains(s.received(), sequence) {
					t.Errorf("`fleetctl %s` wrote %s to the terminal; on a terminal that does not answer it then waits five seconds for one",
						strings.Join(tc.args, " "), what)
				}
			}

			// And the half that is data loss. The shell reads a line after the
			// command exits; a command that consumed the operator's keystrokes
			// leaves nothing there and this never arrives.
			s.awaitTerminal(t, "the line typed during startup to still be in the terminal's input queue",
				"READBACK["+typedWhileStarting+"]")
		})
	}
}
