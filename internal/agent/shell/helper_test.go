package shell

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// The sessions these tests open have to run something, and that something has
// to exist on Linux, macOS and Windows. Rather than reaching for `sh` — absent
// on one of the three — the test binary re-executes itself in a helper mode
// selected by an environment variable, the same arrangement internal/agent/exec
// uses and for the same reason.
//
// It buys more here than it does there. A session is a terminal, and the
// interesting behaviour is what a program attached to one sees: the window size
// it was given, a resize arriving while it runs, a child it spawned being
// killed with it. A helper this repository controls can report all three; `sh`
// can report none of them the same way twice across platforms.
const helperEnv = "FLEET_SHELL_TEST_HELPER"

func TestMain(m *testing.M) {
	if mode := os.Getenv(helperEnv); mode != "" {
		os.Exit(helperMain(mode, os.Args[1:]))
	}
	os.Exit(m.Run())
}

// selfArgv is an argv that re-runs the test binary. Which helper mode it enters
// is decided by helperEnvFor in the session's environment.
func selfArgv(args ...string) []string {
	self, err := os.Executable()
	if err != nil {
		panic("shell test: cannot find the test binary: " + err.Error())
	}
	return append([]string{self}, args...)
}

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

	case "cat":
		// Echoes each line back with a marker, so a test can tell the program's
		// output apart from the terminal's echo of what was typed. Ends on a
		// line reading "quit", because a pty read has no EOF to wait for.
		return helperCat()

	case "winsize":
		// Reports the terminal size it was given, and again whenever it
		// changes. This is what makes a resize assertable end to end: the size
		// is read by the program inside the session, through the same platform
		// call `fleetctl shell` reads the local one with.
		return helperWinsize()

	case "tree":
		// Spawns a child in the same process group and prints both pids, then
		// both sleep until something kills them.
		return helperTree(args)

	case "sleep":
		return blockUntilKilled()

	case "announce":
		// Says it is running, then waits to be killed. It exists so a test can
		// know that *this* program is the terminal's foreground process before
		// it sends an interrupt: a Ctrl-C that arrives while the shell is still
		// parsing the line interrupts nothing, and a test that sent one anyway
		// would pass without proving anything.
		fmt.Println("foreground-running")
		return blockUntilKilled()

	case "ignore-hup":
		// Ignores the hangup a closing terminal sends, so a test can prove the
		// kill that follows it is what ends the session rather than the polite
		// half.
		signal.Ignore(hangupSignals()...)
		return blockUntilKilled()
	}
	fmt.Fprintf(os.Stderr, "unknown helper mode %q\n", mode)
	return 2
}

// blockUntilKilled waits for something to end this process.
//
// A pending timer rather than `select {}`, and the difference is not
// stylistic: the runtime aborts a program in which every goroutine is asleep,
// so a helper that parked on a bare select would die of the deadlock detector a
// microsecond after starting — and a test asserting that a session was reaped
// would pass against a process that reaped itself. A timer keeps the runtime
// satisfied that something is still due to happen.
func blockUntilKilled() int {
	<-time.After(10 * time.Minute)
	return 0
}

func arg(args []string, fallback string) string {
	if len(args) == 0 {
		return fallback
	}
	return args[0]
}

// helperCat reads from the terminal a byte at a time.
//
// A byte at a time rather than bufio, because a terminal in canonical mode
// delivers a line as soon as the newline arrives and a buffered reader would
// hold the last partial line — which is the state this helper spends most of
// its life in.
func helperCat() int {
	var line strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			switch buf[0] {
			case '\n', '\r':
				text := strings.TrimSpace(line.String())
				line.Reset()
				if text == "quit" {
					return 0
				}
				fmt.Printf("read[%s]\n", text)
			default:
				line.WriteByte(buf[0])
			}
		}
		if err != nil {
			return 0
		}
	}
}

// helperWinsize prints its terminal's size whenever it changes, including once
// at startup.
func helperWinsize() int {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	platform.WatchWindowSize(ctx, os.Stdin.Fd(), func(columns, rows int) {
		fmt.Printf("size %dx%d\n", columns, rows)
	})
	return 0
}

// helperTree spawns one child and prints both pids, then waits to be killed.
func helperTree(args []string) int {
	fmt.Printf("pid %d\n", os.Getpid())

	if len(args) > 0 && args[0] == "child" {
		return blockUntilKilled()
	}

	self, err := os.Executable()
	if err != nil {
		return 1
	}
	child := exec.Command(self, "child") //nolint:gosec // the test binary re-running itself
	child.Env = append(os.Environ(), helperEnvFor("tree"))
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		return 1
	}
	return blockUntilKilled()
}

// waitTimeout is how long any of these tests waits for something to become
// true. It is generous on purpose: every wait here crosses a pseudo-terminal,
// two goroutines and a gRPC stream, and the tests assert on what eventually
// happened rather than on when.
const waitTimeout = 30 * time.Second

// waitFor polls until cond reports true, failing with the last detail it saw.
//
// Every wait in this package's tests goes through here: a session crosses a
// pseudo-terminal, two goroutines and a gRPC stream, and an assertion that
// depended on how long any of that took would be a test nobody trusts.
func waitFor(t *testing.T, what string, cond func() (bool, string)) {
	t.Helper()

	deadline := time.Now().Add(waitTimeout)
	var detail string
	for {
		ok, d := cond()
		if ok {
			return
		}
		detail = d
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s: %s", waitTimeout, what, detail)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// syncBuffer collects a session's output from the goroutine reading the stream
// while a test reads it from its own.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
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
