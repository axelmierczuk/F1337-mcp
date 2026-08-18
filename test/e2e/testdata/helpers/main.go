// Command helpers is the workload the end-to-end suite runs on a sandbox.
//
// The scenarios need a dev server that binds a port, a process that keeps
// producing output, and a process tree deep enough that killing only its leader
// leaves survivors. Reaching for python3, node or a shell built-in to get those
// would make the suite depend on what happens to be installed on the machine —
// and on a container image agreeing with a laptop about it. One small Go
// program, built by the suite from source it owns, behaves identically
// everywhere the agent runs.
//
// It lives under testdata so that `go build ./...` and `go test ./...` do not
// pick it up. That exclusion is the go tool's, not a choice, and it applied to
// the checkers too until the Makefile started naming this package: vet and
// golangci-lint both reach it now, under every GOOS, which is the only reason
// the file below can be held to the same standard as the rest of the tree.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: helpers <serve|serve-when|spew|orphan|linger|tree|sleep|winsize|tui> ...")
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "serve-when":
		serveWhen(os.Args[2:])
	case "spew":
		spew(os.Args[2:])
	case "orphan":
		orphan()
	case "linger":
		linger(os.Args[2:])
	case "tree":
		tree(os.Args[2:])
	case "sleep":
		sleepForever()
	case "winsize":
		winsize()
	case "tui":
		handedOver()
	default:
		fail("unknown command " + os.Args[1])
	}
}

// linger runs for a while, leaves a child holding this process's stdout in a
// session of its own, and exits.
//
// It is the one shape in which a command's process group is released while the
// call that started it is still running, which is the state #105 is about. The
// child is out of the group, so the post-exec sweep cannot reach it; it holds
// the command's stdout, so os/exec's Wait stays parked on the output copiers
// for the whole of Cmd.WaitDelay after the leader has exited and been
// collected. Everything the agent decides in that window — a timeout, a caller
// hanging up — is decided about a process group id the kernel has taken back.
//
// The pids go in a file rather than on stdout, because the caller of an exec
// RPC does not see stdout until the call ends and a scenario has to know them
// while it is still running.
//
// Unix only in effect: detach is what puts the child outside the group, and on
// Windows there is no group to be outside of.
func linger(args []string) {
	if len(args) < 2 {
		fail("usage: helpers linger <seconds-before-exit> <pidfile>")
	}
	before, err := strconv.Atoi(args[0])
	if err != nil {
		fail("linger: " + err.Error())
	}
	time.Sleep(time.Duration(before) * time.Second)

	// #nosec G204 -- this is a self-exec: the binary is os.Args[0] and there is
	// no interpolated value at all.
	child := exec.Command(os.Args[0], "sleep")
	child.Stdout = os.Stdout
	detach(child)
	if err := child.Start(); err != nil {
		fail("spawn child: " + err.Error())
	}

	pids := fmt.Sprintf("%d\n%d\n", os.Getpid(), child.Process.Pid)
	if err := os.WriteFile(args[1], []byte(pids), 0o600); err != nil {
		fail("write pidfile: " + err.Error())
	}
	fmt.Printf("pid %d pgid %d\n", os.Getpid(), processGroup())
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "helpers:", msg)
	os.Exit(2)
}

// handedOverStatus is what the stand-in helper exits with: an unremarkable
// number nothing else in the suite produces, so reading it back means it came
// from here rather than from something failing on the way. Kept in step with
// test/e2e's stubHelperStatus.
const handedOverStatus = 17

// handOffMarker is the environment variable `fleetctl tui` sets on the helper
// it hands the terminal to, spelled out because it is unexported where it is
// defined (internal/cli/fleetctl/handoff.go).
//
// It is the whole of what stops a second hand-off, and the far side is the only
// place it can be observed. Two spellings that drift apart read back as an
// empty value, which is what the scenario asserts against.
const handOffMarker = "FLEET_TUI_HANDED_OFF"

// handedOver stands in for fleet-tui, and records everything about a hand-off
// that only the far side can see.
//
// It answers to "tui" because that is the subcommand `fleetctl tui` forwards,
// so a copy of this binary installed under the helper's name is reached by the
// command an operator types, with nothing arranged around it.
//
// A compiled program rather than the shell script this used to be, for one
// reason: a `#!/bin/sh` file cannot observe argv[0]. The kernel drops the
// caller's argv[0] when it runs a script and puts the script's own path there
// instead, so the one thing the hand-off's self-guard rests on — that argv[0]
// names the resolved helper, which on a host without /proc is the only identity
// the far side has — was invisible to a scenario written with a script. It
// stayed invisible while the whole suite was green.
func handedOver() {
	dir := os.Getenv("FLEET_HANDOFF_DIR")
	if dir == "" {
		fail("tui: FLEET_HANDOFF_DIR is not set, so there is nowhere to record the hand-off")
	}

	// One bracketed argument per line, never joined: an argv taken apart and
	// put back together as a single argument, or one that lost an empty value,
	// reads back exactly like the list that was forwarded. The count is
	// recorded beside it because the bracketing is not quite injective — one
	// argument holding "]\n[" renders as two holding "]" and "[".
	var argv strings.Builder
	for _, a := range os.Args[1:] {
		fmt.Fprintf(&argv, "[%s]\n", a)
	}
	for name, content := range map[string]string{
		"argv0":      os.Args[0],
		"argc":       strconv.Itoa(len(os.Args) - 1),
		"argv":       strings.TrimSpace(argv.String()),
		"helper-pid": strconv.Itoa(os.Getpid()),
		// The marker that says a hand-off has happened, which only the far
		// side can see. A fleetctl reading it refuses to hand over again, so
		// this is the one recorded value that is a guard rather than a
		// promise about the command line.
		"handed-to": os.Getenv(handOffMarker),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			fail("tui: record " + name + ": " + err.Error())
		}
	}
	os.Exit(handedOverStatus)
}

// serve runs an HTTP server on a loopback port, and announces itself on stdout
// only once the listener is actually accepting.
//
// The announcement order matters: a readiness probe that watched for a log line
// printed before the bind would pass while the port was still closed, which is
// exactly the failure a probe exists to prevent.
//
// With a third argument, the announcement is made once per file rather than
// once per run: the first run creates the file and announces itself, and every
// later run serves silently. A supervised process keeps its argv across a
// restart, so this is the only way to give the second run of the *same* process
// different output — which is what it takes to ask whether a log-pattern
// readiness probe is watching this run's output or the last one's.
func serve(args []string) {
	if len(args) < 2 {
		fail("usage: helpers serve <port> <body> [announce-once-file]")
	}
	port, err := strconv.Atoi(args[0])
	if err != nil {
		fail("port: " + err.Error())
	}
	body := args[1]

	announce := true
	if len(args) > 2 {
		if _, err := os.Stat(args[2]); err == nil {
			announce = false
		} else if err := os.WriteFile(args[2], []byte("announced\n"), 0o600); err != nil {
			fail("mark: " + err.Error())
		}
	}

	lis, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		fail("listen: " + err.Error())
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		// A client that hung up mid-body is the caller's problem, not this
		// helper's: the scenarios read the response to completion or fail on
		// what they got, and there is nowhere useful for a handler to report
		// a half-written 200 to anyway.
		_, _ = fmt.Fprint(w, body)
	})
	if !announce {
		fmt.Printf("serving %d without announcing it\n", port)
		srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		if err := srv.Serve(lis); err != nil {
			fail("serve: " + err.Error())
		}
		return
	}
	fmt.Printf("listening on %d\n", port)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.Serve(lis); err != nil {
		fail("serve: " + err.Error())
	}
}

// serveWhen binds its port immediately and announces itself only once a file
// appears, then serves forever.
//
// It hands a scenario the moment of the announcement. A readiness probe that
// has to give up before the process has said anything cannot be arranged with a
// delay — a loaded machine turns "announces later than the probe waits" into a
// coin toss — but it can be arranged with a handshake: nothing is printed until
// the test writes the file, so the probe's verdict is decided before the
// announcement is possible. That is what it takes to leave a record in the
// state a re-adoption then has to resolve: still being probed, with the
// evidence already in the log.
func serveWhen(args []string) {
	if len(args) < 3 {
		fail("usage: helpers serve-when <port> <body> <announce-when-file>")
	}
	port, err := strconv.Atoi(args[0])
	if err != nil {
		fail("port: " + err.Error())
	}
	body := args[1]

	lis, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		fail("listen: " + err.Error())
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		// A client that hung up mid-body is the caller's problem, not this
		// helper's: the scenarios read the response to completion or fail on
		// what they got, and there is nowhere useful for a handler to report
		// a half-written 200 to anyway.
		_, _ = fmt.Fprint(w, body)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		for {
			if _, err := os.Stat(args[2]); err == nil {
				fmt.Printf("listening on %d\n", port)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	if err := srv.Serve(lis); err != nil {
		fail("serve: " + err.Error())
	}
}

// spew prints a numbered line at a fixed interval, forever, so a log follow
// has something to follow and a re-adopted process has output that continues
// across the agent restart.
func spew(args []string) {
	interval := 100 * time.Millisecond
	if len(args) > 0 {
		ms, err := strconv.Atoi(args[0])
		if err != nil {
			fail("interval: " + err.Error())
		}
		interval = time.Duration(ms) * time.Millisecond
	}
	prefix := "line"
	if len(args) > 1 {
		prefix = args[1]
	}
	for n := 1; ; n++ {
		fmt.Printf("%s %d\n", prefix, n)
		time.Sleep(interval)
	}
}

// treeLifetime bounds how long a level of the tree lasts if nothing kills it.
//
// The tree exists to be killed, and no scenario ever asserts that it is still
// there — only that it is gone, within deadlines of thirty seconds or less. A
// bound three orders of magnitude beyond those therefore cannot make any
// assertion pass for the wrong reason.
//
// What it bounds is the mess a failing run leaves behind. The scenario kills the
// pids it parsed out of the command's output when it fails, but a run that never
// gets that output — an exec that timed out at the call level, an agent that
// died mid-call, a result that would not decode — has nothing to kill, and
// without this each such run would strand three processes that sleep forever.
const treeLifetime = 5 * time.Minute

// tree announces its pid and process group, spawns a child one level
// shallower, and then waits to be killed.
//
// Each level prints "pid N pgid M" on the shared stdout, so the caller ends up
// holding the identity of every process in the tree. The group id is there so
// the caller can tell whether the command really leads a group of its own:
// "nothing is left in the group" is a claim about an empty set either way, and
// only true membership makes it a claim about this tree. Within any window a
// scenario observes, the only way this tree ends is for something to kill it,
// which is the question the timeout scenario asks; see treeLifetime for the
// long stop that keeps a failed run from stranding it forever.
func tree(args []string) {
	depth := 2
	if len(args) > 0 {
		d, err := strconv.Atoi(args[0])
		if err != nil {
			fail("depth: " + err.Error())
		}
		depth = d
	}

	fmt.Printf("pid %d pgid %d\n", os.Getpid(), processGroup())
	if depth > 0 {
		// #nosec G204 -- this is a self-exec: the binary is os.Args[0] and the
		// only interpolated value is a depth counter formatted from an int.
		child := exec.Command(os.Args[0], "tree", strconv.Itoa(depth-1))
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			fail("spawn child: " + err.Error())
		}
	}
	time.Sleep(treeLifetime)
}

// orphan starts a child that outlives it, announces both identities, and exits
// at once.
//
// This is the shape the post-exec sweep exists for and the only one nothing on
// the kill path ever reaches: the command succeeded, so no timeout and no
// hangup signalled anything, and by the time the agent is done waiting the
// process that would have carried its child down with it is already gone.
// `sh -c 'daemon &'` is the same thing spelled with a shell.
//
// The child inherits no pipes. A child holding the command's stdout is a
// different scenario — it is what Cmd.WaitDelay bounds — and mixing the two
// would leave a failure of either looking like a failure of the other.
//
// Both identities are printed in the same form tree uses, so a scenario reads
// them back with parseTree: this process first, because it is the group leader
// and the assertions turn on that.
func orphan() {
	// #nosec G204 -- this is a self-exec: the binary is os.Args[0] and there is
	// no interpolated value at all.
	child := exec.Command(os.Args[0], "sleep")
	child.Stdout = nil
	child.Stderr = nil
	if err := child.Start(); err != nil {
		fail("spawn child: " + err.Error())
	}

	// The child inherited this process's group, so one reading covers both. A
	// scenario that needs that checked rather than asserted reads the group's
	// membership from the process table.
	group := processGroup()
	fmt.Printf("pid %d pgid %d\n", os.Getpid(), group)
	fmt.Printf("pid %d pgid %d\n", child.Process.Pid, group)
}

// winsizeLifetime bounds a session that nothing ever ends. See treeLifetime:
// no scenario asserts that this process is still running, so a stop three
// orders of magnitude beyond any deadline cannot make an assertion pass for the
// wrong reason — it only keeps a failed run from stranding a process.
const winsizeLifetime = 5 * time.Minute

// winsize reports the terminal it was given, and again whenever it changes.
//
// This is what makes a resize assertable end to end. The size is read inside
// the session, on the sandbox, through the same platform call `fleetctl shell`
// reads the local terminal with — so a scenario that resizes its own terminal
// and sees the new size printed here has followed a SIGWINCH from the
// operator's window, through the client, over the stream, and into a
// TIOCSWINSZ on the far end.
//
// A program that renders to the wrong width is the whole failure this covers,
// and it is invisible to every other kind of assertion: `top` on an 80-column
// terminal that is really 200 wide produces output, just useless output.
func winsize() {
	ctx, cancel := context.WithTimeout(context.Background(), winsizeLifetime)
	defer cancel()

	// stdout, not stdin: on Windows a terminal's size comes from the console
	// screen buffer, and only the output handle has one.
	platform.WatchWindowSize(ctx, os.Stdout.Fd(), func(columns, rows int) {
		fmt.Printf("size %dx%d\n", columns, rows)
	})
}

// sleepForever blocks until something kills the process.
//
// A bare `select {}` would be shorter and would panic: the runtime reports
// every goroutine blocked forever as a deadlock, and a helper that killed
// itself with a stack trace would make "nothing survived" trivially true.
func sleepForever() {
	for {
		time.Sleep(time.Hour)
	}
}
