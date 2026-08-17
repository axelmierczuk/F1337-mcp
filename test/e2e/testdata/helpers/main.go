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
// It lives under testdata so the module's own build and lint passes ignore it;
// the suite compiles it at startup, so it cannot rot unnoticed.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: helpers <serve|spew|tree|sleep|winsize> ...")
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "spew":
		spew(os.Args[2:])
	case "tree":
		tree(os.Args[2:])
	case "sleep":
		sleepForever()
	case "winsize":
		winsize()
	default:
		fail("unknown command " + os.Args[1])
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "helpers:", msg)
	os.Exit(2)
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
		fmt.Fprint(w, body)
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
		child := exec.Command(os.Args[0], "tree", strconv.Itoa(depth-1))
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			fail("spawn child: " + err.Error())
		}
	}
	time.Sleep(treeLifetime)
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
