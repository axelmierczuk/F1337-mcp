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
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: helpers <serve|serve-when|spew|tree|sleep> ...")
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "serve-when":
		serveWhen(os.Args[2:])
	case "spew":
		spew(os.Args[2:])
	case "tree":
		tree(os.Args[2:])
	case "sleep":
		sleepForever()
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
		fmt.Fprint(w, body)
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
