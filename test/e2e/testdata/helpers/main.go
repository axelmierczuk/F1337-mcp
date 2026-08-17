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
		fail("usage: helpers <serve|spew|tree|sleep> ...")
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
func serve(args []string) {
	if len(args) < 2 {
		fail("usage: helpers serve <port> <body>")
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

// tree announces its pid, spawns a child one level shallower, and then sleeps
// forever.
//
// Each level prints "pid N" on the shared stdout, so the caller ends up holding
// the identity of every process in the tree. Nothing here exits on its own: the
// only way this tree ends is for something to kill it, which is the question
// the timeout scenario asks.
func tree(args []string) {
	depth := 2
	if len(args) > 0 {
		d, err := strconv.Atoi(args[0])
		if err != nil {
			fail("depth: " + err.Error())
		}
		depth = d
	}

	fmt.Printf("pid %d\n", os.Getpid())
	if depth > 0 {
		child := exec.Command(os.Args[0], "tree", strconv.Itoa(depth-1))
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			fail("spawn child: " + err.Error())
		}
	}
	sleepForever()
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
