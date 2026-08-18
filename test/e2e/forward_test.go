//go:build integration

package e2e

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// TestDevServerReadinessForwardAndFetch is the whole remote development loop,
// end to end: start a server on a sandbox, wait for it to be usable rather than
// merely spawned, forward its port to this workstation, and fetch it over
// localhost.
//
// It is the scenario the product exists for, and every part of it crosses a
// process boundary: the readiness probe is the agent connecting to its own
// loopback, the forward is a bidirectional gRPC stream carrying a TCP
// connection, and the fetch is an ordinary HTTP client that knows nothing about
// any of it.
func TestDevServerReadinessForwardAndFetch(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})
	s := f.connect(t)
	s.ok("fleet_select", map[string]any{"name": a.name})

	remotePort := freePort(t)
	const body = "hello from the sandbox"

	started := startProcess(t, s, map[string]any{
		"name": "web-dev",
		"argv": []string{bins.helpers, "serve", strconv.Itoa(remotePort), body},
		"ready_probe": map[string]any{
			"tcp_port":        remotePort,
			"timeout_seconds": 30,
		},
	})
	defer stopProcess(t, s, started)

	if started.Ready == nil || !*started.Ready {
		t.Fatalf("a process started with a tcp_port probe must report readiness: %+v", started)
	}
	if started.Process.State != "ready" {
		t.Fatalf("process state is %q after a passing probe, want ready", started.Process.State)
	}
	// listening_ports is best effort — it costs a /proc walk on Linux and an
	// lsof on macOS, and either can come back empty. When the agent does report
	// ports, the one the model is about to forward has to be among them.
	if ports := started.Process.ListeningPorts; len(ports) > 0 {
		if !containsPort(ports, remotePort) {
			t.Fatalf("the agent reports the process listening on %v, not on %d", ports, remotePort)
		}
	}

	// Forward it. The local port is chosen by the server, not by the caller,
	// which is what a workstation with an unpredictable set of free ports needs.
	fwd := structured[forwardResult](t, s.ok("fleet_forward", map[string]any{"remote_port": remotePort}))
	if fwd.Sandbox != a.name {
		t.Fatalf("the forward echoed sandbox %q, want %q", fwd.Sandbox, a.name)
	}
	if fwd.LocalAddress == "" || fwd.LocalPort == 0 {
		t.Fatalf("the forward reported no local address: %+v", fwd)
	}
	if fwd.RemotePort != remotePort {
		t.Fatalf("the forward reports remote port %d, want %d", fwd.RemotePort, remotePort)
	}

	// The fetch a developer would make, from a client that has no idea a
	// sandbox is involved.
	if got := httpGet(t, "http://"+fwd.LocalAddress+"/"); got != body {
		t.Fatalf("fetched %q over the forward, want %q", got, body)
	}

	// A second call for the same port reuses the forward rather than opening a
	// second listener, and reports what has been carried over it.
	again := structured[forwardResult](t, s.ok("fleet_forward", map[string]any{"remote_port": remotePort}))
	if !again.Existing {
		t.Fatalf("a second forward for the same port should have been reported as existing: %+v", again)
	}
	if again.LocalPort != fwd.LocalPort {
		t.Fatalf("the reused forward moved from local port %d to %d", fwd.LocalPort, again.LocalPort)
	}
	var carried uint64
	for _, line := range again.Active {
		if line.RemotePort == remotePort {
			carried = line.Connections
			if line.LastError != "" {
				t.Fatalf("the forward recorded a connection error: %s", line.LastError)
			}
		}
	}
	if carried == 0 {
		t.Fatalf("the forward reports no connections after a successful fetch: %+v", again.Active)
	}

	// Stopping it closes the local listener, which is the half a caller can
	// check: a forward that reported itself stopped and kept the port would
	// hold it against the next process to want it.
	stopped := structured[forwardResult](t, s.ok("fleet_forward", map[string]any{
		"remote_port": remotePort, "stop": true,
	}))
	if !stopped.Stopped {
		t.Fatalf("stopping the forward did not report it stopped: %+v", stopped)
	}
	waitFor(t, 30*time.Second, "the local forward listener to close", func() (bool, string) {
		if !dialable(fwd.LocalAddress) {
			return true, ""
		}
		return false, fwd.LocalAddress + " is still accepting"
	})

	// The server on the sandbox is untouched by any of that: a forward is a
	// route, not a lifetime. Its own announcement is in its own log.
	//
	// Waited for, not read once. The probe that passed above is a TCP connect,
	// and the announcement reaching this log is a different event: the helper
	// binds its port before it prints, the agent writes the child's output to a
	// capture file, and the supervisor tails that file on a poll that backs off
	// from 5ms to 200ms while a process is quiet. A server that takes long
	// enough to start can therefore be connectable well before its first line
	// is readable. This used to be read about 70ms after readiness, which is a
	// guess that those are one event — #83, and 3 of 3 red on a busy host. The
	// deadline is a failsafe for a line that never arrives, which is the defect
	// worth failing on.
	marker := "listening on " + strconv.Itoa(remotePort)
	waitFor(t, 30*time.Second, "the dev server's own announcement to reach its logs", func() (bool, string) {
		logs := readLogs(t, s, started.Process.ProcessID)
		return contains(logs.Logs, marker), "log so far:\n" + logs.Logs
	})
	list := structured[processListResult](t, s.ok("fleet_process_list", nil))
	if p := findProcess(list.Processes, started.Process.ProcessID); p == nil || p.State != "ready" {
		t.Fatalf("the dev server should still be ready after its forward closed: %+v", p)
	}
}

// TestForwardRefusesAPortNothingIsServing checks the negative case a developer
// hits most: forwarding a port before the server behind it is up.
//
// The listener a forward opens is local, so it would be easy for this to
// "succeed" and leave the caller with a port that answers every connection with
// a reset. It does not: opening the forward reaches the sandbox first, and the
// refusal names the port and what to check.
func TestForwardRefusesAPortNothingIsServing(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})
	s := f.connect(t)
	s.ok("fleet_select", map[string]any{"name": a.name})

	closed := freePort(t)
	msg := s.fails("fleet_forward", map[string]any{"remote_port": closed})
	if !contains(msg, strconv.Itoa(closed)) {
		t.Fatalf("the refusal does not name the port that could not be reached: %s", msg)
	}
	if !contains(msg, a.name) {
		t.Fatalf("the refusal does not name the sandbox it came from: %s", msg)
	}

	// A refused forward leaves nothing behind: the next call must not report an
	// active forward for a port that never opened.
	remotePort := freePort(t)
	started := startProcess(t, s, map[string]any{
		"name": "web-dev",
		"argv": []string{bins.helpers, "serve", strconv.Itoa(remotePort), "up"},
		"ready_probe": map[string]any{
			"tcp_port":        remotePort,
			"timeout_seconds": 30,
		},
	})
	defer stopProcess(t, s, started)

	fwd := structured[forwardResult](t, s.ok("fleet_forward", map[string]any{"remote_port": remotePort}))
	for _, line := range fwd.Active {
		if line.RemotePort == closed {
			t.Fatalf("a forward that was refused is still listed as active: %+v", line)
		}
	}
	s.ok("fleet_forward", map[string]any{"remote_port": remotePort, "stop": true})
}

// httpGet fetches a URL and returns its body.
func httpGet(t *testing.T, url string) string {
	t.Helper()

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request for %s: %v", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s returned %s: %s", url, resp.Status, body)
	}
	return string(body)
}

func containsPort(ports []uint32, want int) bool {
	for _, p := range ports {
		if p == uint32(want) { //nolint:gosec // a port is well inside uint32
			return true
		}
	}
	return false
}
