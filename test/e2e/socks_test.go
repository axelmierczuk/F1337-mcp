//go:build integration

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The SOCKS proxy, end to end, driven by `curl --socks5-hostname` — the client
// the acceptance criterion names, rather than a Go SOCKS library agreeing with
// a Go SOCKS server.
//
// # What this topology can and cannot show
//
// Everything runs on one machine, so "a host only the sandbox can see" does not
// literally exist here; see README.md's "What is not covered". What does exist,
// and is what the feature actually turns on, is *where the name is resolved*.
// A proxy that resolved on the client would send an address in its CONNECT
// request; this one sends the name, and the agent's audit record — written on
// the far side of a gRPC stream, from what the agent was asked for — is where
// that difference is visible. An implementation that resolved locally would
// write "127.0.0.1" into the field these scenarios require to say "localhost",
// and no amount of the fetch working would hide it.

// TestSocksProxyCarriesCurlThroughTheSandbox is `fleetctl socks` doing its job:
// an operator opens a proxy, points curl at it, and reaches a service by a name
// this workstation never resolved.
func TestSocksProxyCarriesCurlThroughTheSandbox(t *testing.T) {
	requireCurl(t)

	f := newFleet(t)
	a := f.enrollProxying("build-box", "localhost", "nowhere.invalid")

	const body = "served to a client that went the long way round"
	destination := startDestinationServer(t, body)

	proxyPort := freePort(t)
	proxy := f.startSocks(a, "--port", strconv.Itoa(proxyPort))

	// The fetch the acceptance criterion names, from a client that knows
	// nothing about gRPC, mTLS or fleets.
	got := curlThroughProxy(t, proxy.address, fmt.Sprintf("http://localhost:%d/", destination))
	if got != body {
		t.Fatalf("fetched %q through the proxy, want %q", got, body)
	}

	// The name was resolved on the agent, which is the whole point of
	// --socks5-hostname and the one thing this topology can prove outright: a
	// proxy that resolved locally would have sent an address, and the agent
	// records what it was asked for.
	record := waitForForwardRecord(t, a, func(rec map[string]any) bool {
		return rec["remote_host"] == "localhost" && rec["outcome"] == "ok"
	}, `a connection to the name "localhost"`)

	if got := record["remote_port"]; got != float64(destination) {
		t.Fatalf("the audit record names port %v, want %d", got, destination)
	}
	if got := record["sandbox"]; got != a.name {
		t.Fatalf("the audit record names sandbox %v, want %q", got, a.name)
	}
	if got := record["rpc"]; got != "sandboxd.v1.ForwardService/Forward" {
		t.Fatalf("the audit record names rpc %v", got)
	}
	if got, ok := record["resolved_address"].(string); !ok || got == "" {
		t.Fatalf("the audit record does not say where the connection actually went: %v", record["resolved_address"])
	}
	for _, field := range []string{"bytes_to_remote", "bytes_from_remote"} {
		if got, ok := record[field].(float64); !ok || got <= 0 {
			t.Fatalf("the audit record does not count %s: %v", field, record[field])
		}
	}

	// It counts the bytes and never holds them. A proxy carries whatever the
	// caller sends through it, and a log that captured that would be a
	// credential store nobody meant to build.
	if audit := readAudit(t, a); contains(audit, body) {
		t.Fatalf("the audit log captured what the connection carried:\n%s", audit)
	}

	// The listener is loopback-only, so it is not reachable from another
	// machine. Asserted against an address a machine on this network would
	// actually dial.
	if routable := routableAddress(); routable != "" {
		if dialable(routable + ":" + strconv.Itoa(proxyPort)) {
			t.Fatalf("the proxy answered on %s:%d, so any machine that can route to this one can use it",
				routable, proxyPort)
		}
	}

	// A destination the agent's allow list does not cover is refused — by the
	// agent, not by curl — and recorded. This is the line an operator reads to
	// find out that somebody asked.
	if _, err := curl(t, proxy.address, "http://203.0.113.9:443/"); err == nil {
		t.Fatal("a destination outside forward.allowed_hosts was not refused")
	}
	denied := waitForForwardRecord(t, a, func(rec map[string]any) bool {
		return rec["outcome"] == "denied" && rec["remote_host"] == "203.0.113.9"
	}, "the refused destination")
	if got := denied["rule"]; got != "forward.allowed_hosts" {
		t.Fatalf("the refusal is recorded against rule %v, want forward.allowed_hosts", got)
	}

	// And a name the agent cannot resolve fails on the agent, which is again
	// only possible if the name crossed the wire. curl never resolved it.
	if _, err := curl(t, proxy.address, "http://nowhere.invalid/"); err == nil {
		t.Fatal("a name that resolves nowhere was reported as reachable")
	}
	waitForForwardRecord(t, a, func(rec map[string]any) bool {
		return rec["remote_host"] == "nowhere.invalid"
	}, "the unresolvable name reaching the agent")

	// Stopping the command shuts the proxy down on its own terms rather than by
	// dying — see socksProxy.stop, which is where that distinction lives. The
	// released port is checked after it as a corollary: it is what a caller
	// notices, but on its own it would be the operating system's doing.
	proxy.stop(t)
	waitFor(t, 30*time.Second, "the proxy's listener to close", func() (bool, string) {
		if !dialable(proxy.address) {
			return true, ""
		}
		return false, proxy.address + " is still accepting"
	})
}

// TestSocksIsRefusedByAnAgentThatDidNotOptIn is the default posture: proxying is
// off until an operator turns it on, and the refusal names the setting.
func TestSocksIsRefusedByAnAgentThatDidNotOptIn(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})

	// Bounded, because the failure mode of a regression here is a command that
	// succeeds and then serves forever: an unbounded run would hang until the
	// package timeout and report as "panic: test timed out" rather than as this
	// assertion. A refusal is immediate, so ten seconds is generous.
	out, err := tryCLIWithin(t, 10*time.Second, bins.fleetctl, []string{"socks", a.name}, f.ctlEnv())
	if err == nil {
		t.Fatalf("an agent that never opted in served a proxy:\n%s", out)
	}
	if !contains(out, "forward.socks_enabled") {
		t.Fatalf("the refusal does not name the setting that would permit it:\n%s", out)
	}
	if !contains(out, a.name) {
		t.Fatalf("the refusal does not name the sandbox it came from:\n%s", out)
	}
}

// TestFleetSocksRefusesAnUnrestrictedAgent is the decision #45 left open,
// asserted across the two halves it distinguishes: the same agent configuration
// that `fleetctl socks` will serve, fleet_socks will not.
func TestFleetSocksRefusesAnUnrestrictedAgent(t *testing.T) {
	requireCurl(t)

	f := newFleet(t)
	// Proxying on, nothing narrowing it: the lab-box posture.
	unrestricted := f.enrollProxying("lab-box")
	// And the same, narrowed.
	narrowed := f.enrollProxying("build-box", "localhost")

	s := f.connect(t)

	// The model is refused, and told what to ask the operator for.
	msg := s.fails("fleet_socks", map[string]any{"sandbox": unrestricted.name})
	for _, want := range []string{"forward.allowed_hosts", "any host", "fleetctl socks"} {
		if !contains(msg, want) {
			t.Fatalf("the refusal does not mention %q:\n%s", want, msg)
		}
	}

	// The operator is not. Same agent, same configuration, different caller —
	// which is the whole of the argument, so it is asserted rather than
	// described.
	proxy := f.startSocks(unrestricted, "--port", strconv.Itoa(freePort(t)))
	if !contains(proxy.banner, "ANY HOST") {
		t.Fatalf("the CLI opened an unrestricted proxy without saying so:\n%s", proxy.banner)
	}
	proxy.stop(t)

	// And --json does not silence that. The document says it in a field, which
	// is right for the script and invisible to the person watching the
	// terminal, so the same fact goes to stderr — where it cannot land in the
	// middle of the document a consumer is parsing.
	//
	// This is the only place the command is run with --json. The assertion that
	// the warning exists calls the function that composes it, which is true of a
	// build where nothing calls that function: deleting the call from the
	// command left every test in the tree green, including this suite.
	requireUnrestrictedJSONWarning(t, f, unrestricted)

	// And the narrowed agent serves the model, reaching what it was narrowed
	// to.
	const body = "reachable because an operator said which hosts are"
	destination := startDestinationServer(t, body)

	out := structured[socksResult](t, s.ok("fleet_socks", map[string]any{"sandbox": narrowed.name}))
	if out.Sandbox != narrowed.name {
		t.Fatalf("the proxy echoed sandbox %q, want %q", out.Sandbox, narrowed.name)
	}
	if out.LocalAddress == "" || out.LocalPort == 0 {
		t.Fatalf("the proxy reported no local address: %+v", out)
	}
	if !strings.HasPrefix(out.LocalAddress, "127.0.0.1:") {
		t.Fatalf("the proxy bound %s, which is not loopback", out.LocalAddress)
	}
	if len(out.AllowedHosts) == 0 {
		t.Fatalf("the result does not say where the proxy may reach: %+v", out)
	}

	if got := curlThroughProxy(t, out.LocalAddress, fmt.Sprintf("http://localhost:%d/", destination)); got != body {
		t.Fatalf("fetched %q through the model's proxy, want %q", got, body)
	}

	// Stopping it releases the listener.
	stopped := structured[socksResult](t, s.ok("fleet_socks", map[string]any{
		"sandbox": narrowed.name, "stop": true,
	}))
	if !stopped.Stopped {
		t.Fatalf("stopping the proxy did not report it stopped: %+v", stopped)
	}
	waitFor(t, 30*time.Second, "the model's proxy listener to close", func() (bool, string) {
		if !dialable(out.LocalAddress) {
			return true, ""
		}
		return false, out.LocalAddress + " is still accepting"
	})
}

// TestSocksProxyIsReleasedWithItsSandbox is the lifetime criterion, in the half
// this suite can actually assert.
//
// A proxy outlives the call that opened it, so deregistering the sandbox it
// reaches through has to take it with it: the pooled channel behind it is
// dropped on removal, and what would be left is a local port that accepts every
// connection and fails it — which a client pointed at a proxy cannot tell from
// every destination being down.
//
// The other half of the criterion — "the MCP server or CLI exiting releases
// every listener" — is deliberately *not* asserted here, because at this level
// it cannot fail: a process that exits releases its listeners whether or not
// any code asked it to, so a scenario shaped like that would report success for
// a server that closed nothing. Reverting Registrar.Close's teardown of the
// proxies leaves such a scenario green; it turns
// TestSocks_ServerCloseReleasesEveryListener in internal/mcpserver red, in the
// same process, before the exit. That is where that promise is pinned.
func TestSocksProxyIsReleasedWithItsSandbox(t *testing.T) {
	f := newFleet(t)
	a := f.enrollProxying("build-box", "localhost")

	s := f.connect(t)
	out := structured[socksResult](t, s.ok("fleet_socks", map[string]any{"sandbox": a.name}))
	if !dialable(out.LocalAddress) {
		t.Fatalf("the proxy at %s is not accepting", out.LocalAddress)
	}

	removed := structured[removeResult](t, s.ok("fleet_remove", map[string]any{"name": a.name}))
	if removed.ProxyClosed != out.LocalAddress {
		t.Fatalf("removing the sandbox reported proxy_closed %q, want %q", removed.ProxyClosed, out.LocalAddress)
	}

	// The MCP server is still running: this is the code releasing the listener,
	// not the operating system reclaiming a dead process's sockets.
	waitFor(t, 30*time.Second, "the proxy's listener to close with its sandbox", func() (bool, string) {
		if !dialable(out.LocalAddress) {
			return true, ""
		}
		return false, out.LocalAddress + " is still accepting"
	})

	// Genuinely released, not merely deaf: the port is free for the next
	// process to want it.
	port := out.LocalAddress[strings.LastIndex(out.LocalAddress, ":")+1:]
	if !portIsFree(t, port) {
		t.Fatalf("port %s was not released when its sandbox was removed", port)
	}
}

// requireUnrestrictedJSONWarning runs `fleetctl socks --json` against an agent
// that permits every host and requires both halves of the answer: the field a
// script reads, and the line a person does.
func requireUnrestrictedJSONWarning(t *testing.T, f *fleet, a *agent) {
	t.Helper()

	port := freePort(t)
	p := start(t, "fleetctl socks --json "+a.name, bins.fleetctl,
		[]string{"socks", a.name, "--json", "--port", strconv.Itoa(port)},
		procOptions{env: f.ctlEnv()})
	address := "127.0.0.1:" + strconv.Itoa(port)

	var doc socksResult
	waitFor(t, 30*time.Second, "the --json document to be emitted", func() (bool, string) {
		if !p.running() {
			t.Fatalf("fleetctl socks --json exited:\nstdout:\n%s\nstderr:\n%s", p.stdout(), p.stderr())
		}
		if err := json.Unmarshal([]byte(p.stdout()), &doc); err != nil {
			return false, "no complete document yet:\n" + p.stdout()
		}
		return true, ""
	})

	if doc.LocalAddress != address {
		t.Fatalf("the document reports local_address %q, want %q", doc.LocalAddress, address)
	}
	if !doc.Unrestricted {
		t.Fatalf("the document does not report an unrestricted proxy as one: %+v", doc)
	}
	// The warning a person reads, on the stream that is not carrying the
	// document.
	if !contains(p.stderr(), "ANY host "+a.name) {
		t.Fatalf("--json silenced the warning that this proxy reaches any host %s can:\nstderr:\n%s", a.name, p.stderr())
	}
	if contains(p.stdout(), "warning:") {
		t.Fatalf("the warning landed in the document a consumer is parsing:\n%s", p.stdout())
	}

	// And it shuts itself down on a signal in this mode too, which is a
	// different path: --json returns as soon as Serve does rather than printing
	// a closing summary, so the summary socksProxy.stop looks for is not there
	// to look for.
	p.terminate(t)
	if p.waitErr != nil {
		t.Fatalf("fleetctl socks --json exited with %v rather than shutting down on its own terms:\nstderr:\n%s", p.waitErr, p.stderr())
	}
}

// ------------------------------------------------------------- fixtures

// enrollProxying enrolls an agent with SOCKS proxying turned on, narrowed to
// allowedHosts — or, with none, to nothing at all, which is the unrestricted
// posture.
//
// The edit is textual, on the config `fleet-agent enroll` wrote, for the same
// reason disableExec's is: the daemon reads this file with its own loader, and a
// test that round-tripped it through a hand-written struct would be asserting
// against its own idea of the schema instead of the product's.
func (f *fleet) enrollProxying(name string, allowedHosts ...string) *agent {
	f.t.Helper()

	a := f.enroll(name, enrollOptions{})
	a.stop(f.t)
	f.enableSocks(filepath.Join(a.dir, "agent.yaml"), allowedHosts...)
	f.startAgent(a)
	return a
}

// enableSocks rewrites the forward block of an enrolled config.
func (f *fleet) enableSocks(path string, allowedHosts ...string) {
	f.t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		f.t.Fatalf("read %s: %v", path, err)
	}
	text := string(data)

	const marker = "\nforward:\n"
	at := strings.Index(text, marker)
	if at < 0 {
		f.t.Fatalf("agent.yaml has no forward block:\n%s", text)
	}
	// The indentation the encoder chose, taken from the block's first key
	// rather than assumed: a change in how the config is written should fail
	// here rather than produce a file the daemon reads as something else.
	rest := text[at+len(marker):]
	indent := rest[:len(rest)-len(strings.TrimLeft(rest, " "))]
	if indent == "" {
		f.t.Fatalf("the forward block in agent.yaml is not indented:\n%s", text)
	}

	added := indent + "socks_enabled: true\n"
	if len(allowedHosts) > 0 {
		added += indent + "allowed_hosts:\n"
		for _, host := range allowedHosts {
			added += indent + "  - " + host + "\n"
		}
	}
	writeFile(f.t, path, []byte(text[:at+len(marker)]+added+rest))

	// Read back through the daemon's own loader would be ideal and is not
	// available here; the next best is that the daemon starts and serves, which
	// startAgent waits for. A config it cannot parse fails there, loudly.
}

// socksProxy is a running `fleetctl socks`.
type socksProxy struct {
	proc    *proc
	address string
	banner  string
}

// startSocks runs `fleetctl socks` against an agent and waits until it is
// serving.
func (f *fleet) startSocks(a *agent, args ...string) *socksProxy {
	f.t.Helper()

	argv := append([]string{"socks", a.name}, args...)
	p := start(f.t, "fleetctl socks "+a.name, bins.fleetctl, argv, procOptions{env: f.ctlEnv()})

	var address string
	waitFor(f.t, 30*time.Second, "the proxy to report its address", func() (bool, string) {
		if !p.running() {
			f.t.Fatalf("fleetctl socks exited:\n%s\n%s", p.stdout(), p.stderr())
		}
		line := lineWith(p.stdout(), "listening on ")
		if line == "" {
			return false, "no listening line yet"
		}
		address = strings.TrimSpace(line[strings.Index(line, "listening on ")+len("listening on "):])
		return true, ""
	})
	waitFor(f.t, 30*time.Second, "the proxy to accept connections", func() (bool, string) {
		if dialable(address) {
			return true, ""
		}
		return false, "nothing listening on " + address
	})
	return &socksProxy{proc: p, address: address, banner: p.stdout()}
}

// stop signals the proxy the way a service manager or Ctrl-C does, and
// requires that it shut itself down rather than merely died.
//
// "The listener is gone afterwards" is deliberately *not* the assertion, for
// the same reason the MCP-server-exit scenario was replaced: a process that
// exits releases its listeners whether or not any code asked it to, so a check
// shaped that way reports success for a command whose signal handling does
// nothing at all. Ripping signal.NotifyContext out of `fleetctl socks` leaves
// the port free on the next line and this function red — the default
// disposition for SIGTERM kills the process, and a killed process prints no
// closing summary and exits non-zero.
//
// What only the graceful path produces is that summary: it is written after
// Serve returns, which needs the signal to have been caught and the listener
// closed under it.
func (s *socksProxy) stop(t *testing.T) {
	t.Helper()
	s.proc.terminate(t)

	if s.proc.waitErr != nil {
		t.Fatalf("fleetctl socks exited with %v rather than shutting down on its own terms:\nstdout:\n%s\nstderr:\n%s",
			s.proc.waitErr, s.proc.stdout(), s.proc.stderr())
	}
	if !contains(s.proc.stdout(), "stopped "+s.address) {
		t.Fatalf("fleetctl socks never reported stopping %s, so its shutdown was the process dying rather than the command closing its listener:\nstdout:\n%s\nstderr:\n%s",
			s.address, s.proc.stdout(), s.proc.stderr())
	}
}

// startDestinationServer runs an HTTP server standing in for something on the
// sandbox's network, and returns its port.
func startDestinationServer(t *testing.T, body string) int {
	t.Helper()
	port := freePort(t)
	p := start(t, "destination", bins.helpers,
		[]string{"serve", strconv.Itoa(port), body}, procOptions{})
	waitFor(t, 30*time.Second, "the destination server to accept connections", func() (bool, string) {
		if !p.running() {
			t.Fatalf("the destination server exited:\n%s", p.stderr())
		}
		if dialable("127.0.0.1:" + strconv.Itoa(port)) {
			return true, ""
		}
		return false, "nothing listening on port " + strconv.Itoa(port)
	})
	return port
}

// ---------------------------------------------------------------- curl

// tryCLIWithin runs a command under a deadline and returns its combined output.
//
// tryCLI has none, which is right for the one-shot commands it was written for
// and wrong for a command whose success case is "serve until stopped": a test
// asserting that such a command *fails* has to be able to tell a refusal from a
// success, and without a deadline the second one is indistinguishable from a
// hang.
func tryCLIWithin(t *testing.T, timeout time.Duration, bin string, args []string, env []string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("%s %v did not return within %s; it served rather than refusing:\n%s",
			filepathBase(bin), args, timeout, out)
	}
	return string(out), err
}

// requireCurl fails rather than skips.
//
// The acceptance criterion for this feature is written in terms of `curl
// --socks5-hostname`, and a scenario that quietly skipped when curl was absent
// would report success for a run that proved nothing about the client the
// criterion names. curl ships on both platforms this suite supports and on both
// CI runners it runs on, so its absence is a broken environment rather than a
// configuration to tolerate.
func requireCurl(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("curl"); err != nil {
		t.Fatalf("curl is not on PATH, and the SOCKS scenarios are written against it: %v. "+
			"See test/e2e/README.md — it is the client this feature's acceptance criterion names, "+
			"so these scenarios fail rather than skip without it", err)
	}
}

// curlThroughProxy fetches a URL through a SOCKS5 proxy and returns the body.
func curlThroughProxy(t *testing.T, proxyAddress, url string) string {
	t.Helper()
	out, err := curl(t, proxyAddress, url)
	if err != nil {
		t.Fatalf("curl --socks5-hostname %s %s: %v\n%s", proxyAddress, url, err, out)
	}
	return out
}

// curl runs the real client, with --socks5-hostname so the destination name is
// sent to the proxy rather than resolved here. That flag is the whole subject:
// with --socks5 instead, curl resolves locally and a private name reaches the
// wrong host or nothing at all.
func curl(t *testing.T, proxyAddress, url string) (string, error) {
	t.Helper()
	cmd := exec.Command("curl",
		"--socks5-hostname", proxyAddress,
		"--silent", "--show-error", "--fail",
		"--max-time", "30",
		url)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ----------------------------------------------------------- assertions

// waitForForwardRecord waits for an audit record matching want and returns it.
func waitForForwardRecord(t *testing.T, a *agent, want func(map[string]any) bool, what string) map[string]any {
	t.Helper()

	var found map[string]any
	waitFor(t, 30*time.Second, what+" to reach the audit log", func() (bool, string) {
		for _, line := range strings.Split(readAudit(t, a), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var rec map[string]any
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				return false, "unparseable record: " + line
			}
			if want(rec) {
				found = rec
				return true, ""
			}
		}
		return false, "no matching record yet"
	})
	return found
}

// readAudit returns the agent's whole audit log, or "" if it has written none.
func readAudit(t *testing.T, a *agent) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(a.dir, "logs", "audit.jsonl"))
	if err != nil {
		return ""
	}
	return string(data)
}

// portIsFree reports whether a port can be bound, which is how a released
// listener is told from a delisted one.
func portIsFree(t *testing.T, port string) bool {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		return false
	}
	_ = lis.Close()
	return true
}

// routableAddress is a non-loopback IPv4 address of this host, or "" if there
// is none — which is what another machine on this network would dial.
func routableAddress() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() || ipnet.IP.To4() == nil {
			continue
		}
		return ipnet.IP.String()
	}
	return ""
}
