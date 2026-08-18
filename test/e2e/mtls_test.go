//go:build integration

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The two scenarios in this file are the whole of #85 as an operator meets it:
// an agent on a network that authenticates its own peers, running with no CA at
// all, and the refusal that stops the same configuration from landing on a
// reachable address by accident.
//
// The second is the one that must not be able to pass vacuously. A test that
// only asserted "the daemon exited" would pass for a typo in the config, a
// missing binary, or a port already in use — so it asserts the reason, and then
// starts the *same* configuration with the flag that authorises it and requires
// that one to serve.

// plaintextAgent starts a `fleet-agent serve` on loopback with no TLS material
// at all, against a config this test wrote by hand.
//
// By hand, because that is the whole point: there is no CA on this machine to
// enroll against, and `fleet-agent enroll` is the ceremony this posture skips.
// The file is the one documented in examples/agent.yaml, loaded by the daemon's
// own loader.
func (f *fleet) plaintextAgent(t *testing.T, name string) *agent {
	t.Helper()

	a := f.writePlaintextAgent(t, name, fmt.Sprintf("127.0.0.1:%d", freePort(t)))
	f.startAgent(a)
	return a
}

// writePlaintextAgent writes the config and the argv without starting anything,
// for a scenario that expects the start to fail.
func (f *fleet) writePlaintextAgent(t *testing.T, name, listen string) *agent {
	t.Helper()

	dir := filepath.Join(f.root, "agents", name)
	home := filepath.Join(f.root, "homes", name)
	for _, d := range []string{dir, home} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatalf("create %s: %v", d, err)
		}
	}

	// Relative paths resolve against the config file's own directory, which is
	// what keeps this layout the same as an enrolled agent's — and is what lets
	// readAudit find the log.
	config := fmt.Sprintf(`name: %q
listen: %q
tls:
  enabled: false
audit:
  enabled: true
  path: "logs/audit.jsonl"
state_dir: "state"
`, name, listen)
	path := filepath.Join(dir, "agent.yaml")
	writeFile(t, path, []byte(config))

	return &agent{
		name: name,
		dir:  dir,
		addr: listen,
		home: home,
		env: envWith(
			envEntry("PATH", os.Getenv("PATH")),
			envEntry("HOME", home),
			envEntry("TMPDIR", os.TempDir()),
		),
		args: []string{"serve", "--config", path, "--log-level", "debug"},
	}
}

// A fleet with one enrolled agent and one that never enrolled: both reachable,
// both usable, and told apart everywhere an operator or a model looks.
//
// The mTLS half is not decoration. Every assertion below about the
// unauthenticated agent is only meaningful because the authenticated one, in
// the same fleet, through the same commands, answers differently — a product
// that had simply stopped authenticating anything would satisfy half of this
// file otherwise.
func TestUnauthenticatedAgentServesAndIsMarkedEverywhere(t *testing.T) {
	f := newFleet(t)
	secure := f.enroll("build-box", enrollOptions{})
	open := f.plaintextAgent(t, "tailnet-box")

	s := f.connect(t)

	// The registry entry is the operator's decision, stated: nothing infers it,
	// because an agent serving plaintext and one refusing a handshake are
	// indistinguishable to a dialer that has not been told.
	added := structured[addResult](t, s.ok("fleet_add", map[string]any{
		"name": open.name, "address": open.addr, "insecure": true,
	}))
	if added.Auth != "none" {
		t.Fatalf("fleet_add reported auth %q for an insecure sandbox, want none", added.Auth)
	}
	if !contains(added.Note, "without mTLS") {
		t.Fatalf("fleet_add's note does not say what it registered: %q", added.Note)
	}

	// It works. This is the feature: an agent that skipped the CA ceremony
	// runs commands for the control plane immediately.
	s.ok("fleet_select", map[string]any{"name": open.name})
	const marker = "reached-the-unauthenticated-agent"
	ran := structured[execResult](t, s.ok("fleet_exec", map[string]any{
		"argv": []string{"sh", "-c", "echo " + marker},
	}))
	if ran.ExitCode != 0 || !contains(ran.Stdout, marker) {
		t.Fatalf("the command did not run on the unauthenticated agent: %+v", ran)
	}
	if ran.Sandbox != open.name {
		t.Fatalf("the result echoes sandbox %q, want %q", ran.Sandbox, open.name)
	}

	// fleet_info: the posture, and the agent's own account of who it thinks it
	// is serving.
	info := structured[infoResult](t, s.ok("fleet_info", map[string]any{"sandbox": open.name}))
	if info.Auth != "none" {
		t.Fatalf("fleet_info reports auth %q for the unauthenticated agent, want none", info.Auth)
	}
	if !strings.HasPrefix(info.Principal, "unauthenticated:") {
		t.Fatalf("the agent named its caller %q; an unverified principal must say so", info.Principal)
	}
	if !contains(info.Note, "registered as insecure") {
		t.Fatalf("fleet_info's note does not explain what auth none means: %q", info.Note)
	}

	secureInfo := structured[infoResult](t, s.ok("fleet_info", map[string]any{"sandbox": secure.name}))
	if secureInfo.Auth != "mtls" {
		t.Fatalf("fleet_info reports auth %q for the enrolled agent, want mtls", secureInfo.Auth)
	}
	if secureInfo.Principal != "fleet-mcp" {
		t.Fatalf("the enrolled agent named its caller %q, want fleet-mcp", secureInfo.Principal)
	}

	// fleet_list: both, side by side.
	list := structured[listResult](t, s.ok("fleet_list", nil))
	auth := map[string]string{}
	for _, line := range list.Sandboxes {
		auth[line.Name] = line.Auth
	}
	if auth[open.name] != "none" || auth[secure.name] != "mtls" {
		t.Fatalf("fleet_list does not tell the two apart: %+v", auth)
	}

	// `fleetctl list`: the same fact, for the operator rather than the model.
	out := runCLI(t, bins.fleetctl, []string{"list", "--no-probe"}, f.ctlEnv())
	if !contains(out, "AUTH") {
		t.Fatalf("`fleetctl list` has no AUTH column:\n%s", out)
	}
	for _, want := range []string{
		open.name, "none", secure.name, "mtls",
		"auth none (" + open.name + ")",
		"nothing in this fleet authenticates either end",
	} {
		if !contains(out, want) {
			t.Fatalf("`fleetctl list` does not show %q:\n%s", want, out)
		}
	}

	// The audit record. This is the one that decides whether the log keeps
	// meaning what it meant: a principal nothing verified must not read like
	// one that was.
	rec := waitForRecordNaming(t, open, marker)
	if got, _ := rec["principal"].(string); !strings.HasPrefix(got, "unauthenticated:") {
		t.Fatalf("the audit record attributes the command to %q; nothing authenticated that caller", got)
	}
	if got := rec["principal_source"]; got != "network" {
		t.Fatalf("the audit record reports principal_source %v, want network", got)
	}
	if got := rec["sandbox"]; got != open.name {
		t.Fatalf("the audit record names sandbox %v, want %q", got, open.name)
	}

	// And the enrolled agent's record, from the same fleet through the same
	// tool, still names a certificate — so "network" above is a fact about that
	// agent rather than about this build.
	s.ok("fleet_select", map[string]any{"name": secure.name})
	const secureMarker = "reached-the-enrolled-agent"
	s.ok("fleet_exec", map[string]any{"argv": []string{"sh", "-c", "echo " + secureMarker}})
	secureRec := waitForRecordNaming(t, secure, secureMarker)
	if got := secureRec["principal"]; got != "fleet-mcp" {
		t.Fatalf("the enrolled agent's record attributes the command to %v, want fleet-mcp", got)
	}
	if got := secureRec["principal_source"]; got != "certificate" {
		t.Fatalf("the enrolled agent's record reports principal_source %v, want certificate", got)
	}

	// Said at every start, in the daemon's own log, where an operator running
	// `service status` or reading journald will meet it.
	logs := open.logs()
	for _, want := range []string{
		"THIS AGENT AUTHENTICATES NOBODY",
		"tls.enabled is false",
		"authenticates its peers",
		"mtls=false",
	} {
		if !contains(logs, want) {
			t.Fatalf("the daemon never said %q at startup:\n%s", want, logs)
		}
	}
	if contains(secure.logs(), "THIS AGENT AUTHENTICATES NOBODY") {
		t.Fatalf("the enrolled agent claimed it authenticates nobody:\n%s", secure.logs())
	}
}

// The guard: an agent with mTLS off refuses to open a listener that is neither
// loopback nor private, and starts on the same configuration once the operator
// says they mean it.
//
// `--listen 0.0.0.0:8722` with no mTLS is the shape this must never allow
// silently, and it is the default listen address, so the refusal is what stands
// between "an operator skipped the CA ceremony" and "an operator published a
// shell on their host".
func TestAgentRefusesToServeUnauthenticatedOnAPublicAddress(t *testing.T) {
	f := newFleet(t)

	port := freePort(t)
	wildcard := fmt.Sprintf("0.0.0.0:%d", port)
	a := f.writePlaintextAgent(t, "wildcard-box", wildcard)

	// Spawned rather than run to completion, and given a deadline: a daemon
	// that wrongly starts here serves forever, and a test that waited for it
	// would report a regression in this guard as a suite-wide timeout twenty
	// minutes later rather than as itself. Verified — with both halves of the
	// guard deleted this fails in seconds, naming the daemon that would not
	// exit.
	p := start(t, "fleet-agent wildcard-box", bins.agent, a.args, procOptions{env: a.env, dir: a.home})
	p.awaitExit(t, 30*time.Second)
	if p.waitErr == nil {
		t.Fatalf("`fleet-agent serve` exited zero on %s with no mTLS; it must refuse:\n%s", wildcard, p.stderr())
	}
	out := p.stderr()
	// The reason, not merely a failure: a test that accepted any non-zero exit
	// would pass for a typo in the config or a port already in use.
	for _, want := range []string{
		"refusing to serve without mTLS",
		wildcard,
		"binds every interface",
		"--allow-unauthenticated-public",
		"tls.enabled: true",
	} {
		if !contains(out, want) {
			t.Fatalf("the refusal does not say %q:\n%s", want, out)
		}
	}
	if dialable("127.0.0.1:" + fmt.Sprint(port)) {
		t.Fatalf("something is listening on %s after the daemon refused to serve", wildcard)
	}

	// The same configuration, plus the flag that authorises it, must serve —
	// which is what stops the refusal above from being a daemon that cannot
	// start at all, or a wildcard address the daemon simply cannot bind.
	allowedPort := freePort(t)
	allowed := f.writePlaintextAgent(t, "wildcard-box-allowed", fmt.Sprintf("0.0.0.0:%d", allowedPort))
	allowed.args = append(allowed.args, "--allow-unauthenticated-public")
	// It binds every interface; this is where the test reaches it.
	allowed.addr = fmt.Sprintf("127.0.0.1:%d", allowedPort)
	f.startAgent(allowed)

	// And it is still loud about what it is. The flag buys the operator a
	// listener, not silence.
	waitFor(t, 30*time.Second, "the allowed daemon to announce its posture", func() (bool, string) {
		if contains(allowed.logs(), "THIS AGENT AUTHENTICATES NOBODY") {
			return true, ""
		}
		return false, "no posture warning yet"
	})
}

// A public listen address with mTLS on is an ordinary deployment, and the guard
// must not touch it.
//
// Without this the "refusal" could be a wildcard-address ban, which would break
// every enrolled agent in the world — the default listen address is 0.0.0.0.
func TestEnrolledAgentStillServesOnAWildcardAddress(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("wide-box", enrollOptions{})

	port := portOf(t, a.addr)
	a.proc.terminate(t)
	a.args = []string{"serve", "--config", filepath.Join(a.dir, "agent.yaml"), "--log-level", "debug",
		"--listen", "0.0.0.0:" + port}
	f.startAgent(a)

	s := f.connect(t)
	s.ok("fleet_select", map[string]any{"name": a.name})
	ran := structured[execResult](t, s.ok("fleet_exec", map[string]any{"argv": []string{"sh", "-c", "echo wide"}}))
	if ran.ExitCode != 0 || !contains(ran.Stdout, "wide") {
		t.Fatalf("an enrolled agent on a wildcard address must serve normally: %+v", ran)
	}
}

// waitForRecordNaming waits for the audit record of the command carrying
// marker, and returns it.
func waitForRecordNaming(t *testing.T, a *agent, marker string) map[string]any {
	t.Helper()

	var found map[string]any
	waitFor(t, 30*time.Second, "the exec on "+a.name+" to reach the audit log", func() (bool, string) {
		for _, line := range strings.Split(readAudit(t, a), "\n") {
			if !contains(line, marker) {
				continue
			}
			var rec map[string]any
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				return false, "unparseable record: " + line
			}
			found = rec
			return true, ""
		}
		return false, "no record naming the command yet"
	})
	return found
}

// portOf pulls the port out of a host:port address.
func portOf(t *testing.T, address string) string {
	t.Helper()
	i := strings.LastIndex(address, ":")
	if i < 0 {
		t.Fatalf("address %q is not host:port", address)
	}
	return address[i+1:]
}
