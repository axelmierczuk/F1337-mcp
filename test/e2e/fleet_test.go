//go:build integration

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fleet is a whole running system: a CA, a control plane serving enrollment,
// and the agents enrolled against it.
//
// One fleet per test. Sharing one across tests would be faster and would make
// every scenario depend on what the previous one left behind — a fleet is
// cheap here (two processes and a keypair) and a scenario that starts from a
// known state is worth more than the second it saves.
type fleet struct {
	t *testing.T

	// root holds everything this fleet ever writes: the control plane's config
	// directory, each agent's enrollment directory, and the home directories
	// that give the agents distinguishable identities.
	root string
	// ctlDir is FLEET_CONFIG_DIR for fleetctl and fleet-mcp alike: the CA, the
	// token store, the registry and the control leaf all live here, which is
	// exactly the layout an operator following docs/quickstart.md ends up with.
	ctlDir string

	fingerprint string
	enrollAddr  string
	control     *proc
}

// agent is one enrolled fleet-agent: its enrollment directory, the daemon
// process, and the facts a scenario uses to prove a call reached *this* host
// rather than its neighbour.
type agent struct {
	name string
	dir  string
	addr string

	// home is the daemon's HOME, and the reason two agents on one machine are
	// distinguishable at all.
	//
	// The agent does not pass its own environment to commands it runs — the
	// base environment is an allowlist, deliberately, so an operator's
	// credentials do not reach a model's commands — but HOME is on that
	// allowlist and is what an exec with no working_dir runs in. Two daemons
	// with different HOMEs therefore run identical argv in different
	// directories, which is the loopback equivalent of two containers with
	// different hostnames.
	home string

	// env is the daemon's whole environment, kept so a restart is the same
	// daemon rather than a similar one.
	env  []string
	args []string
	proc *proc
}

// newFleet initialises a CA, issues the control leaf, and starts the
// enrollment endpoint.
func newFleet(t *testing.T) *fleet {
	t.Helper()
	requireSupportedHost(t)

	root := t.TempDir()
	ctlDir := filepath.Join(root, "control")
	if err := os.MkdirAll(ctlDir, 0o700); err != nil {
		t.Fatalf("create control config directory: %v", err)
	}

	f := &fleet{t: t, root: root, ctlDir: ctlDir}

	out := runCLI(t, bins.fleetctl, []string{"ca", "init"}, f.ctlEnv())
	f.fingerprint = valueAfter(t, out, "SHA256 Fingerprint=")

	f.issueControlLeaf()
	f.startControlPlane()
	return f
}

// ctlEnv is the environment every fleetctl and fleet-mcp invocation runs with.
// FLEET_CONFIG_DIR is what keeps the CA, the token store, the registry and the
// control leaf in one directory across all three binaries.
func (f *fleet) ctlEnv() []string { return f.configEnv(f.ctlDir) }

// configEnv is ctlEnv pointed at some other config directory — an operator's
// second workstation, or one that is missing a credential on purpose.
func (f *fleet) configEnv(dir string) []string {
	return envWith(
		envEntry("FLEET_CONFIG_DIR", dir),
		envEntry("PATH", os.Getenv("PATH")),
		envEntry("HOME", f.root),
		envEntry("TMPDIR", os.TempDir()),
	)
}

// issueControlLeaf gives fleet-mcp the client certificate it presents to
// agents.
//
// One shipped command, run with the argv docs/quickstart.md prints and nothing
// else: `fleetctl ca sign --profile control` with no --csr generates the
// keypair here — the leaf identifies this workstation, so its key has nowhere
// else to be made — and writes control.crt and control.key into the config
// directory, which is where fleet-mcp and `fleetctl list` look for them.
//
// This step used to be the one part of the documented flow no command
// performed: `ca sign` signed a CSR and nothing produced one, so the suite
// built the CSR itself with crypto/x509 and covered only the signing. That gap
// was pinned by TestNoShippedCommandIssuesTheControlLeaf until #54 closed it,
// and both the test and the workaround went with it. Do not reintroduce a
// hand-built CSR here: the point of this call is that the suite walks the
// operator's path rather than one it built for itself, and a workaround nothing
// fails on is a workaround nobody removes.
func (f *fleet) issueControlLeaf() {
	f.t.Helper()

	runCLI(f.t, bins.fleetctl, []string{"ca", "sign", "--profile", "control"}, f.ctlEnv())

	// The command was given no paths, so where it put them is part of what the
	// operator's flow promises: fleet-mcp reads these two names out of the
	// config directory and reaches no agent without them. Asserted here so a
	// regression in the defaults reads as itself rather than as every scenario
	// failing to connect.
	for _, name := range []string{"control.crt", "control.key"} {
		if _, err := os.Stat(filepath.Join(f.ctlDir, name)); err != nil {
			f.t.Fatalf("`fleetctl ca sign --profile control` left no %s in the config directory: %v", name, err)
		}
	}
}

// startControlPlane runs `fleetctl serve` on an ephemeral port and reads back
// the address it actually bound.
func (f *fleet) startControlPlane() {
	f.t.Helper()

	f.control = start(f.t, "fleetctl serve", bins.fleetctl,
		[]string{"serve", "--listen", "127.0.0.1:0"}, procOptions{env: f.ctlEnv()})

	waitFor(f.t, 30*time.Second, "the enrollment endpoint to report its address", func() (bool, string) {
		if !f.control.running() {
			f.t.Fatalf("fleetctl serve exited:\n%s\n%s", f.control.stdout(), f.control.stderr())
		}
		line := lineWith(f.control.stdout(), "enrollment endpoint listening on ")
		if line == "" {
			return false, "no listening line yet"
		}
		f.enrollAddr = strings.TrimSpace(strings.TrimPrefix(line, "enrollment endpoint listening on "))
		return true, ""
	})
}

// enrollOptions are the per-agent decisions a scenario makes.
type enrollOptions struct {
	// roots fills allowed_roots. It only confines an agent that also has exec
	// disabled; see jailed.
	roots []string
	// jailed rewrites the enrolled config to turn exec off, which is the one
	// configuration in which the path jail is a boundary rather than a
	// decoration.
	jailed bool
}

// mintToken mints a single-use enrollment token reserving name and authorizing
// address, and returns the token itself.
func (f *fleet) mintToken(name, address string) string {
	f.t.Helper()

	out := runCLI(f.t, bins.fleetctl, []string{
		"enroll", "mint",
		"--name", name,
		"--address", address,
		"--ttl", "10m",
	}, f.ctlEnv())
	return valueAfter(f.t, out, "token:")
}

// enroll mints a token, redeems it with `fleet-agent enroll`, and starts the
// daemon.
//
// Every step is the real command: the token comes out of the token store, the
// CSR is built on the agent's side and never leaves it as a key, and the leaf
// the daemon serves with is the one the control plane signed.
func (f *fleet) enroll(name string, opts enrollOptions) *agent {
	f.t.Helper()

	port := freePort(f.t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	token := f.mintToken(name, addr)

	dir := filepath.Join(f.root, "agents", name)
	home := filepath.Join(f.root, "homes", name)
	for _, d := range []string{dir, home} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			f.t.Fatalf("create %s: %v", d, err)
		}
	}

	env := envWith(
		envEntry("PATH", os.Getenv("PATH")),
		envEntry("HOME", home),
		envEntry("TMPDIR", os.TempDir()),
	)

	args := []string{
		"enroll",
		"--control", f.enrollAddr,
		"--token", token,
		"--ca-fingerprint", f.fingerprint,
		"--dir", dir,
		"--listen", addr,
		"--address", addr,
	}
	for _, root := range opts.roots {
		args = append(args, "--root", root)
	}
	runCLI(f.t, bins.agent, args, env)

	if opts.jailed {
		f.disableExec(filepath.Join(dir, "agent.yaml"))
	}

	a := &agent{
		name: name,
		dir:  dir,
		addr: addr,
		home: home,
		env:  env,
		args: []string{"serve", "--config", filepath.Join(dir, "agent.yaml"), "--log-level", "debug"},
	}
	f.startAgent(a)
	return a
}

// disableExec turns exec off in the config `fleet-agent enroll` wrote, which
// is what puts the path jail in force.
//
// The edit is textual rather than a decode-and-re-encode: the daemon reads this
// file with its own loader, and a test that round-tripped it through a
// hand-written struct would be asserting against its own idea of the schema
// instead of the product's. The exec block is the first `enabled:` in the file
// the enrollment writes, and the check below fails loudly if that stops being
// true rather than silently disabling something else.
func (f *fleet) disableExec(path string) {
	f.t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		f.t.Fatalf("read %s: %v", path, err)
	}
	text := string(data)

	execAt := strings.Index(text, "\nexec:")
	if execAt < 0 {
		f.t.Fatalf("agent.yaml has no exec block:\n%s", text)
	}
	enabledAt := strings.Index(text[execAt:], "enabled: true")
	if enabledAt < 0 {
		f.t.Fatalf("agent.yaml's exec block does not carry `enabled: true`:\n%s", text)
	}
	at := execAt + enabledAt
	text = text[:at] + strings.Replace(text[at:], "enabled: true", "enabled: false", 1)
	writeFile(f.t, path, []byte(text))
}

// startAgent runs the daemon and waits until its listener is accepting.
func (f *fleet) startAgent(a *agent) {
	f.t.Helper()

	a.proc = start(f.t, "fleet-agent "+a.name, bins.agent, a.args, procOptions{env: a.env, dir: a.home})
	waitFor(f.t, 60*time.Second, "agent "+a.name+" to accept connections", func() (bool, string) {
		if !a.proc.running() {
			f.t.Fatalf("agent %s exited during startup:\n%s", a.name, a.proc.stderr())
		}
		if dialable(a.addr) {
			return true, ""
		}
		return false, "nothing listening on " + a.addr
	})
}

// kill ends the daemon without a drain, the way a crash or an OOM kill does.
// Supervised processes are expected to survive it: that is the whole point of
// the re-adoption path.
func (a *agent) kill() { a.proc.kill() }

// stop shuts the daemon down the way a service manager does.
func (a *agent) stop(t *testing.T) { a.proc.terminate(t) }

// restart brings the daemon back with the same config, state directory and
// environment — which is what makes it the same agent rather than a new one.
func (f *fleet) restart(a *agent) {
	f.t.Helper()
	if a.proc.running() {
		a.proc.kill()
	}
	f.startAgent(a)
}

// stateDir is where the supervisor persists its process records.
func (a *agent) stateDir() string { return filepath.Join(a.dir, "state") }

// logs is what the daemon *currently running* has written to stderr.
//
// Not the whole history across restarts, deliberately: an assertion that the
// agent logged something is nearly always an assertion about the agent that is
// answering now, and one that could match a line the previous run wrote would
// pass whether or not this one did anything. The output of the runs before it
// is not lost — each spawn registers a cleanup that prints its own streams when
// the scenario fails.
func (a *agent) logs() string { return a.proc.stderr() }

// writeFile writes a file at 0600, failing the test rather than returning an
// error. Everything this suite writes is either a credential or test data
// beside one, so there is no second mode to pass.
func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// valueAfter pulls the value that follows a labelled prefix in CLI output.
func valueAfter(t *testing.T, out, prefix string) string {
	t.Helper()
	line := lineWith(out, prefix)
	if line == "" {
		t.Fatalf("no %q in output:\n%s", prefix, out)
	}
	return strings.TrimSpace(strings.TrimPrefix(line, prefix))
}

// lineWith returns the first line containing prefix, from prefix onwards.
func lineWith(out, prefix string) string {
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, prefix); i >= 0 {
			return strings.TrimRight(line[i:], "\r")
		}
	}
	return ""
}
