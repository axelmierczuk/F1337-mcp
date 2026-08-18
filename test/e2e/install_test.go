//go:build integration

package e2e

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aymanbagabas/go-pty"
)

// install.sh, driven the way an operator drives it.
//
// #100 is an installer that downloaded a binary and stopped: everything that
// turned that binary into a working fleet member was left to the operator, and
// each piece had to be discovered by hitting the failure it caused. So these
// scenarios drive the questions and then check the answers reached the machine
// — the config the daemon actually starts with, the command the operator
// actually pastes on their workstation — rather than checking that a prompt was
// printed.
//
// Nothing here is timed. The one wait is for a prompt to appear on a terminal,
// which [waitFor] polls for, and the assertions that follow are about files on
// disk, an exit status, and what a second process saw.
//
// What no runner can drive is the other half: registering a service needs root
// and a service manager, and a Windows host needs Windows. Those steps are in
// docs/service.md under Manual verification, and install.tests.ps1 asserts the
// Windows decisions that can be made without one.

// installerVersion is the release the installer is told to fetch. Explicit in
// every scenario, so nothing here asks github.com what "latest" is.
const installerVersion = "v0.1.0"

// releaseServer is what a GitHub release serves: an archive and the checksum
// file published beside it.
//
// hits counts what was fetched, which is how a scenario asserts that a refusal
// came *before* the download rather than after it. An installer that refused
// an unsafe listen address only once the binary was on disk would have left the
// operator with an install to undo.
type releaseServer struct {
	url  string
	hits *atomic.Int32
}

// startReleaseServer publishes the agent this suite built as a release.
//
// The real binary, not a stand-in: the config the installer writes is checked
// by starting a daemon with it, and the service refusal a scenario asserts is
// the agent's own.
func startReleaseServer(t *testing.T, tamper bool) *releaseServer {
	t.Helper()

	archive := archiveOfAgent(t)
	name := fmt.Sprintf("fleet-agent_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	published := sha256.Sum256(archive)
	if tamper {
		// The checksum is of what was published; what is served is not that.
		// This is the shape the check exists for — a mirror that answered with
		// something else — and it is asserted rather than assumed because the
		// download block was rewritten around it.
		archive = append(archive, byte('x'))
	}

	var hits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/download/"+installerVersion+"/"+name, func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write(archive)
	})
	mux.HandleFunc("/download/"+installerVersion+"/checksums.txt", func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = fmt.Fprintf(w, "%x  %s\n", published, name)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &releaseServer{url: srv.URL, hits: &hits}
}

// archiveOfAgent packs the built agent the way the release workflow does.
func archiveOfAgent(t *testing.T) []byte {
	t.Helper()

	binary, err := os.ReadFile(bins.agent)
	if err != nil {
		t.Fatalf("read the built agent: %v", err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	header := &tar.Header{
		Name:     "fleet-agent",
		Mode:     0o755,
		Size:     int64(len(binary)),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(header); err != nil {
		t.Fatalf("write the archive header: %v", err)
	}
	if _, err := tw.Write(binary); err != nil {
		t.Fatalf("write the archive: %v", err)
	}
	for _, closer := range []func() error{tw.Close, gz.Close} {
		if err := closer(); err != nil {
			t.Fatalf("close the archive: %v", err)
		}
	}
	return buf.Bytes()
}

// installer is one invocation of install.sh, with somewhere of its own to
// install into.
type installer struct {
	t          *testing.T
	release    *releaseServer
	home       string
	installDir string
	configDir  string
	// hostTools holds the stubs that answer "what addresses does this host
	// have", when a scenario needs that answer to be the same everywhere.
	hostTools string
}

func newInstaller(t *testing.T, release *releaseServer) *installer {
	t.Helper()

	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatalf("create the installing account's home: %v", err)
	}
	return &installer{
		t:          t,
		release:    release,
		home:       home,
		installDir: filepath.Join(root, "bin"),
		configDir:  filepath.Join(root, "config"),
	}
}

func (i *installer) env() []string {
	path := os.Getenv("PATH")
	if i.hostTools != "" {
		path = i.hostTools + string(os.PathListSeparator) + path
	}
	return envWith(
		envEntry("PATH", path),
		envEntry("HOME", i.home),
		envEntry("TMPDIR", os.TempDir()),
		envEntry("TERM", operatorTerm),
	)
}

// withHostAddresses puts a host with known addresses in front of the installer.
//
// The script asks the operating system what addresses this machine has, and no
// runner can be made to have a tailnet address, a public address and an RFC
// 1918 address at once -- so the answer is stubbed where the script asks for
// it, by putting `ip`, `ifconfig` and `tailscale` on its PATH. Everything the
// installer then does with that answer -- the order, the labels, which one
// pressing return chooses -- is its own.
//
// Both `ip` and `ifconfig` are supplied, in their own output formats, because
// the script prefers whichever it finds: this is the only place either parser
// is exercised on a machine that does not have that tool.
func (i *installer) withHostAddresses() *installer {
	i.t.Helper()

	dir := filepath.Join(i.t.TempDir(), "host-tools")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		i.t.Fatalf("create the stub tool directory: %v", err)
	}
	for name, body := range map[string]string{
		"ip":        stubIP,
		"ifconfig":  stubIfconfig,
		"tailscale": stubTailscale,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			i.t.Fatalf("write the stub %s: %v", name, err)
		}
	}
	i.hostTools = dir
	return i
}

// The addresses the stubs report, in the order they are reported in -- which is
// deliberately not the order the installer must offer them in.
const (
	stubTailnetAddress = "100.83.4.17"
	stubCarrierAddress = "100.100.20.5"
	stubPrivateAddress = "192.168.1.20"
	stubPublicAddress  = "203.0.113.9"
)

const stubIP = `#!/bin/sh
cat <<'ADDRESSES'
1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
2: eth1    inet 203.0.113.9/24 brd 203.0.113.255 scope global eth1\       valid_lft forever
3: eth0    inet 192.168.1.20/24 brd 192.168.1.255 scope global eth0\       valid_lft forever
4: cgnat0    inet 100.100.20.5/10 scope global cgnat0\       valid_lft forever
5: tailscale0    inet 100.83.4.17/32 scope global tailscale0\       valid_lft forever
ADDRESSES
`

const stubIfconfig = `#!/bin/sh
cat <<'ADDRESSES'
lo: flags=8049<UP,LOOPBACK,RUNNING> mtu 65536
	inet 127.0.0.1 netmask 0xff000000
eth1: flags=8863<UP,BROADCAST,RUNNING> mtu 1500
	inet 203.0.113.9 netmask 0xffffff00 broadcast 203.0.113.255
eth0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500
	inet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255
cgnat0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500
	inet 100.100.20.5 netmask 0xffc00000
tailscale0: flags=8863<UP,POINTOPOINT,RUNNING> mtu 1280
	inet 100.83.4.17 netmask 0xffffffff
ADDRESSES
`

const stubTailscale = `#!/bin/sh
[ "$1" = "ip" ] || exit 1
echo 100.83.4.17
`

// argv is the command line, with the flags every scenario needs: where the
// release is, which one, and somewhere to put it that is not this machine's
// /usr/local/bin.
func (i *installer) argv(extra ...string) []string {
	base := []string{
		filepath.Join(repoRoot, "install.sh"),
		"--base-url", i.release.url,
		"--version", installerVersion,
		"--install-dir", i.installDir,
		"--config-dir", i.configDir,
	}
	return append(base, extra...)
}

func (i *installer) binary() string     { return filepath.Join(i.installDir, "fleet-agent") }
func (i *installer) configPath() string { return filepath.Join(i.configDir, "agent.yaml") }

func (i *installer) installedBinary() bool { return exists(i.binary()) }
func (i *installer) wroteConfig() bool     { return exists(i.configPath()) }

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// run drives the installer with no terminal at all, which is the path
// `curl | sh -s -- ...`, CI and every provisioning script take.
//
// stdin is /dev/null rather than a pipe left open, because "no terminal" is the
// condition under test: a run that blocked here waiting for an answer would be
// the failure, and the deadline turns that into a report rather than a hung
// suite.
func (i *installer) run(extra ...string) (string, error) {
	i.t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/bin/sh", i.argv(extra...)...)
	cmd.Env = i.env()
	cmd.Stdin = nil
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		i.t.Fatalf("install.sh never finished without a terminal; it must take the non-interactive path rather than wait for an answer. It had said:\n%s", out)
	}
	return string(out), err
}

// installerTerminalScript is what the shell on the pseudo-terminal runs.
//
// The installer under a shell rather than on its own, for the reason
// startup_test.go gives: the shell is the session leader, so macOS does not
// revoke the terminal the moment the installer exits, and it outlives it — so
// the exit status is written *to the terminal*, where a scenario that has just
// watched a refusal can read it.
const installerTerminalScript = `
printf 'READY\n'
sh "$@"
printf 'EXIT[%d]\n' "$?"
`

// installerTerminal is an installer running on a terminal that says nothing it is not
// told to say.
type installerTerminal struct {
	t    *testing.T
	pty  pty.Pty
	out  *syncBuffer
	done chan struct{}
}

// startOnATerminal runs install.sh on a fresh pseudo-terminal whose only writer
// is this test.
func (i *installer) startOnATerminal(extra ...string) *installerTerminal {
	i.t.Helper()

	term, err := pty.New()
	if err != nil {
		i.t.Fatalf("allocate a pseudo-terminal: %v", err)
	}
	if err := term.Resize(100, 40); err != nil {
		i.t.Fatalf("size the pseudo-terminal: %v", err)
	}

	run := &installerTerminal{t: i.t, pty: term, out: &syncBuffer{}, done: make(chan struct{})}
	args := append([]string{"-c", installerTerminalScript, "sh"}, i.argv(extra...)...)
	cmd := term.Command("/bin/sh", args...)
	cmd.Env = i.env()
	if err := cmd.Start(); err != nil {
		i.t.Fatalf("start install.sh on a pseudo-terminal: %v", err)
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, readErr := term.Read(buf)
			if n > 0 {
				_, _ = run.out.Write(buf[:n])
			}
			if readErr != nil {
				return
			}
		}
	}()
	go func() {
		defer close(run.done)
		_ = cmd.Wait()
	}()

	i.t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		select {
		case <-run.done:
		case <-time.After(30 * time.Second):
		}
		_ = term.Close()
		if i.t.Failed() {
			i.t.Logf("the terminal received:\n%s", run.received())
		}
	})
	return run
}

func (r *installerTerminal) received() string { return r.out.String() }

// await waits for the terminal to have received want.
func (r *installerTerminal) await(what, want string) {
	r.t.Helper()
	waitFor(r.t, 90*time.Second, what, func() (bool, string) {
		if strings.Contains(r.received(), want) {
			return true, ""
		}
		return false, "the terminal has received:\n" + r.received()
	})
}

// answer types a line, as an operator does.
func (r *installerTerminal) answer(text string) {
	r.t.Helper()
	if _, err := r.pty.Write([]byte(text + "\r")); err != nil {
		r.t.Fatalf("type into the terminal: %v", err)
	}
}

// endInput closes the input the way Ctrl-D does: nothing was typed, and there
// is nothing more coming.
func (r *installerTerminal) endInput() {
	r.t.Helper()
	if _, err := r.pty.Write([]byte{4}); err != nil {
		r.t.Fatalf("end the terminal's input: %v", err)
	}
}

// exitStatus waits for the installer to finish and returns what it exited with.
func (r *installerTerminal) exitStatus() int {
	r.t.Helper()
	r.await("install.sh to exit", "EXIT[")
	text := r.received()
	start := strings.LastIndex(text, "EXIT[") + len("EXIT[")
	end := strings.Index(text[start:], "]")
	if end < 0 {
		r.t.Fatalf("install.sh's exit status never arrived; the terminal received:\n%s", text)
	}
	code, err := strconv.Atoi(text[start : start+end])
	if err != nil {
		r.t.Fatalf("install.sh's exit status was not a number: %v", err)
	}
	return code
}

// The whole of #100 as an operator meets it: an installer that asks, and a host
// that is a fleet member when it finishes.
//
// Every answer is checked where it landed rather than where it was typed. The
// listen address ends up in the config a real daemon then starts with, the name
// ends up in the command printed for the workstation, and that command — run
// here, as an operator would — registers a host the fleet can reach.
func TestInstallerAsksAndTheAnswersReachTheConfigAndTheFleet(t *testing.T) {
	requireSupportedHost(t)

	release := startReleaseServer(t, false)
	inst := newInstaller(t, release)
	port := freePort(t)
	listen := fmt.Sprintf("127.0.0.1:%d", port)

	run := inst.startOnATerminal()
	run.await("the shell to reach the installer", "READY")

	// Nothing on the command line said which posture to configure, so it is
	// asked — with the consequence of each, which is the whole of what an
	// operator is deciding here.
	run.await("the posture question", "Authentication [1 or 2]")
	for _, want := range []string{
		"1) mTLS.",
		"2) None. The agent authenticates nobody",
		"can run commands on this host",
	} {
		if !contains(run.received(), want) {
			t.Fatalf("the posture question does not say %q:\n%s", want, run.received())
		}
	}
	run.answer("2")

	// The addresses this host has, labelled by what can reach them. The menu is
	// the answer to "0.0.0.0 is the obvious thing to type": with mTLS off it is
	// not on it.
	// Waited for to the end of the menu rather than to the question: the
	// addresses are written after it, and asserting on the first line to arrive
	// would be asserting on whatever the terminal happened to hold.
	run.await("the listen question", "Which address should the agent serve on?")
	run.await("the addresses this host has", "0) something else")
	menu := run.received()
	if !contains(menu, "loopback - reachable only from this host") {
		t.Fatalf("the address menu does not label loopback:\n%s", menu)
	}
	if contains(menu, "0.0.0.0:8722") {
		t.Fatalf("the address menu offered a wildcard bind to an agent that authenticates nobody, which is exactly what #85's guard refuses:\n%s", menu)
	}
	run.answer("0")
	run.await("the free-text address question", "Address as host:port")
	run.answer(listen)

	run.await("the name question", "Sandbox name")
	run.answer("installed-box")

	run.await("the plan", "fleet-agent, on this host:")
	run.await("the confirmation", "Proceed?")
	run.answer("yes")

	if code := run.exitStatus(); code != 0 {
		t.Fatalf("install.sh exited %d:\n%s", code, run.received())
	}

	// It said what it did, and it did not claim a service it did not register.
	said := run.received()
	for _, want := range []string{
		"checksum ok",
		"installed " + inst.binary(),
		"wrote " + inst.configPath(),
		"Installed and configured. Nothing is running",
	} {
		if !contains(said, want) {
			t.Fatalf("install.sh never said %q:\n%s", want, said)
		}
	}

	if !inst.installedBinary() {
		t.Fatalf("install.sh reported success and there is no binary at %s", inst.binary())
	}
	config := readInstalledConfig(t, inst)
	for _, want := range []string{
		`name: "installed-box"`,
		fmt.Sprintf("listen: %q", listen),
		"enabled: false",
	} {
		if !contains(config, want) {
			t.Fatalf("the config install.sh wrote does not carry the answers (%q missing):\n%s", want, config)
		}
	}

	// Item 9: the command to finish the job, ready to paste, with this host's
	// name and address already in it.
	wantCommand := fmt.Sprintf("fleetctl add installed-box --address %s --insecure", listen)
	if !contains(said, wantCommand) {
		t.Fatalf("install.sh did not print the command that registers this host (%q):\n%s", wantCommand, said)
	}

	// And the answers work. A daemon started with exactly the file the
	// installer wrote, and then the line it printed, run here.
	daemon := start(t, "fleet-agent installed-box", bins.agent,
		[]string{"serve", "--config", inst.configPath()},
		procOptions{env: inst.env(), dir: inst.home})
	waitFor(t, 60*time.Second, "the installed agent to accept connections", func() (bool, string) {
		if !daemon.running() {
			t.Fatalf("the daemon started with the config install.sh wrote exited:\n%s", daemon.stderr())
		}
		if dialable(listen) {
			return true, ""
		}
		return false, "nothing listening on " + listen
	})

	ctlDir := filepath.Join(t.TempDir(), "workstation")
	ctlEnv := envWith(
		envEntry("FLEET_CONFIG_DIR", ctlDir),
		envEntry("PATH", os.Getenv("PATH")),
		envEntry("HOME", ctlDir),
		envEntry("TMPDIR", os.TempDir()),
	)
	added := runCLI(t, bins.fleetctl,
		[]string{"add", "installed-box", "--address", listen, "--insecure"}, ctlEnv)
	if !contains(added, "health serving") {
		t.Fatalf("`%s` did not find a serving agent:\n%s", wantCommand, added)
	}
}

// What the operator is offered, and what they get for pressing return.
//
// This is the heart of #100's first bullet: the addresses are enumerated,
// labelled by what can reach them, and a tailnet address is offered first
// because on a host that has one it is almost always the answer. The host's own
// addresses are stubbed -- no runner has a tailnet -- and everything asserted
// below is what the installer did with them.
//
// The default matters as much as the order. An operator who answers nothing
// gets the tailnet address; what they must never get is the public one or a
// wildcard, which is the failure this whole question exists to remove.
func TestInstallerOffersTheTailnetAddressFirstAndDefaultsToNothingUnsafe(t *testing.T) {
	requireSupportedHost(t)

	release := startReleaseServer(t, false)
	inst := newInstaller(t, release).withHostAddresses()

	run := inst.startOnATerminal("--no-mtls")
	run.await("the shell to reach the installer", "READY")
	run.await("the listen question", "Which address should the agent serve on?")
	run.await("the addresses this host has", "0) something else")

	// The order, as an operator reads it down the screen.
	offered := offeredAddresses(t, run.received())
	want := []string{
		stubTailnetAddress + ":8722",
		stubCarrierAddress + ":8722",
		stubPrivateAddress + ":8722",
		"127.0.0.1:8722",
		stubPublicAddress + ":8722",
	}
	if len(offered) != len(want) {
		t.Fatalf("the menu offers %d addresses, want %d:\n%s", len(offered), len(want), run.received())
	}
	for i := range want {
		if offered[i] != want[i] {
			t.Fatalf("the menu offers %v, want %v (the tailnet address first, the public one last):\n%s",
				offered, want, run.received())
		}
	}
	for _, want := range []string{
		"tailscale0, Tailscale - private to your tailnet",
		"cgnat0, carrier-grade NAT (100.64.0.0/10)",
		"eth0, private (RFC 1918)",
		"lo, loopback - reachable only from this host",
		"eth1, PUBLIC - reachable from anywhere that routes to it",
	} {
		if !contains(run.received(), want) {
			t.Fatalf("the menu does not say %q, so nothing tells the operator who can reach what:\n%s", want, run.received())
		}
	}

	// The default the prompt offers, before anything is typed at it: the first
	// entry, which the order above makes the tailnet address. Asserted here as
	// well as through the config below, so that a default that had moved is
	// reported as a moved default rather than as a question that never arrived.
	run.await("the address prompt", "Address [")
	if !contains(run.received(), "Address [1]:") {
		t.Fatalf("the address prompt does not default to the first offer, which is the only one it may default to:\n%s", run.received())
	}

	// Nothing is typed. The answer is whatever pressing return gives, and that
	// is the assertion: it is the tailnet address, and it is not the public one.
	run.answer("")
	run.await("the name question", "Sandbox name")
	run.answer("stub-box")
	run.await("the confirmation", "Proceed?")
	run.answer("yes")

	if code := run.exitStatus(); code != 0 {
		t.Fatalf("install.sh exited %d:\n%s", code, run.received())
	}
	config := readInstalledConfig(t, inst)
	if !contains(config, `listen: "`+stubTailnetAddress+`:8722"`) {
		t.Fatalf("pressing return did not choose the tailnet address:\n%s", config)
	}
	if contains(config, stubPublicAddress) || contains(config, "0.0.0.0") {
		t.Fatalf("pressing return chose an address anyone can reach:\n%s", config)
	}
	if !contains(run.received(), "fleetctl add stub-box --address "+stubTailnetAddress+":8722 --insecure") {
		t.Fatalf("the command printed for the workstation does not name the address chosen:\n%s", run.received())
	}
}

// offeredAddresses reads the addresses out of the menu, in the order they were
// printed.
func offeredAddresses(t *testing.T, screen string) []string {
	t.Helper()

	var found []string
	for _, line := range strings.Split(screen, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || !strings.HasSuffix(fields[0], ")") {
			continue
		}
		if fields[0] == "0)" || !strings.Contains(fields[1], ":") {
			continue
		}
		found = append(found, fields[1])
	}
	return found
}

// The refusal that removes failure 6, and the point in the run it happens at.
//
// `listen: 0.0.0.0` with mTLS off is what the daemon's own guard refuses, and
// through a service manager that refusal reaches an operator as a start that
// timed out. So the installer refuses it itself — before the download, which is
// what the untouched release server proves.
func TestInstallerRefusesAListenAddressTheAgentWouldNotStartOn(t *testing.T) {
	requireSupportedHost(t)

	release := startReleaseServer(t, false)
	inst := newInstaller(t, release)

	out, err := inst.run("--no-mtls", "--listen", "0.0.0.0:8722")
	if err == nil {
		t.Fatalf("install.sh accepted a wildcard listen address for an agent that authenticates nobody:\n%s", out)
	}
	for _, want := range []string{
		"binds every interface on this host",
		"this agent authenticates nobody",
		"listen on a loopback or private address",
	} {
		if !contains(out, want) {
			t.Fatalf("the refusal does not say %q:\n%s", want, out)
		}
	}
	if hits := release.hits.Load(); hits != 0 {
		t.Fatalf("install.sh made %d request(s) to the release server before refusing; the refusal is worth having only if it comes before the download:\n%s", hits, out)
	}
	if inst.installedBinary() || inst.wroteConfig() {
		t.Fatalf("install.sh refused and left something behind at %s:\n%s", inst.installDir, out)
	}

	// The same address is not refused for an agent that authenticates every
	// caller by certificate, which is the posture `fleetctl enroll mint` prints
	// this exact address for. A check that refused it there would refuse the
	// command this product tells operators to paste.
	mtls := newInstaller(t, release)
	out, err = mtls.run("--token", "sbx_no-control-plane-here", "--control", "127.0.0.1:1",
		"--ca-fingerprint", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"--listen", "0.0.0.0:8722")
	if err == nil {
		t.Fatalf("enrollment against a control plane that does not exist should have failed:\n%s", out)
	}
	if contains(out, "binds every interface on this host") {
		t.Fatalf("install.sh refused a wildcard bind for an enrolled agent, which is the address `fleetctl enroll mint` prints:\n%s", out)
	}
	if !mtls.installedBinary() {
		t.Fatalf("the mTLS run should have got as far as installing the binary before enrollment failed:\n%s", out)
	}
}

// The other posture, all the way through: an installer that enrolls.
//
// Every step is the real one -- a real token out of the token store, a real
// handshake against a real control plane, the leaf the CA signed -- and what is
// asserted at the end is that the workstation reaches the host, over mTLS, at
// the address its certificate had to name.
//
// Two tokens, because item 8 in #100 is the difference between them. A token
// minted with --address already says what the control plane dials, and both the
// certificate and the fleet entry come from it. A token that authorized none
// records whatever the *agent* asked for -- so an installer that passes nothing
// there enrolls a host into the fleet with no address at all, which is the
// "registered agent nobody can reach" that issue names.
func TestInstallerEnrollsAndTheFleetReachesTheHost(t *testing.T) {
	f := newFleet(t)
	release := startReleaseServer(t, false)

	t.Run("the token the enroll mint command authorizes an address", func(t *testing.T) {
		inst := newInstaller(t, release)
		listen := fmt.Sprintf("127.0.0.1:%d", freePort(t))
		token := f.mintToken("minted-with-address", listen)

		out, err := inst.run(
			"--token", token,
			"--control", f.enrollAddr,
			"--ca-fingerprint", f.fingerprint,
			"--listen", listen,
		)
		if err != nil {
			t.Fatalf("install.sh could not enroll: %v\n%s", err, out)
		}
		if !contains(out, "enrolling with "+f.enrollAddr) {
			t.Fatalf("install.sh did not say it was enrolling:\n%s", out)
		}

		// The config enrollment wrote, at the path the installer chose, in the
		// posture it asked for.
		config := readInstalledConfig(t, inst)
		for _, want := range []string{
			"enabled: true",
			fmt.Sprintf("listen: %s", listen),
			"agent.crt",
			"ca.crt",
		} {
			if !contains(config, want) {
				t.Fatalf("the config enrollment wrote does not carry %q:\n%s", want, config)
			}
		}

		// Nothing was told to add this host: enrollment registered it, which
		// the installer says rather than printing an `add` nobody needs.
		if !contains(out, "Enrollment registered this host") {
			t.Fatalf("install.sh does not say enrollment registered this host:\n%s", out)
		}
		if contains(out, "--insecure") {
			t.Fatalf("install.sh told an enrolled host to register itself as unauthenticated:\n%s", out)
		}

		serveAndFind(t, f, inst, "minted-with-address", listen)
	})

	t.Run("a token that authorized no address at all", func(t *testing.T) {
		inst := newInstaller(t, release)
		listen := fmt.Sprintf("127.0.0.1:%d", freePort(t))

		// Minted without --address, which `fleetctl enroll mint` warns about
		// and allows: the leaf then names only the sandbox, and the fleet entry
		// is built from what the enrolling host asks for.
		minted := runCLI(t, bins.fleetctl, []string{
			"enroll", "mint", "--name", "minted-without-address", "--ttl", "10m",
		}, f.ctlEnv())
		token := valueAfter(t, minted, "token:")

		out, err := inst.run(
			"--token", token,
			"--control", f.enrollAddr,
			"--ca-fingerprint", f.fingerprint,
			"--listen", listen,
			"--address", listen,
		)
		if err != nil {
			t.Fatalf("install.sh could not enroll: %v\n%s", err, out)
		}
		serveAndFind(t, f, inst, "minted-without-address", listen)
	})
}

// serveAndFind starts a daemon with the config the installer wrote and requires
// the workstation to find it, over mTLS, at the address it was installed for.
//
// `fleetctl list` is the whole assertion: it reads the registry the enrollment
// wrote, dials each entry at the address recorded there, and verifies the leaf
// against the host it dialled. An entry with no address, or a leaf that does not
// name the one it has, fails here.
func serveAndFind(t *testing.T, f *fleet, inst *installer, name, listen string) {
	t.Helper()

	daemon := start(t, "fleet-agent "+name, bins.agent,
		[]string{"serve", "--config", inst.configPath()},
		procOptions{env: inst.env(), dir: inst.home})
	waitFor(t, 60*time.Second, "the enrolled agent to accept connections", func() (bool, string) {
		if !daemon.running() {
			t.Fatalf("the daemon started with the config install.sh wrote exited:\n%s", daemon.stderr())
		}
		if dialable(listen) {
			return true, ""
		}
		return false, "nothing listening on " + listen
	})

	list := runCLI(t, bins.fleetctl, []string{"list"}, f.ctlEnv())
	line := ""
	for _, l := range strings.Split(list, "\n") {
		if strings.Contains(l, name) {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatalf("`fleetctl list` does not hold the host install.sh enrolled:\n%s", list)
	}
	if !strings.Contains(line, listen) {
		t.Fatalf("`fleetctl list` records %s at some other address than the one it was installed for (%s), so nothing can dial it:\n%s", name, listen, list)
	}
	if !strings.Contains(line, "mtls") {
		t.Fatalf("`fleetctl list` does not report %s as authenticated:\n%s", name, list)
	}
	if !strings.Contains(line, "serving") {
		t.Fatalf("`fleetctl list` could not reach %s at %s, which is what a leaf that does not name that address looks like:\n%s", name, listen, list)
	}
}

// #73's fixture, pointed at this installer: a terminal that answers nothing.
//
// Two things must hold, and neither is a duration. The question must be asked
// and then waited on — an installer that timed out into a default would have
// gone on to install, which the release server would have seen. And when the
// input ends, the run must refuse and name the flag that answers it without a
// terminal, rather than picking something.
func TestInstallerOnATerminalThatAnswersNothing(t *testing.T) {
	requireSupportedHost(t)

	release := startReleaseServer(t, false)
	inst := newInstaller(t, release)

	run := inst.startOnATerminal()
	run.await("the shell to reach the installer", "READY")
	run.await("the posture question", "Authentication [1 or 2]")

	// Nothing is typed. The input ends instead, which is the terminal going
	// away underneath a question.
	run.endInput()

	if code := run.exitStatus(); code == 0 {
		t.Fatalf("install.sh exited 0 having never been answered:\n%s", run.received())
	}
	said := run.received()
	for _, want := range []string{
		"no answer",
		"--token or --no-mtls",
	} {
		if !contains(said, want) {
			t.Fatalf("the refusal does not say %q, so it does not say how to run this without a terminal:\n%s", want, said)
		}
	}
	if hits := release.hits.Load(); hits != 0 {
		t.Fatalf("install.sh downloaded something for a run nobody answered (%d request(s)):\n%s", hits, said)
	}
	if inst.installedBinary() || inst.wroteConfig() {
		t.Fatalf("install.sh installed something for a run nobody answered:\n%s", said)
	}
}

// The other half of the same rule: no terminal at all is not a reason to block,
// and a missing answer there is an error naming the flag rather than a wait.
//
// This is the path CI takes, and #73 is what happens when a program decides a
// terminal it cannot see is worth waiting on.
func TestInstallerWithoutATerminalSaysWhichFlagIsMissing(t *testing.T) {
	requireSupportedHost(t)

	release := startReleaseServer(t, false)

	cases := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "no listen address for an agent that authenticates nobody",
			args: []string{"--no-mtls"},
			want: []string{"--listen is required with --no-mtls", "no safe default"},
		},
		{
			name: "a token with no control address",
			args: []string{"--token", "sbx_abc"},
			want: []string{"--control"},
		},
		{
			name: "a token with no pinned CA",
			args: []string{"--token", "sbx_abc", "--control", "workstation:9443"},
			want: []string{"--ca-fingerprint", "fleetctl ca fingerprint"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inst := newInstaller(t, release)
			out, err := inst.run(tc.args...)
			if err == nil {
				t.Fatalf("install.sh went ahead with an unanswered question:\n%s", out)
			}
			for _, want := range tc.want {
				if !contains(out, want) {
					t.Fatalf("the error does not name %q:\n%s", want, out)
				}
			}
			if inst.installedBinary() || inst.wroteConfig() {
				t.Fatalf("install.sh left something behind after refusing:\n%s", out)
			}
		})
	}
}

// A name the fleet cannot hold is refused where it is still cheap.
//
// The installer ends by printing `fleetctl add <name> --address ...` for the
// operator to paste, so a name with a space in it is not a cosmetic problem: it
// is a command that cannot run, discovered on the workstation, after the host
// has been installed and configured. The rule is the registry's, and the second
// half of this asserts that -- a refusal stricter than the fleet's own would
// turn away names that work.
func TestInstallerRefusesANameTheFleetCannotHold(t *testing.T) {
	requireSupportedHost(t)

	release := startReleaseServer(t, false)
	inst := newInstaller(t, release)

	out, err := inst.run("--no-mtls", "--listen", "127.0.0.1:8722", "--name", "build box")
	if err == nil {
		t.Fatalf("install.sh accepted a name the fleet cannot hold:\n%s", out)
	}
	if !contains(out, "is not a name this fleet can hold") {
		t.Fatalf("install.sh refused for some other reason:\n%s", out)
	}
	if !contains(out, "printable ASCII with no spaces") {
		t.Fatalf("the refusal does not say what a name may be:\n%s", out)
	}
	if hits := release.hits.Load(); hits != 0 {
		t.Fatalf("install.sh downloaded %d thing(s) before refusing a name it could have refused first:\n%s", hits, out)
	}
	if inst.installedBinary() || inst.wroteConfig() {
		t.Fatalf("install.sh refused and left something behind:\n%s", out)
	}

	// The same name, at the command the installer would have printed. If this
	// ever succeeds, the installer is refusing a name the fleet would have
	// taken.
	ctlDir := filepath.Join(t.TempDir(), "workstation")
	ctlEnv := envWith(
		envEntry("FLEET_CONFIG_DIR", ctlDir),
		envEntry("PATH", os.Getenv("PATH")),
		envEntry("HOME", ctlDir),
		envEntry("TMPDIR", os.TempDir()),
	)
	added, addErr := tryCLI(bins.fleetctl,
		[]string{"add", "build box", "--address", "127.0.0.1:8722", "--insecure", "--no-probe"}, ctlEnv)
	if addErr == nil {
		t.Fatalf("`fleetctl add` accepted a name install.sh refused, so the installer is stricter than the fleet:\n%s", added)
	}
}

// A registration that fails is a failed install, not a warning.
//
// Until #100 this was a warning and the installer went on to print "done. This
// host should now appear in fleet_list", which left an operator with a host
// they believed had joined the fleet and a service that had never been written.
// The refusal here is the agent's own — `service install` needs root — which is
// also why the scenario skips when it has it.
func TestInstallerDoesNotClaimSuccessWhenRegistrationFails(t *testing.T) {
	requireSupportedHost(t)
	if os.Geteuid() == 0 {
		t.Skip("this scenario needs `service install` to refuse, and as root it would register a service on the machine running the tests")
	}

	release := startReleaseServer(t, false)
	inst := newInstaller(t, release)

	out, err := inst.run("--no-mtls", "--listen", "127.0.0.1:8722", "--service", "yes")
	if err == nil {
		t.Fatalf("install.sh reported success for a registration that failed:\n%s", out)
	}
	if !contains(out, "needs root") {
		t.Fatalf("install.sh did not pass on why registration failed:\n%s", out)
	}
	for _, forbidden := range []string{
		"Installed, configured, running",
		"fleetctl add",
	} {
		if contains(out, forbidden) {
			t.Fatalf("install.sh said %q about a host with no service registered:\n%s", forbidden, out)
		}
	}
	// And it said so about a host it had already changed, which is what makes
	// "fix the cause above and run" the right instruction.
	if !inst.installedBinary() || !inst.wroteConfig() {
		t.Fatalf("install.sh failed before writing the binary and config it tells the operator to register:\n%s", out)
	}
	if !contains(out, "service install --config "+inst.configPath()) {
		t.Fatalf("install.sh did not print the command that finishes the job:\n%s", out)
	}
}

// `curl -fsSL ... | sh`, with nothing else. It installs the binary and stops,
// which is what the README's "put the agent on the sandbox host" step is, and
// what every host that ran it before #100 got.
//
// It keeps working because an install that started guessing at a posture would
// be guessing about who may run commands on the machine.
func TestInstallerWithNoArgumentsInstallsTheBinaryAndSaysWhatIsLeft(t *testing.T) {
	requireSupportedHost(t)

	release := startReleaseServer(t, false)
	inst := newInstaller(t, release)

	out, err := inst.run()
	if err != nil {
		t.Fatalf("install.sh failed with no arguments and no terminal: %v\n%s", err, out)
	}
	if !inst.installedBinary() {
		t.Fatalf("install.sh installed nothing:\n%s", out)
	}
	if inst.wroteConfig() {
		t.Fatalf("install.sh wrote a config for a run that was never told which posture to configure:\n%s", out)
	}
	for _, want := range []string{
		"Installed. Nothing else was configured",
		"--no-mtls --listen",
		"--token <enrollment-token>",
	} {
		if !contains(out, want) {
			t.Fatalf("install.sh does not say %q, so nothing tells the operator what is left:\n%s", want, out)
		}
	}
}

// The one security property this script has: it will not install an artifact
// whose checksum is not the published one.
func TestInstallerRefusesAnArchiveTheChecksumDoesNotMatch(t *testing.T) {
	requireSupportedHost(t)

	release := startReleaseServer(t, true)
	inst := newInstaller(t, release)

	out, err := inst.run("--no-mtls", "--listen", "127.0.0.1:8722")
	if err == nil {
		t.Fatalf("install.sh installed an archive that does not match its published checksum:\n%s", out)
	}
	if !contains(out, "checksum mismatch") {
		t.Fatalf("install.sh failed for some other reason than the checksum:\n%s", out)
	}
	if inst.installedBinary() {
		t.Fatalf("install.sh installed the binary it had just refused:\n%s", out)
	}
}

func readInstalledConfig(t *testing.T, inst *installer) string {
	t.Helper()

	data, err := os.ReadFile(inst.configPath())
	if err != nil {
		t.Fatalf("read the config install.sh wrote: %v", err)
	}
	return string(data)
}
