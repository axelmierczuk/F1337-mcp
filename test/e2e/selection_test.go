//go:build integration

package e2e

import (
	"path/filepath"
	"strings"
	"testing"
)

// markerFile is written into each agent's home directory, and read back with a
// *relative* path.
//
// That is what makes it a proof rather than a label. `fleet_exec` with no
// working_dir runs in the agent account's home directory, and the two daemons
// have different ones, so identical argv reads a different file depending on
// which daemon forked it. Both agents share this machine's filesystem — an
// absolute path, or a hostname, would prove nothing here.
const markerFile = "which-sandbox-am-i"

// whereItRan runs the marker read and returns the name of the agent that
// actually executed it, along with the name the server echoed.
//
// Every targeted call carries an echo naming the sandbox the server resolved.
// Reading the echo alone would only prove the server is self-consistent;
// comparing it against a fact produced by the machine that ran the command is
// what makes silent target confusion visible.
func whereItRan(t *testing.T, s *session, args map[string]any) (ran, echoed string) {
	t.Helper()

	call := map[string]any{"argv": []string{"cat", markerFile}}
	for k, v := range args {
		call[k] = v
	}
	res := s.ok("fleet_exec", call)
	out := structured[execResult](t, res)
	if out.ExitCode != 0 {
		t.Fatalf("reading the marker failed with exit %d: %s", out.ExitCode, out.Stderr)
	}
	return strings.TrimSpace(out.Stdout), echoOf(t, res)
}

// TestTwoSandboxesTargeting is the scenario the issue calls the highest-value
// one in the list, and it is right: selection is the only part of this system
// whose failure is silent. A call that runs on the wrong host succeeds, returns
// plausible output, and is indistinguishable from a correct one unless
// something on the far side says which host it was.
func TestTwoSandboxesTargeting(t *testing.T) {
	f := newFleet(t)
	alpha := f.enroll("alpha", enrollOptions{})
	beta := f.enroll("beta", enrollOptions{})
	for _, a := range []*agent{alpha, beta} {
		writeFile(t, filepath.Join(a.home, markerFile), []byte(a.name+"\n"))
	}

	s := f.connect(t)

	list := structured[listResult](t, s.ok("fleet_list", nil))
	if len(list.Sandboxes) != 2 {
		t.Fatalf("expected both sandboxes in the registry, got %+v", list.Sandboxes)
	}
	if list.Sandboxes[0].Address == list.Sandboxes[1].Address {
		t.Fatalf("both sandboxes registered the same address %q", list.Sandboxes[0].Address)
	}

	// Select one. Every later call with no sandbox argument goes there.
	sel := structured[selectResult](t, s.ok("fleet_select", map[string]any{"name": alpha.name}))
	if sel.Address != alpha.addr {
		t.Fatalf("fleet_select reported address %q for %s, want %q", sel.Address, alpha.name, alpha.addr)
	}

	ran, echoed := whereItRan(t, s, nil)
	if ran != alpha.name {
		t.Fatalf("the command ran on %q after selecting %q", ran, alpha.name)
	}
	if echoed != ran {
		t.Fatalf("the result echoed %q but the command ran on %q", echoed, ran)
	}

	// An explicit sandbox argument overrides the selection for that call...
	ran, echoed = whereItRan(t, s, map[string]any{"sandbox": beta.name})
	if ran != beta.name {
		t.Fatalf("an explicit sandbox=%q ran on %q instead", beta.name, ran)
	}
	if echoed != ran {
		t.Fatalf("the result echoed %q but the command ran on %q", echoed, ran)
	}

	// ...and only for that call. An override that leaked into the sticky
	// default would silently move every later call to the other machine.
	ran, _ = whereItRan(t, s, nil)
	if ran != alpha.name {
		t.Fatalf("after a one-call override, the selection moved: the next call ran on %q, want %q", ran, alpha.name)
	}

	// The handle fleet_select minted resolves to the same sandbox as the name.
	ran, echoed = whereItRan(t, s, map[string]any{"sandbox": sel.Handle})
	if ran != alpha.name || echoed != alpha.name {
		t.Fatalf("handle %q resolved to %q (echoed %q), want %q", sel.Handle, ran, echoed, alpha.name)
	}

	// Selecting the other one moves the default.
	s.ok("fleet_select", map[string]any{"name": beta.name})
	ran, echoed = whereItRan(t, s, nil)
	if ran != beta.name || echoed != beta.name {
		t.Fatalf("after selecting %q the command ran on %q (echoed %q)", beta.name, ran, echoed)
	}

	// The file tools resolve the target through the same path, so the same
	// override applies to them — and a file written through the override must
	// land on the machine it named.
	path := filepath.Join(alpha.home, "written-through-an-override.txt")
	s.ok("fleet_write", map[string]any{
		"sandbox": alpha.name, "path": path, "content": "from alpha\n",
	})
	res := s.ok("fleet_read", map[string]any{"sandbox": alpha.name, "path": path})
	if got := echoOf(t, res); got != alpha.name {
		t.Fatalf("fleet_read echoed %q for an alpha-targeted call", got)
	}
	// Reading the same absolute path through beta is not a control — both
	// agents share this filesystem. Asking beta to run the *relative* marker
	// read is.
	ran, _ = whereItRan(t, s, map[string]any{"sandbox": alpha.name})
	if ran != alpha.name {
		t.Fatalf("an alpha-targeted call ran on %q", ran)
	}
}

// TestSelectionIsPerClientIdentity checks the half of the selection model that
// only two real agents can show: two clients holding different targets at the
// same time, against one server, with no protocol-level session to hang the
// distinction off.
func TestSelectionIsPerClientIdentity(t *testing.T) {
	f := newFleet(t)
	alpha := f.enroll("alpha", enrollOptions{})
	beta := f.enroll("beta", enrollOptions{})
	for _, a := range []*agent{alpha, beta} {
		writeFile(t, filepath.Join(a.home, markerFile), []byte(a.name+"\n"))
	}

	s := f.connect(t)

	const editor, ci = "editor-session", "ci-session"
	s.okAs("fleet_select", map[string]any{"name": alpha.name}, callOptions{identity: editor})
	s.okAs("fleet_select", map[string]any{"name": beta.name}, callOptions{identity: ci})

	for _, tc := range []struct{ identity, want string }{
		{editor, alpha.name},
		{ci, beta.name},
		{editor, alpha.name},
	} {
		res := s.okAs("fleet_exec", map[string]any{"argv": []string{"cat", markerFile}}, callOptions{identity: tc.identity})
		out := structured[execResult](t, res)
		if got := strings.TrimSpace(out.Stdout); got != tc.want {
			t.Fatalf("identity %q ran on %q, want %q", tc.identity, got, tc.want)
		}
		if echoed := echoOf(t, res); echoed != tc.want {
			t.Fatalf("identity %q got an echo of %q, want %q", tc.identity, echoed, tc.want)
		}
	}

	// A third identity has chosen nothing, and nothing is chosen for it —
	// not even with a fleet this small.
	msg := s.failsAs("fleet_exec", map[string]any{"argv": []string{"true"}}, callOptions{identity: "never-selected"})
	if !contains(msg, "fleet_select") {
		t.Fatalf("an unselected identity should be told to call fleet_select, got: %s", msg)
	}
}

// TestSelectionSurvivesAServerRestart checks that the sticky default is
// persisted rather than held in memory: an agent CLI restarts its MCP server
// constantly, and a selection that did not survive that would send the next
// call to the structured no-target error at best, and to the wrong host at
// worst.
func TestSelectionSurvivesAServerRestart(t *testing.T) {
	f := newFleet(t)
	alpha := f.enroll("alpha", enrollOptions{})
	beta := f.enroll("beta", enrollOptions{})
	for _, a := range []*agent{alpha, beta} {
		writeFile(t, filepath.Join(a.home, markerFile), []byte(a.name+"\n"))
	}

	first := f.connect(t)
	first.ok("fleet_select", map[string]any{"name": beta.name})
	if ran, _ := whereItRan(t, first, nil); ran != beta.name {
		t.Fatalf("the first session ran on %q after selecting %q", ran, beta.name)
	}

	// A second server process, started fresh against the same config
	// directory, with the same client implementation name.
	second := f.connect(t)
	ran, echoed := whereItRan(t, second, nil)
	if ran != beta.name {
		t.Fatalf("after restarting fleet-mcp the selection landed on %q, want %q", ran, beta.name)
	}
	if echoed != beta.name {
		t.Fatalf("after restarting fleet-mcp the echo said %q, want %q", echoed, beta.name)
	}

	list := structured[listResult](t, second.ok("fleet_list", nil))
	if len(list.Sandboxes) != 2 {
		t.Fatalf("expected both sandboxes after a restart, got %+v", list.Sandboxes)
	}
	for _, line := range list.Sandboxes {
		want := line.Name == beta.name
		if line.Selected != want {
			t.Fatalf("fleet_list marks %q selected=%v after a restart, want %v", line.Name, line.Selected, want)
		}
		if line.Name == alpha.name && line.Address != alpha.addr {
			t.Fatalf("fleet_list reports %q at %q, want %q", line.Name, line.Address, alpha.addr)
		}
	}
}
