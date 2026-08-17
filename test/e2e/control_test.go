//go:build integration

package e2e

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNoShippedCommandIssuesTheControlLeaf records a defect, as the product
// currently behaves.
//
// `fleet-mcp` presents a control certificate to every agent, and tells an
// operator who has none to run `fleetctl ca sign --profile control`. That
// command cannot be run as printed: it requires a --csr, and nothing in the
// product produces one or the key that goes with it. `ca init` does not issue a
// control leaf, `enroll mint` issues agent identities only, and no page in
// docs/ mentions the control leaf. Following docs/quickstart.md exactly leaves
// a workstation that can list sandboxes and reach none of them.
//
// It is asserted here rather than left as prose because this suite *works
// around* it: [fleet.issueControlLeaf] builds the CSR itself, with crypto/x509,
// and only the signing goes through the real command. A workaround nothing
// fails on is a workaround nobody removes — and this one hides the single step
// that stands between the documented flow and a usable MCP server.
//
// If this test starts failing, that is the fix landing (PR #54 gives `ca sign
// --profile control` a no-CSR mode that generates the keypair). Delete it, and
// replace the CSR building in issueControlLeaf with the shipped command, so the
// suite covers the path an operator actually walks.
//
// Reported in the PR body for #28.
func TestNoShippedCommandIssuesTheControlLeaf(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})

	// A config directory as an operator following the quickstart has it: a CA,
	// and nothing else. Separate from the fleet's own, which this suite has
	// already fitted with a hand-built control leaf.
	opDir := filepath.Join(f.root, "operator")
	if err := os.MkdirAll(opDir, 0o700); err != nil {
		t.Fatalf("create the operator config directory: %v", err)
	}
	env := f.configEnv(opDir)
	runCLI(t, bins.fleetctl, []string{"ca", "init"}, env)

	// The command fleet-mcp's own error message names, run as printed.
	out, err := tryCLI(bins.fleetctl, []string{
		"ca", "sign",
		"--profile", "control",
		"--subject", "fleet-mcp",
		"--out", filepath.Join(opDir, "control.crt"),
	}, env)
	if err == nil {
		t.Fatalf("`fleetctl ca sign --profile control` issued a leaf with no CSR — the gap this test records is closed, "+
			"so delete this test and have issueControlLeaf call the shipped command:\n%s", out)
	}
	if !contains(out, "csr") {
		t.Fatalf("the refusal does not name the missing CSR, so this test is recording something else:\n%s", out)
	}

	// And nothing else in the flow produced one either: `ca init` above is the
	// step the quickstart tells the operator to run on this machine.
	for _, name := range []string{"control.crt", "control.key"} {
		if _, err := os.Stat(filepath.Join(opDir, name)); err == nil {
			t.Fatalf("%s exists after `ca init` alone — the product now issues the control leaf, so delete this test", name)
		}
	}

	// The consequence, end to end. A server on that config directory starts,
	// lists, and registers a sandbox; the first call that has to reach one
	// fails, naming a command the operator cannot run.
	s := f.connectAt(t, opDir, "operator-workstation")
	s.ok("fleet_add", map[string]any{"name": a.name, "address": a.addr})

	// Selecting still succeeds — an unreachable sandbox stays addressable by
	// design — but it reports the reason it could not be reached.
	sel := structured[selectResult](t, s.ok("fleet_select", map[string]any{"name": a.name}))
	if sel.Health == "serving" {
		t.Fatalf("a server with no control certificate reached an agent: %+v", sel)
	}

	msg := s.fails("fleet_exec", map[string]any{"argv": []string{"true"}, "sandbox": a.name})
	if !contains(msg, "control certificate") {
		t.Fatalf("the failure does not name the missing credential: %s", msg)
	}
	if !contains(msg, "ca sign --profile control") {
		t.Fatalf("the failure does not name the command that would create it: %s", msg)
	}
}
