//go:build integration

package e2e

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestEnrollConnectExecReadBack is the walking skeleton: a host joins a fleet
// it was not previously part of, an MCP client selects it, asks what it is,
// runs a command on it, and reads back what that command wrote.
//
// Nothing here is mocked. The certificate the agent serves with was signed
// during this test by a CA created during this test, the client leaf was signed
// by the same CA, and the file the last step reads was written by a process the
// agent forked.
func TestEnrollConnectExecReadBack(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})
	s := f.connect(t)

	// The registry is populated by enrollment itself, not by fleet_add: the
	// control plane records the sandbox as it issues the leaf.
	list := structured[listResult](t, s.ok("fleet_list", nil))
	if len(list.Sandboxes) != 1 || list.Sandboxes[0].Name != a.name {
		t.Fatalf("expected the enrolled sandbox in the listing, got %+v", list.Sandboxes)
	}
	if list.Sandboxes[0].Address != a.addr {
		t.Fatalf("registry recorded address %q, agent serves on %q", list.Sandboxes[0].Address, a.addr)
	}

	// Nothing resolves implicitly, even with one sandbox enrolled.
	if msg := s.fails("fleet_exec", map[string]any{"argv": []string{"true"}}); !contains(msg, "fleet_select") {
		t.Fatalf("a call with no selection should name fleet_select, got: %s", msg)
	}

	sel := structured[selectResult](t, s.ok("fleet_select", map[string]any{"name": a.name}))
	if sel.Sandbox != a.name {
		t.Fatalf("fleet_select echoed %q, want %q", sel.Sandbox, a.name)
	}
	if sel.Health != "serving" {
		t.Fatalf("a freshly enrolled agent should be serving, got %q", sel.Health)
	}
	if !sel.Unconfined {
		t.Fatalf("an exec-enabled agent must report itself unconfined, got allowed_roots=%v", sel.AllowedRoots)
	}

	// GetHostInfo, over mTLS, reporting the identity the agent authenticated
	// this client as — which is the common name in the control leaf.
	info := structured[infoResult](t, s.ok("fleet_info", nil))
	if info.Principal != "fleet-mcp" {
		t.Fatalf("agent authenticated the client as %q, want fleet-mcp", info.Principal)
	}
	if info.Platform == "" || info.Hostname == "" {
		t.Fatalf("host info is missing platform or hostname: %+v", info)
	}
	if info.Agent == "" {
		t.Fatalf("host info carries no agent version: %+v", info)
	}

	// Exec writes the file...
	path := filepath.Join(a.home, "exec-wrote-this.txt")
	const content = "written by the command, read by the tool"
	execRes := structured[execResult](t, s.ok("fleet_exec", map[string]any{
		"argv": []string{"sh", "-c", "printf '%s' " + shellQuote(content) + " > " + shellQuote(path)},
	}))
	if execRes.ExitCode != 0 {
		t.Fatalf("exec exited %d: %s %s", execRes.ExitCode, execRes.Stdout, execRes.Stderr)
	}
	if execRes.Sandbox != a.name {
		t.Fatalf("exec result echoed %q, want %q", execRes.Sandbox, a.name)
	}

	// ...and the file tool reads it back over a separate RPC on a separate
	// service, which is the seam this scenario exists to cross.
	read := structured[readResult](t, s.ok("fleet_read", map[string]any{"path": path}))
	if !contains(read.Content, content) {
		t.Fatalf("fleet_read returned %q, which does not contain what exec wrote", read.Content)
	}
	if read.Sandbox != a.name {
		t.Fatalf("read result echoed %q, want %q", read.Sandbox, a.name)
	}
}

// TestWriteEditReadRoundTrip checks that content survives all three file tools
// unchanged — including the bytes that make a diff-based edit interesting:
// trailing whitespace, a tab, a CR, and a non-ASCII rune.
func TestWriteEditReadRoundTrip(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})
	s := f.connect(t)
	s.ok("fleet_select", map[string]any{"name": a.name})

	path := filepath.Join(a.home, "round-trip.txt")
	original := "alpha\n\tbeta with trailing space \ngamma — ünïcode\ndelta\n"

	write := structured[writeResult](t, s.ok("fleet_write", map[string]any{
		"path":    path,
		"content": original,
	}))
	if !write.Created {
		t.Fatalf("fleet_write should have created %s", path)
	}
	if write.BytesWritten != uint64(len(original)) {
		t.Fatalf("wrote %d bytes, sent %d", write.BytesWritten, len(original))
	}

	edit := structured[editResult](t, s.ok("fleet_edit", map[string]any{
		"path":       path,
		"old_string": "beta with trailing space ",
		"new_string": "beta edited",
	}))
	if edit.Replacements != 1 {
		t.Fatalf("expected exactly one replacement, got %d", edit.Replacements)
	}
	if !contains(edit.Diff, "beta edited") {
		t.Fatalf("the diff does not show the replacement: %s", edit.Diff)
	}

	// An edit that matches nothing must fail rather than silently do nothing,
	// and one that matches twice must fail rather than pick.
	if msg := s.fails("fleet_edit", map[string]any{
		"path": path, "old_string": "beta with trailing space ", "new_string": "x",
	}); msg == "" {
		t.Fatal("editing a string that is no longer present should have failed")
	}

	want := strings.Replace(original, "beta with trailing space ", "beta edited", 1)
	read := structured[readResult](t, s.ok("fleet_read", map[string]any{"path": path}))

	// fleet_read numbers lines, so compare the content line by line rather
	// than as one blob.
	for _, line := range strings.Split(strings.TrimSuffix(want, "\n"), "\n") {
		if !contains(read.Content, line) {
			t.Fatalf("line %q did not survive write→edit→read:\n%s", line, read.Content)
		}
	}

	// And the bytes themselves, with no rendering in the way.
	raw := structured[readResult](t, s.ok("fleet_read", map[string]any{"path": path, "raw": true}))
	if got := decodeBase64(t, raw.ContentBase64); got != want {
		t.Fatalf("raw read returned %q, want %q", got, want)
	}
}

// TestToolSurfaceOverStdio checks that a client which speaks the protocol —
// rather than one that reaches into the server — sees every tool the product
// advertises.
func TestToolSurfaceOverStdio(t *testing.T) {
	f := newFleet(t)
	s := f.connect(t)

	names := s.tools()
	if len(names) != 19 {
		t.Fatalf("expected nineteen tools over the wire, got %d: %v", len(names), names)
	}
	for _, want := range []string{"fleet_list", "fleet_select", "fleet_exec", "fleet_read", "fleet_forward"} {
		if !containsString(names, want) {
			t.Fatalf("%s is missing from tools/list: %v", want, names)
		}
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// shellQuote wraps a string in single quotes for `sh -c`.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
