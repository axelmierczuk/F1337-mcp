//go:build integration

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestConcurrentCallsKeepTheirTargets runs calls at both sandboxes at once.
//
// The sequential targeting scenario proves the resolution order. This proves
// the thing the resolution order is for: one server, one pooled dialer, two
// hosts, and many calls in flight. A pool that keyed a channel wrongly, or a
// handler that read a target from anything shared, would show up here and
// nowhere else — and it would show up as calls quietly running on the wrong
// machine, which is the failure this system must not have.
func TestConcurrentCallsKeepTheirTargets(t *testing.T) {
	f := newFleet(t)
	alpha := f.enroll("alpha", enrollOptions{})
	beta := f.enroll("beta", enrollOptions{})
	for _, a := range []*agent{alpha, beta} {
		writeFile(t, filepath.Join(a.home, markerFile), []byte(a.name+"\n"))
	}

	s := f.connect(t)
	s.ok("fleet_select", map[string]any{"name": alpha.name})

	const rounds = 12
	type outcome struct {
		want, ran, echoed string
	}
	results := make([]outcome, rounds*2)

	var wg sync.WaitGroup
	for i := range rounds {
		for j, target := range []*agent{alpha, beta} {
			wg.Add(1)
			// Nothing in here fails the test directly. t.Fatalf from a
			// goroutine that is not the test's own stops that goroutine and
			// leaves the test running, so a failure reported that way arrives
			// as a confusing second failure somewhere else; each call records
			// what it saw and the loop below does the failing.
			go func(slot int, a *agent) {
				defer wg.Done()
				res, err := s.tryCall("fleet_exec", map[string]any{
					"argv":    []string{"cat", markerFile},
					"sandbox": a.name,
				}, callOptions{})
				if err != nil {
					results[slot] = outcome{want: a.name, ran: "protocol failure: " + err.Error()}
					return
				}
				if res.IsError {
					results[slot] = outcome{want: a.name, ran: "error: " + resultText(res)}
					return
				}
				out, err := decodeStructured[execResult](res)
				if err != nil {
					results[slot] = outcome{want: a.name, ran: "undecodable result: " + err.Error()}
					return
				}
				results[slot] = outcome{
					want:   a.name,
					ran:    strings.TrimSpace(out.Stdout),
					echoed: out.Sandbox,
				}
			}(i*2+j, target)
		}
	}
	wg.Wait()

	for i, got := range results {
		if got.ran != got.want {
			t.Fatalf("call %d targeted %q and ran on %q", i, got.want, got.ran)
		}
		if got.echoed != got.want {
			t.Fatalf("call %d targeted %q and echoed %q", i, got.want, got.echoed)
		}
	}

	// The selection is where it was left, having been overridden a dozen times
	// concurrently.
	if ran, _ := whereItRan(t, s, nil); ran != alpha.name {
		t.Fatalf("after concurrent overrides the selection resolved to %q, want %q", ran, alpha.name)
	}
}

// TestListReportsAnUnreachableSandboxWithoutWaitingForIt checks the case a
// fleet is in most of the time: one machine is off.
//
// The assertion that matters is not that the dead one is reported dead — it is
// that the live one is still reported live in the same call. A probe that let
// one unreachable host decide the whole listing is how a twenty-machine fleet
// becomes unusable because somebody closed a laptop.
func TestListReportsAnUnreachableSandboxWithoutWaitingForIt(t *testing.T) {
	f := newFleet(t)
	alpha := f.enroll("alpha", enrollOptions{})
	beta := f.enroll("beta", enrollOptions{})
	s := f.connect(t)

	list := structured[listResult](t, s.ok("fleet_list", map[string]any{"refresh": true}))
	liveAgent := map[string]string{}
	for _, line := range list.Sandboxes {
		if line.Health != "serving" {
			t.Fatalf("%s is %q before anything was stopped: %+v", line.Name, line.Health, line)
		}
		if line.Agent == "" {
			t.Fatalf("%s reports no agent version while it is serving: %+v", line.Name, line)
		}
		liveAgent[line.Name] = line.Agent
	}

	beta.kill()
	waitFor(t, 30*time.Second, "beta's listener to close", func() (bool, string) {
		if !dialable(beta.addr) {
			return true, ""
		}
		return false, beta.addr + " is still accepting"
	})

	refreshed := structured[listResult](t, s.okAs("fleet_list", map[string]any{"refresh": true},
		callOptions{timeout: 60 * time.Second}))
	if len(refreshed.Sandboxes) != 2 {
		t.Fatalf("a dead sandbox dropped out of the listing: %+v", refreshed.Sandboxes)
	}
	for _, line := range refreshed.Sandboxes {
		switch line.Name {
		case alpha.name:
			if line.Health != "serving" {
				t.Fatalf("the live sandbox is reported %q while its neighbour is down: %+v", line.Health, line)
			}
		case beta.name:
			if line.Health == "serving" {
				t.Fatalf("a sandbox whose daemon was killed is still reported serving: %+v", line)
			}
		}
		// The AGENT column has two sources — the value the daemon answers with
		// while it is up, and the one the registry recorded at enrollment — and
		// the listing silently prefers whichever it has. A host going
		// unreachable must not therefore appear to change version: that reads
		// as "something about the agent changed" at the exact moment an
		// operator is working out what went wrong. See #61.
		if line.Agent != liveAgent[line.Name] {
			t.Fatalf("%s reports agent %q now that it is %q, having reported %q while it was serving: "+
				"the stored and live version strings disagree",
				line.Name, line.Agent, line.Health, liveAgent[line.Name])
		}
	}

	// And a call aimed at the dead one fails with something that names it,
	// rather than hanging or reporting the wrong host.
	msg := s.failsAs("fleet_exec", map[string]any{
		"argv": []string{"true"}, "sandbox": beta.name,
	}, callOptions{timeout: 90 * time.Second})
	if !contains(msg, beta.name) {
		t.Fatalf("the failure does not name the sandbox that could not be reached: %s", msg)
	}

	// The live one still works from the same session and the same pool.
	s.ok("fleet_exec", map[string]any{"argv": []string{"true"}, "sandbox": alpha.name})
}

// TestFileSearchToolsWalkTheSandbox covers the three tools that answer
// questions about a tree rather than about one file. Grep is a server stream,
// so this is also the only place a streamed FileService response is read by a
// real client.
func TestFileSearchToolsWalkTheSandbox(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})
	s := f.connect(t)
	s.ok("fleet_select", map[string]any{"name": a.name})

	root := filepath.Join(a.home, "project")
	for rel, content := range map[string]string{
		"main.go":            "package main\n\nfunc main() { needle() }\n",
		"internal/util/u.go": "package util\n\nfunc needle() {}\n",
		"docs/readme.md":     "no match here\n",
	} {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("create %s: %v", filepath.Dir(path), err)
		}
		writeFile(t, path, []byte(content))
	}

	ls := resultText(s.ok("fleet_ls", map[string]any{"path": root}))
	for _, want := range []string{"main.go", "docs", "internal"} {
		if !contains(ls, want) {
			t.Fatalf("fleet_ls of the project root does not mention %q:\n%s", want, ls)
		}
	}

	glob := resultText(s.ok("fleet_glob", map[string]any{"root": root, "pattern": "**/*.go"}))
	for _, want := range []string{"main.go", "u.go"} {
		if !contains(glob, want) {
			t.Fatalf("fleet_glob did not find %q:\n%s", want, glob)
		}
	}
	if contains(glob, "readme.md") {
		t.Fatalf("fleet_glob for *.go returned a markdown file:\n%s", glob)
	}

	grep := resultText(s.ok("fleet_grep", map[string]any{"root": root, "pattern": "func needle"}))
	if !contains(grep, "u.go") {
		t.Fatalf("fleet_grep did not find the definition:\n%s", grep)
	}
	if contains(grep, "readme.md") {
		t.Fatalf("fleet_grep matched a file with no match in it:\n%s", grep)
	}
}

// TestExecIsAudited checks that the record an operator would investigate with
// actually gets written, and names the identity the agent authenticated.
//
// The audit log is a subsystem with no observable effect on any tool result, so
// a version of it that silently wrote nothing would pass every other test in
// this repository.
func TestExecIsAudited(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})
	s := f.connect(t)
	s.ok("fleet_select", map[string]any{"name": a.name})

	// The command's output has to be distinguishable from its argv, or the last
	// assertion in this test cannot tell which of the two the log captured. So
	// the command prints a file: the path is in argv and identifies the record,
	// while the contents exist nowhere but on the command's stdout.
	const marker = "audited-command"
	const outputOnly = "this-text-exists-only-as-command-output"
	printed := filepath.Join(a.home, marker+".txt")
	writeFile(t, printed, []byte(outputOnly+"\n"))
	ran := structured[execResult](t, s.ok("fleet_exec", map[string]any{"argv": []string{"cat", printed}}))
	if !contains(ran.Stdout, outputOnly) {
		t.Fatalf("the command did not print the marker, so the assertion that the log omits it proves nothing: %+v", ran)
	}

	auditPath := filepath.Join(a.dir, "logs", "audit.jsonl")
	var record map[string]any
	waitFor(t, 30*time.Second, "the exec to reach the audit log", func() (bool, string) {
		data, err := os.ReadFile(auditPath)
		if err != nil {
			return false, "no audit log at " + auditPath
		}
		for _, line := range strings.Split(string(data), "\n") {
			if !contains(line, marker) {
				continue
			}
			if err := json.Unmarshal([]byte(line), &record); err != nil {
				return false, "unparseable record: " + line
			}
			return true, ""
		}
		return false, "no record naming the command yet"
	})

	if got := record["principal"]; got != "fleet-mcp" {
		t.Fatalf("the audit record attributes the command to %v, want fleet-mcp", got)
	}
	if got := record["sandbox"]; got != a.name {
		t.Fatalf("the audit record names sandbox %v, want %q", got, a.name)
	}
	if got := record["rpc"]; got != "sandboxd.v1.ExecService/Exec" {
		t.Fatalf("the audit record names rpc %v", got)
	}
	if got := record["outcome"]; got != "ok" {
		t.Fatalf("the audit record reports outcome %v, want ok", got)
	}
	if got, ok := record["exit_code"].(float64); !ok || got != 0 {
		t.Fatalf("the audit record reports exit_code %v", record["exit_code"])
	}

	// The output is not in it, and must never be: an audit log that captured
	// what commands printed would be a new place to steal secrets from. That is
	// what docs/security.md promises — "no field for … file contents, stdin,
	// command output" — and the command above was chosen so this can be checked
	// rather than assumed: outputOnly reached the agent as bytes on a pipe and
	// appears in no argument the caller sent.
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read the audit log: %v", err)
	}
	if contains(string(data), outputOnly) {
		t.Fatalf("the audit log captured what the command printed:\n%s", data)
	}
	if contains(string(data), "sbx_") {
		t.Fatalf("the audit log carries something token-shaped:\n%s", data)
	}
}
