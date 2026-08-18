//go:build integration

package e2e

import (
	"encoding/json"
	"strings"
	"testing"
)

// #101 as an operator meets it: a host is registered with `fleetctl add`, and
// the model reaches it.
//
// The registry is the seam between the operator's tools and the model's, and in
// the no-mTLS default nothing else writes it — enrollment is the ceremony this
// posture skips. So this scenario drives the whole path from the command an
// operator types: add the host, see it in `fleetctl list` marked as
// unauthenticated, then start a server and run something on it through a tool
// call. Every step is a separate process reading the same file, which is what
// makes the last one evidence rather than a round trip through one value.

// ctlAddResult is what `fleetctl add --json` reports back.
type ctlAddResult struct {
	Name    string            `json:"name"`
	Address string            `json:"address"`
	Auth    string            `json:"auth"`
	Labels  map[string]string `json:"labels"`
	Health  string            `json:"health"`
	Detail  string            `json:"detail"`
	Note    string            `json:"note"`
}

func TestOperatorRegistersAnUnauthenticatedHostWithFleetctlAdd(t *testing.T) {
	f := newFleet(t)
	open := f.plaintextAgent(t, "tailnet-box")

	// The command. --json because this is also the scripting path the issue is
	// about: an operator provisioning several hosts drives this, not an MCP
	// client.
	out, warnings := splitCLI(t, bins.fleetctl, []string{
		"add", open.name, "--address", open.addr, "--insecure",
		"--label", "network=tailnet", "--json",
	}, f.ctlEnv())

	var added ctlAddResult
	if err := json.Unmarshal([]byte(out), &added); err != nil {
		t.Fatalf("`fleetctl add --json` did not emit one JSON document (%v):\nstdout:\n%s\nstderr:\n%s", err, out, warnings)
	}
	// The probe dialled a host nothing authenticates, and said so — on stderr,
	// where it cannot land in the middle of the document a provisioning script
	// is parsing.
	if !contains(warnings, "CONNECTING TO A SANDBOX THIS FLEET DOES NOT AUTHENTICATE") {
		t.Fatalf("`fleetctl add --insecure` dialled an unauthenticated host without saying so:\n%s", warnings)
	}
	if added.Name != open.name || added.Address != open.addr {
		t.Fatalf("`fleetctl add` registered %q at %q, want %q at %q", added.Name, added.Address, open.name, open.addr)
	}
	if added.Auth != "none" {
		t.Fatalf("`fleetctl add --insecure` reported auth %q, want none", added.Auth)
	}
	// The probe ran and the agent answered. This is the half enrollment used to
	// provide for free: something is serving that address, in the posture the
	// entry records.
	if added.Health != "serving" {
		t.Fatalf("`fleetctl add` reported health %q for a running agent, want serving (detail %q)", added.Health, added.Detail)
	}
	if !contains(added.Note, "without mTLS") {
		t.Fatalf("`fleetctl add`'s note does not say what it registered: %q", added.Note)
	}
	if added.Labels["network"] != "tailnet" {
		t.Fatalf("`fleetctl add` dropped the label it was given: %+v", added.Labels)
	}

	// `fleetctl list`, in a second process, reading the file the first one
	// wrote. The AUTH column and the note under the table are what an operator
	// sees, and they are the same words the model's fleet_list uses.
	list := runCLI(t, bins.fleetctl, []string{"list", "--no-probe"}, f.ctlEnv())
	if !contains(list, "AUTH") {
		t.Fatalf("`fleetctl list` has no AUTH column:\n%s", list)
	}
	for _, want := range []string{
		open.name, "none",
		"auth none (" + open.name + ")",
		"nothing in this fleet authenticates either end",
	} {
		if !contains(list, want) {
			t.Fatalf("`fleetctl list` does not show %q after `fleetctl add`:\n%s", want, list)
		}
	}
	// The label reached the registry, read back by a command that renders one
	// entry in full.
	info := ctlInfo(t, f, open.name)
	labels, _ := info["labels"].(map[string]any)
	if labels["network"] != "tailnet" {
		t.Fatalf("the label the operator attached did not reach the registry: %+v", info["labels"])
	}

	// And the model reaches it. A third process, and the one that decides
	// whether an operator-registered host is a fleet member in full: no
	// fleet_add call anywhere in this scenario.
	s := f.connect(t)
	s.ok("fleet_select", map[string]any{"name": open.name})
	const marker = "reached-the-host-the-operator-added"
	ran := structured[execResult](t, s.ok("fleet_exec", map[string]any{
		"argv": []string{"sh", "-c", "echo " + marker},
	}))
	if ran.ExitCode != 0 || !contains(ran.Stdout, marker) {
		t.Fatalf("the command did not run on the host `fleetctl add` registered: %+v", ran)
	}
	if ran.Sandbox != open.name {
		t.Fatalf("the result echoes sandbox %q, want %q", ran.Sandbox, open.name)
	}

	// fleet_list sees the same entry with the same posture, which is the two
	// halves of #101 agreeing: the operator wrote it, the model reads it.
	fleetList := structured[listResult](t, s.ok("fleet_list", nil))
	var found bool
	for _, line := range fleetList.Sandboxes {
		if line.Name != open.name {
			continue
		}
		found = true
		if line.Auth != "none" {
			t.Fatalf("fleet_list reports auth %q for the host `fleetctl add --insecure` registered, want none", line.Auth)
		}
	}
	if !found {
		t.Fatalf("fleet_list does not hold the host `fleetctl add` registered: %+v", fleetList.Sandboxes)
	}
}

// The posture is checked against the host, not taken on trust, and it fails
// loudly in both directions — which is what #85 required of anything that
// records a posture.
//
// Both halves run against real agents in one fleet: the enrolled one is refused
// as insecure and the plaintext one is refused as authenticated. A command that
// had stopped checking, or that only ever checked one direction, fails here.
func TestFleetctlAddRefusesAPostureTheHostContradicts(t *testing.T) {
	f := newFleet(t)
	secure := f.enroll("build-box", enrollOptions{})
	open := f.plaintextAgent(t, "open-box")

	// An enrolled agent registered as insecure: every call to it would fail.
	out, err := tryCLI(bins.fleetctl, []string{
		"add", "mislabelled-secure", "--address", secure.addr, "--insecure",
	}, f.ctlEnv())
	if err == nil {
		t.Fatalf("`fleetctl add --insecure` accepted a host serving mTLS:\n%s", out)
	}
	for _, want := range []string{"answered over mTLS", "drop --insecure", "Nothing was registered"} {
		if !contains(out, want) {
			t.Fatalf("the refusal does not say %q:\n%s", want, out)
		}
	}

	// A plaintext agent registered as authenticated: the silent downgrade. The
	// entry would claim an identity check nothing performs.
	out, err = tryCLI(bins.fleetctl, []string{
		"add", "mislabelled-open", "--address", open.addr,
	}, f.ctlEnv())
	if err == nil {
		t.Fatalf("`fleetctl add` accepted a host serving plaintext as authenticated:\n%s", out)
	}
	for _, want := range []string{"answered without mTLS", "--insecure", "Nothing was registered"} {
		if !contains(out, want) {
			t.Fatalf("the refusal does not say %q:\n%s", want, out)
		}
	}

	// Neither refusal wrote anything. Asserted against the registry through the
	// command that reads it, because the message above is the half a refusal
	// that wrote the entry anyway would still get right.
	list := runCLI(t, bins.fleetctl, []string{"list", "--no-probe"}, f.ctlEnv())
	for _, name := range []string{"mislabelled-secure", "mislabelled-open"} {
		if contains(list, name) {
			t.Fatalf("a refused `fleetctl add` left %q in the registry:\n%s", name, list)
		}
	}

	// And both hosts register with the posture they actually serve, so the
	// refusals above are a command that insisted on being told rather than one
	// that cannot register these hosts at all.
	runCLI(t, bins.fleetctl, []string{"add", "tailnet-box-2", "--address", open.addr, "--insecure"}, f.ctlEnv())
	runCLI(t, bins.fleetctl, []string{"add", "build-box-2", "--address", secure.addr}, f.ctlEnv())
	list = runCLI(t, bins.fleetctl, []string{"list", "--no-probe"}, f.ctlEnv())
	for _, want := range []string{"tailnet-box-2", "build-box-2"} {
		if !contains(list, want) {
			t.Fatalf("`fleetctl add` could not register %q in the posture it serves:\n%s", want, list)
		}
	}
}

// An address nothing answers at is refused, and --no-probe is how an operator
// registers a host that is not up yet.
//
// The pair is the point. The refusal alone could be a command that cannot
// register anything unreachable, which would break provisioning ahead of a
// boot; the override alone would make the probe advisory.
func TestFleetctlAddRefusesAnUnreachableAddressUnlessToldNotToProbe(t *testing.T) {
	f := newFleet(t)

	// A port nothing listens on, in the range this harness hands out and then
	// releases: the typo'd address, which is the case a probe is for.
	address := "127.0.0.1:1"

	out, err := tryCLI(bins.fleetctl, []string{
		"add", "typo-box", "--address", address, "--insecure", "--timeout", "2s",
	}, f.ctlEnv())
	if err == nil {
		t.Fatalf("`fleetctl add` accepted an address nothing answers at:\n%s", out)
	}
	if !contains(out, "nothing answered at") || !contains(out, "--no-probe") {
		t.Fatalf("the refusal does not name the address or the way past it:\n%s", out)
	}
	if list := runCLI(t, bins.fleetctl, []string{"list", "--no-probe"}, f.ctlEnv()); contains(list, "typo-box") {
		t.Fatalf("a refused `fleetctl add` left an entry behind:\n%s", list)
	}

	// The same address with --no-probe: registered, and saying it was never
	// confirmed.
	out, _ = splitCLI(t, bins.fleetctl, []string{
		"add", "not-up-yet", "--address", address, "--insecure", "--no-probe", "--json",
	}, f.ctlEnv())
	var added ctlAddResult
	if err := json.Unmarshal([]byte(out), &added); err != nil {
		t.Fatalf("`fleetctl add --no-probe --json` did not emit one JSON document (%v):\n%s", err, out)
	}
	if added.Health != "unknown" {
		t.Fatalf("`fleetctl add --no-probe` reported health %q, want unknown", added.Health)
	}
	if !contains(added.Detail, "no-probe") {
		t.Fatalf("an unconfirmed entry does not say why it is unconfirmed: %q", added.Detail)
	}

	// `list` still answers promptly with a dead host in the fleet — #27's
	// property, restated here because add is now a way to put one there.
	list := runCLI(t, bins.fleetctl, []string{"list", "--timeout", "2s"}, f.ctlEnv())
	if !contains(list, "not-up-yet") || !contains(list, "unreachable") {
		t.Fatalf("`fleetctl list` does not report the unreachable host add registered:\n%s", list)
	}
}

// `fleetctl add` and fleet_add write the same entry, because they are the same
// code path. Two hosts registered the two ways, and every field of the entry
// compared — the one thing that cannot be checked by reading either
// implementation.
func TestFleetctlAddAndFleetAddWriteTheSameEntry(t *testing.T) {
	f := newFleet(t)
	open := f.plaintextAgent(t, "shared-box")

	runCLI(t, bins.fleetctl, []string{
		"add", "via-cli", "--address", open.addr, "--insecure", "--label", "arch=arm64",
	}, f.ctlEnv())

	s := f.connect(t)
	s.ok("fleet_add", map[string]any{
		"name": "via-tool", "address": open.addr, "insecure": true,
		"labels": map[string]any{"arch": "arm64"},
	})

	// Read back through `info --json`, which renders one entry in full.
	cli := ctlInfo(t, f, "via-cli")
	tool := ctlInfo(t, f, "via-tool")
	for _, field := range []string{"address", "auth", "labels"} {
		if !sameField(cli, tool, field) {
			t.Fatalf("the operator's entry and the model's differ on %q:\n cli: %v\ntool: %v",
				field, cli[field], tool[field])
		}
	}

	// The refusal to overwrite is shared too, and each front end names its own
	// remedy: an operator is told about `fleetctl remove`, not about a tool.
	out, err := tryCLI(bins.fleetctl, []string{
		"add", "via-tool", "--address", open.addr, "--insecure", "--no-probe",
	}, f.ctlEnv())
	if err == nil {
		t.Fatalf("`fleetctl add` overwrote an entry fleet_add had written:\n%s", out)
	}
	for _, want := range []string{"already registered", "fleetctl remove via-tool"} {
		if !contains(out, want) {
			t.Fatalf("the refusal does not say %q:\n%s", want, out)
		}
	}
}

// ctlInfo reads one registry entry back through `fleetctl info --json`.
func ctlInfo(t *testing.T, f *fleet, name string) map[string]any {
	t.Helper()

	out, _ := splitCLI(t, bins.fleetctl, []string{"info", name, "--timeout", "2s", "--json"}, f.ctlEnv())
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("`fleetctl info %s --json` did not emit one JSON document (%v):\n%s", name, err, out)
	}
	return doc
}

// sameField compares one field of two info documents, ignoring the fields that
// are the entry's identity rather than its content.
func sameField(a, b map[string]any, field string) bool {
	left, right := a[field], b[field]
	if field == "labels" {
		return jsonEqual(left, right)
	}
	return left == right
}

func jsonEqual(a, b any) bool {
	left, errA := json.Marshal(a)
	right, errB := json.Marshal(b)
	return errA == nil && errB == nil && strings.EqualFold(string(left), string(right))
}
