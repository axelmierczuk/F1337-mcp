//go:build integration

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEnrollmentRefusesWhatTheTokenDoesNotAuthorize drives the enrollment
// exchange from the outside, with the requests a host would send if it wanted
// to be something other than what it was invited to be.
//
// Three privilege escalations have been found in this exchange by inspection.
// All three had the same shape: a field the enrolling host controls reaching a
// certificate. The assertions here are on what the control plane refuses and,
// for the request that succeeds, on what the issued leaf actually carries.
func TestEnrollmentRefusesWhatTheTokenDoesNotAuthorize(t *testing.T) {
	f := newFleet(t)

	dir := filepath.Join(f.root, "attempts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}

	// One token for every attempt, including the legitimate one at the end. A
	// refused enrollment no longer spends its token — see
	// TestARefusedEnrollmentKeepsItsToken — so each attempt below is refused on
	// what it names rather than on the leftovers of the one before it, and the
	// enrollment that succeeds proves the refusals cost the operator nothing.
	//
	// This used to mint a fresh token per attempt, to work around exactly that
	// defect. The workaround went with the fix.
	token := f.mintToken("build-box", "127.0.0.1:8722")
	attempt := func(name string, extra ...string) (string, error) {
		args := []string{
			"enroll",
			"--control", f.enrollAddr,
			"--token", token,
			"--ca-fingerprint", f.fingerprint,
			"--dir", filepath.Join(dir, name),
		}
		return tryCLI(bins.agent, append(args, extra...), f.ctlEnv())
	}

	// Enrolling as a name the token does not reserve. The name is half the
	// identity: it is what the leaf's subject and SANs are built from.
	got, err := attempt("wrong-name", "--name", "not-build-box")
	if err == nil {
		t.Fatalf("a host enrolled under a name its token did not reserve:\n%s", got)
	}
	if !contains(got, "reserves the name") {
		t.Fatalf("the refusal does not explain the name mismatch:\n%s", got)
	}

	// Asking to be certified for an address the operator never authorized.
	got, err = attempt("wrong-address", "--address", "build-box.example.com:8722")
	if err == nil {
		t.Fatalf("a host was certified for an address its token did not authorize:\n%s", got)
	}
	if !contains(got, "not authorized by this token") {
		t.Fatalf("the refusal does not explain the address mismatch:\n%s", got)
	}

	// The legitimate enrollment works — with the token the two refusals above
	// did not spend — and the leaf carries exactly what the operator
	// authorized, not what the host asked for.
	got = runCLI(t, bins.agent, []string{
		"enroll",
		"--control", f.enrollAddr,
		"--token", token,
		"--ca-fingerprint", f.fingerprint,
		"--dir", filepath.Join(dir, "legitimate"),
		"--listen", "127.0.0.1:8722",
		"--address", "127.0.0.1:8722",
	}, f.ctlEnv())
	if !contains(got, `enrolled as "build-box"`) {
		t.Fatalf("the legitimate enrollment did not report the reserved name:\n%s", got)
	}
	if !contains(got, "valid for:   [build-box") {
		t.Fatalf("the issued leaf does not name what the token authorized:\n%s", got)
	}

	// And that token is spent. A replayed token is a second identity for
	// whoever intercepted it.
	got, err = tryCLI(bins.agent, []string{
		"enroll", "--control", f.enrollAddr, "--token", token,
		"--ca-fingerprint", f.fingerprint, "--dir", filepath.Join(dir, "replay"),
	}, f.ctlEnv())
	if err == nil {
		t.Fatalf("a spent enrollment token was redeemed a second time:\n%s", got)
	}
	if !contains(got, "token rejected") {
		t.Fatalf("the refusal does not name the token as the reason:\n%s", got)
	}
}

// TestARefusedEnrollmentKeepsItsToken is #58, from the operator's side.
//
// Enrollment used to redeem the token before it validated anything else, so a
// request refused for a reason that had nothing to do with the token — a
// mistyped --address, a --name the token does not reserve — still burned it.
// The operator's next attempt then failed with "enrollment token rejected",
// which names the credential rather than the mistake, at the moment they are
// least able to interpret it: first-time enrollment on a host they have just
// provisioned. Minting a fresh token makes that message go away, which is
// precisely why the real cause survived it.
//
// This is the same scenario TestARefusedEnrollmentSpendsItsToken recorded as
// the defect, run against the behaviour that replaced it: the typo is refused,
// the corrected command is the fix, and one token pays for the whole session.
func TestARefusedEnrollmentKeepsItsToken(t *testing.T) {
	f := newFleet(t)

	dir := filepath.Join(f.root, "spent")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}

	minted := runCLI(t, bins.fleetctl, []string{
		"enroll", "mint", "--name", "build-box", "--address", "build-box.internal:8722", "--ttl", "10m",
	}, f.ctlEnv())
	token := valueAfter(t, minted, "token:")
	id := valueAfter(t, minted, "token-id:")

	// A request the control plane refuses on the *name*.
	got, err := tryCLI(bins.agent, []string{
		"enroll", "--control", f.enrollAddr, "--token", token,
		"--ca-fingerprint", f.fingerprint, "--name", "somebody-else",
		"--dir", filepath.Join(dir, "refused-name"),
	}, f.ctlEnv())
	if err == nil {
		t.Fatalf("the refused attempt succeeded:\n%s", got)
	}
	if !contains(got, "reserves the name") {
		t.Fatalf("the attempt was refused for an unexpected reason:\n%s", got)
	}
	if state := tokenState(t, f, id); state != "pending" {
		t.Fatalf("a refusal on the name left the token %s, not pending", state)
	}

	// And the headline case from #58: a mistyped --address, on the same token.
	// Not a mistyped loopback address — those an enrolling host may add on its
	// own, so 127.0.0.2 for 127.0.0.1 is honoured rather than refused.
	got, err = tryCLI(bins.agent, []string{
		"enroll", "--control", f.enrollAddr, "--token", token,
		"--ca-fingerprint", f.fingerprint, "--address", "buidl-box.internal:8722",
		"--dir", filepath.Join(dir, "refused-address"),
	}, f.ctlEnv())
	if err == nil {
		t.Fatalf("the mistyped --address was accepted:\n%s", got)
	}
	if !contains(got, "not authorized by this token") {
		t.Fatalf("the attempt was refused for an unexpected reason:\n%s", got)
	}
	if state := tokenState(t, f, id); state != "pending" {
		t.Fatalf("a refusal on the address left the token %s, not pending", state)
	}

	// The same token, now used exactly as the operator meant to.
	got = runCLI(t, bins.agent, []string{
		"enroll", "--control", f.enrollAddr, "--token", token,
		"--ca-fingerprint", f.fingerprint,
		"--dir", filepath.Join(dir, "corrected"),
		"--listen", "0.0.0.0:8722", "--address", "build-box.internal:8722",
	}, f.ctlEnv())
	if !contains(got, `enrolled as "build-box"`) {
		t.Fatalf("the corrected command did not enroll on the token the refusals left behind:\n%s", got)
	}

	// Single-use is the policy and stays the policy. What was wrong was the
	// ordering, not that a redeemed token is spent.
	if state := tokenState(t, f, id); state != "used" {
		t.Fatalf("the token store shows %s after a successful enrollment, not used", state)
	}
	got, err = tryCLI(bins.agent, []string{
		"enroll", "--control", f.enrollAddr, "--token", token,
		"--ca-fingerprint", f.fingerprint, "--dir", filepath.Join(dir, "replay"),
	}, f.ctlEnv())
	if err == nil {
		t.Fatalf("a spent enrollment token was redeemed a second time:\n%s", got)
	}
	if !contains(got, "token rejected") {
		t.Fatalf("the refusal does not name the token as the reason:\n%s", got)
	}
}

// TestARefusedEnrollmentKeepsItsTokenWhenTheAgentAddsALoopbackName covers the
// first of the two consequences #58 carries with it.
//
// An enrolling host may add loopback addresses of its own: they name that host
// and nothing else, so they cannot impersonate a peer, and requiring an
// operator to pre-authorize 127.0.0.1 would be friction with no security
// return. `enroll mint` therefore cannot know how many names the leaf will
// finally carry — the extras arrive with the request — so a token minted at
// exactly the CA's limit, which mint accepts, is one over it at redemption.
//
// The refusal is right. What was wrong is that it arrived after the token was
// spent, on a host the operator had already walked away from.
func TestARefusedEnrollmentKeepsItsTokenWhenTheAgentAddsALoopbackName(t *testing.T) {
	f := newFleet(t)

	dir := filepath.Join(f.root, "san-limit")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}

	// The reserved name plus maxLeafSANs-1 authorized addresses is exactly the
	// number of subject alternative names one leaf may carry.
	args := []string{"enroll", "mint", "--name", "build-box", "--ttl", "10m"}
	for i := 1; i < maxLeafSANs; i++ {
		args = append(args, "--address", fmt.Sprintf("10.0.0.%d:8722", i))
	}
	minted := runCLI(t, bins.fleetctl, args, f.ctlEnv())
	token := valueAfter(t, minted, "token:")
	id := valueAfter(t, minted, "token-id:")

	// --address 127.0.0.1:8722 is the one name over the limit.
	got, err := tryCLI(bins.agent, []string{
		"enroll", "--control", f.enrollAddr, "--token", token,
		"--ca-fingerprint", f.fingerprint,
		"--address", "127.0.0.1:8722",
		"--dir", filepath.Join(dir, "refused"),
	}, f.ctlEnv())
	if err == nil {
		t.Fatalf("a leaf over the subject alternative name limit was issued:\n%s", got)
	}
	if !contains(got, "too many subject alternative names") {
		t.Fatalf("the attempt was refused for an unexpected reason:\n%s", got)
	}
	if state := tokenState(t, f, id); state != "pending" {
		t.Fatalf("the loopback name the agent added left the token %s, not pending", state)
	}

	// Dropping --address is the whole correction, and the token is still there
	// to pay for it.
	got = runCLI(t, bins.agent, []string{
		"enroll", "--control", f.enrollAddr, "--token", token,
		"--ca-fingerprint", f.fingerprint,
		"--dir", filepath.Join(dir, "corrected"),
		"--listen", "127.0.0.1:8722",
	}, f.ctlEnv())
	if !contains(got, `enrolled as "build-box"`) {
		t.Fatalf("the corrected command did not enroll on the token the refusal left behind:\n%s", got)
	}
}

// TestARefusedEnrollmentKeepsItsTokenWhenACollisionLengthensTheName covers the
// second consequence, which has the same shape: what mint checked and what
// redemption certifies are not the same string.
//
// Collision resolution appends "-2", so a name one character under the DNS
// label limit — which mint accepts, because as itself it is certifiable — is
// two bytes over it by the time the CA is asked. The host's real problem is
// that another fleet member is holding the name, and it used to cost a token to
// find that out.
func TestARefusedEnrollmentKeepsItsTokenWhenACollisionLengthensTheName(t *testing.T) {
	f := newFleet(t)

	dir := filepath.Join(f.root, "collision")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}
	// One character under the longest label the CA will certify.
	name := strings.Repeat("a", 63)

	// The first host takes the name.
	runCLI(t, bins.agent, []string{
		"enroll", "--control", f.enrollAddr,
		"--token", f.mintToken(name, "127.0.0.1:8722"),
		"--ca-fingerprint", f.fingerprint,
		"--dir", filepath.Join(dir, "first"),
	}, f.ctlEnv())

	// The second is offered "<name>-2", which is two bytes too long to certify.
	minted := runCLI(t, bins.fleetctl, []string{
		"enroll", "mint", "--name", name, "--address", "127.0.0.1:8723", "--ttl", "10m",
	}, f.ctlEnv())
	token := valueAfter(t, minted, "token:")
	id := valueAfter(t, minted, "token-id:")

	got, err := tryCLI(bins.agent, []string{
		"enroll", "--control", f.enrollAddr, "--token", token,
		"--ca-fingerprint", f.fingerprint,
		"--dir", filepath.Join(dir, "refused"),
	}, f.ctlEnv())
	if err == nil {
		t.Fatalf("a name collision resolution could not certify was issued anyway:\n%s", got)
	}
	if !contains(got, "longer than 63 characters") {
		t.Fatalf("the attempt was refused for an unexpected reason:\n%s", got)
	}
	if state := tokenState(t, f, id); state != "pending" {
		t.Fatalf("the collision left the token %s, not pending", state)
	}

	// Removing the fleet member that was holding the name is the whole
	// correction, and the token is still there to pay for it.
	runCLI(t, bins.fleetctl, []string{"remove", name}, f.ctlEnv())
	got = runCLI(t, bins.agent, []string{
		"enroll", "--control", f.enrollAddr, "--token", token,
		"--ca-fingerprint", f.fingerprint,
		"--dir", filepath.Join(dir, "corrected"),
	}, f.ctlEnv())
	if !contains(got, `enrolled as "`+name+`"`) {
		t.Fatalf("the corrected command did not enroll on the token the refusal left behind:\n%s", got)
	}
}

// maxLeafSANs is ca.MaxSANs, restated because this package drives the shipped
// binaries and imports none of the product's own packages.
//
// It is not left to drift: TestTheSANLimitThisSuiteAssumesIsTheOneTheCAEnforces
// finds the boundary through the CLI and fails if it moves.
const maxLeafSANs = 16

// TestTheSANLimitThisSuiteAssumesIsTheOneTheCAEnforces pins the constant above
// to the product, by asking `enroll mint` — which refuses a token it could not
// redeem — where the edge actually is.
//
// Without this, raising ca.MaxSANs would leave the loopback scenario minting a
// token comfortably inside the limit, adding a loopback name that stayed inside
// it, and passing on an enrollment that was never refused at all.
func TestTheSANLimitThisSuiteAssumesIsTheOneTheCAEnforces(t *testing.T) {
	f := newFleet(t)

	mint := func(names int) (string, error) {
		args := []string{"enroll", "mint", "--name", "limit-box", "--ttl", "10m"}
		for i := 1; i < names; i++ {
			args = append(args, "--address", fmt.Sprintf("10.0.0.%d:8722", i))
		}
		return tryCLI(bins.fleetctl, args, f.ctlEnv())
	}

	if out, err := mint(maxLeafSANs); err != nil {
		t.Fatalf("mint refused %d subject alternative names, which this suite assumes is the limit:\n%s", maxLeafSANs, out)
	}
	out, err := mint(maxLeafSANs + 1)
	if err == nil {
		t.Fatalf("mint accepted %d subject alternative names, so the limit this suite assumes is stale:\n%s", maxLeafSANs+1, out)
	}
	if !contains(out, "too many subject alternative names") {
		t.Fatalf("mint refused %d names for an unexpected reason:\n%s", maxLeafSANs+1, out)
	}
}

// tokenState is the state `fleetctl enroll list` reports for one token id.
//
// Read as JSON rather than matched in the table, so that a scenario asking
// about its own token cannot be answered by some other token's row — which is
// exactly what a substring match on "pending" does in a fleet that has minted
// more than one.
func tokenState(t *testing.T, f *fleet, id string) string {
	t.Helper()

	out := runCLI(t, bins.fleetctl, []string{"enroll", "list", "--json"}, f.ctlEnv())
	var listed struct {
		Tokens []struct {
			ID    string `json:"id"`
			State string `json:"state"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal([]byte(out), &listed); err != nil {
		t.Fatalf("parse `fleetctl enroll list --json`: %v\n%s", err, out)
	}
	for _, tok := range listed.Tokens {
		if tok.ID == id {
			return tok.State
		}
	}
	t.Fatalf("no token %s in `fleetctl enroll list`:\n%s", id, out)
	return ""
}

// TestEnrollmentRequiresThePinnedFingerprint checks the one protection that
// runs before the token is transmitted. Without it, anything that can answer on
// the network collects a bootstrap credential.
func TestEnrollmentRequiresThePinnedFingerprint(t *testing.T) {
	f := newFleet(t)

	out := runCLI(t, bins.fleetctl, []string{
		"enroll", "mint", "--name", "pinned-box", "--address", "127.0.0.1:8722", "--ttl", "10m",
	}, f.ctlEnv())
	token := valueAfter(t, out, "token:")

	dir := filepath.Join(f.root, "pinning")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}

	// No pin at all: refused locally, before anything is sent.
	got, err := tryCLI(bins.agent, []string{
		"enroll", "--control", f.enrollAddr, "--token", token, "--dir", filepath.Join(dir, "unpinned"),
	}, f.ctlEnv())
	if err == nil {
		t.Fatalf("enrollment proceeded without a pinned fingerprint:\n%s", got)
	}
	if !contains(got, "--ca-fingerprint is required") {
		t.Fatalf("the refusal does not name the missing pin:\n%s", got)
	}

	// A pin that names a different CA: the handshake fails, so the token is
	// never written to the connection.
	otherDir := filepath.Join(f.root, "other-ca")
	initOut := runCLI(t, bins.fleetctl, []string{"ca", "init", "--ca-dir", otherDir}, f.ctlEnv())
	otherFingerprint := valueAfter(t, initOut, "SHA256 Fingerprint=")

	got, err = tryCLI(bins.agent, []string{
		"enroll", "--control", f.enrollAddr, "--token", token,
		"--ca-fingerprint", otherFingerprint,
		"--dir", filepath.Join(dir, "mispinned"),
	}, f.ctlEnv())
	if err == nil {
		t.Fatalf("enrollment completed against a control plane that failed the pin:\n%s", got)
	}
	if !contains(got, "does not match the pinned fingerprint") {
		t.Fatalf("the refusal does not name the pin mismatch:\n%s", got)
	}

	// The token survived both failures: a pin that spent the token would have
	// made the check a denial of service on the operator.
	got = runCLI(t, bins.agent, []string{
		"enroll", "--control", f.enrollAddr, "--token", token,
		"--ca-fingerprint", f.fingerprint,
		"--dir", filepath.Join(dir, "correct"),
		"--listen", "127.0.0.1:8722", "--address", "127.0.0.1:8722",
	}, f.ctlEnv())
	if !contains(got, `enrolled as "pinned-box"`) {
		t.Fatalf("the token did not survive the refused attempts:\n%s", got)
	}
}
