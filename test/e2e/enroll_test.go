//go:build integration

package e2e

import (
	"os"
	"path/filepath"
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

	// A fresh token per attempt. A refused enrollment spends its token — see
	// TestARefusedEnrollmentSpendsItsToken — so attempts sharing one would
	// stop testing what they name after the first.
	attempt := func(name string, extra ...string) (string, error) {
		args := []string{
			"enroll",
			"--control", f.enrollAddr,
			"--token", f.mintToken("build-box", "127.0.0.1:8722"),
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

	// The legitimate enrollment works, and the leaf carries exactly what the
	// operator authorized — not what the host asked for.
	token := f.mintToken("build-box", "127.0.0.1:8722")
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

// TestARefusedEnrollmentSpendsItsToken records a defect this suite found, as
// the product currently behaves.
//
// EnrollmentService redeems the token before it validates anything else, so a
// request refused for a reason that has nothing to do with the token — a
// mistyped --address, a --name the token does not reserve — still burns it. The
// operator's next attempt then fails with "enrollment token rejected", which
// names the token rather than the mistake, and the fix is to go and mint
// another one for every typo.
//
// It is asserted here rather than left out because a harness that quietly
// worked around this would hide it: the scenario above needs a fresh token per
// attempt, and the reason has to be written down somewhere that fails when it
// stops being true. If this test starts failing because a refused enrollment no
// longer spends its token, that is the fix landing — delete it and drop the
// fresh-token-per-attempt workaround above.
//
// Reported in the PR body for #28.
func TestARefusedEnrollmentSpendsItsToken(t *testing.T) {
	f := newFleet(t)

	dir := filepath.Join(f.root, "spent")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}
	token := f.mintToken("build-box", "127.0.0.1:8722")

	// A request the control plane refuses on the *name*, long after it has
	// redeemed the token.
	got, err := tryCLI(bins.agent, []string{
		"enroll", "--control", f.enrollAddr, "--token", token,
		"--ca-fingerprint", f.fingerprint, "--name", "somebody-else",
		"--dir", filepath.Join(dir, "refused"),
	}, f.ctlEnv())
	if err == nil {
		t.Fatalf("the refused attempt succeeded:\n%s", got)
	}
	if !contains(got, "reserves the name") {
		t.Fatalf("the attempt was refused for an unexpected reason:\n%s", got)
	}

	// The same token, now used exactly as the operator intended.
	got, err = tryCLI(bins.agent, []string{
		"enroll", "--control", f.enrollAddr, "--token", token,
		"--ca-fingerprint", f.fingerprint,
		"--dir", filepath.Join(dir, "corrected"),
		"--listen", "127.0.0.1:8722", "--address", "127.0.0.1:8722",
	}, f.ctlEnv())
	if err == nil {
		t.Fatalf("the token outlived a refused enrollment — the defect this test records is fixed, so delete it:\n%s", got)
	}
	if !contains(got, "token rejected") {
		t.Fatalf("expected the corrected attempt to fail on the spent token, got:\n%s", got)
	}

	// The token store agrees: it is marked used, not pending.
	listed := runCLI(t, bins.fleetctl, []string{"enroll", "list"}, f.ctlEnv())
	if !contains(listed, "used") {
		t.Fatalf("the token store does not show the token as used:\n%s", listed)
	}
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
