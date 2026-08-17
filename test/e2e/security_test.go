//go:build integration

package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/client"
)

// TestAgentRejectsForeignAndWrongProfileClientCertificates drives the agent's
// mTLS policy from the outside, with certificates a real attacker would have:
// one signed by a CA the agent has never heard of, and one the fleet CA itself
// signed for a different purpose.
//
// The second is the one worth having: it chains to the right CA, it is valid,
// and it was issued by this very control plane. Only the extended key usage and
// the organizational unit separate an agent's own identity from an identity
// authorized to drive agents — so if that check is wrong, any compromised
// sandbox can drive every other sandbox in the fleet.
func TestAgentRejectsForeignAndWrongProfileClientCertificates(t *testing.T) {
	f := newFleet(t)
	a := f.enroll("build-box", enrollOptions{})

	fleetCA := readAll(t, filepath.Join(f.ctlDir, "ca", "ca.crt"))

	// The control leaf this fleet issued: the one identity that is supposed to
	// work. Checked first, so a later rejection cannot be the agent simply
	// being unreachable.
	if err := probeAgent(t, fleetCA,
		readAll(t, filepath.Join(f.ctlDir, "control.crt")),
		readAll(t, filepath.Join(f.ctlDir, "control.key")), a.addr); err != nil {
		t.Fatalf("the fleet's own control leaf was refused: %v", err)
	}

	// A leaf from a CA this fleet has never heard of, presented to an agent
	// that trusts only the fleet CA.
	foreignDir := filepath.Join(f.root, "foreign-ca")
	runCLI(t, bins.fleetctl, []string{"ca", "init", "--ca-dir", foreignDir}, f.ctlEnv())
	foreignCert, foreignKey := signControlLeaf(t, f, foreignDir, "fleet-mcp")

	if err := probeAgent(t, fleetCA, foreignCert, foreignKey, a.addr); err == nil {
		t.Fatal("an agent accepted a client certificate from a foreign CA")
	} else {
		t.Logf("foreign CA leaf refused with: %v", err)
	}

	// The agent's own leaf, used as a client certificate. It chains to the
	// fleet CA — the chain is not what distinguishes it.
	if err := probeAgent(t, fleetCA,
		readAll(t, filepath.Join(a.dir, "agent.crt")),
		readAll(t, filepath.Join(a.dir, "agent.key")), a.addr); err == nil {
		t.Fatal("an agent accepted another agent's server leaf as a client certificate")
	} else {
		t.Logf("agent leaf refused with: %v", err)
	}

	// And the agent is still serving afterwards: the rejections were decisions,
	// not a daemon that fell over.
	if err := probeAgent(t, fleetCA,
		readAll(t, filepath.Join(f.ctlDir, "control.crt")),
		readAll(t, filepath.Join(f.ctlDir, "control.key")), a.addr); err != nil {
		t.Fatalf("the agent stopped serving after refusing two handshakes: %v", err)
	}
	if !a.proc.running() {
		t.Fatalf("the agent exited while refusing handshakes:\n%s", a.logs())
	}
}

// TestJailedAgentRejectsTraversal checks the path jail on the one configuration
// where it is a boundary rather than a decoration: exec disabled, so
// FileService is the only way to reach a path at all.
//
// The symlink case is the one that matters. Rejecting ".." before resolving is
// the classic mistake, and a symlink inside the jail pointing out of it walks
// straight through that check — which is why the jail resolves first and
// checks the resolved path.
func TestJailedAgentRejectsTraversal(t *testing.T) {
	f := newFleet(t)

	workspace := filepath.Join(f.root, "workspace")
	outside := filepath.Join(f.root, "outside")
	for _, dir := range []string{workspace, outside} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("create %s: %v", dir, err)
		}
	}
	writeFile(t, filepath.Join(workspace, "inside.txt"), []byte("in the jail\n"))
	writeFile(t, filepath.Join(outside, "secret.txt"), []byte("outside the jail\n"))
	if err := os.Symlink(outside, filepath.Join(workspace, "escape")); err != nil {
		t.Fatalf("create the escaping symlink: %v", err)
	}

	a := f.enroll("jailed-box", enrollOptions{roots: []string{workspace}, jailed: true})
	s := f.connect(t)

	sel := structured[selectResult](t, s.ok("fleet_select", map[string]any{"name": a.name}))
	if sel.Unconfined {
		t.Fatalf("an agent with exec disabled and roots configured must not report itself unconfined: %+v", sel)
	}
	// The root the agent reports is the *resolved* one — on macOS the temp
	// directory lives under a /var symlink to /private/var, and a jail that
	// compared the unresolved spelling would be comparing a path no syscall
	// ever sees.
	resolvedWorkspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatalf("resolve the workspace: %v", err)
	}
	if len(sel.AllowedRoots) != 1 || sel.AllowedRoots[0] != resolvedWorkspace {
		t.Fatalf("fleet_select reports roots %v, want [%s]", sel.AllowedRoots, resolvedWorkspace)
	}

	// A path inside the jail still works, or the rejections below would prove
	// nothing.
	read := structured[readResult](t, s.ok("fleet_read", map[string]any{
		"path": filepath.Join(workspace, "inside.txt"),
	}))
	if !contains(read.Content, "in the jail") {
		t.Fatalf("a file inside the jail did not read back: %+v", read)
	}

	for _, tc := range []struct {
		name string
		path string
	}{
		{"through a symlink that points out of the jail", filepath.Join(workspace, "escape", "secret.txt")},
		{"through a parent traversal", filepath.Join(workspace, "..", "outside", "secret.txt")},
		{"by absolute path", filepath.Join(outside, "secret.txt")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := s.fails("fleet_read", map[string]any{"path": tc.path})
			if !contains(msg, "roots") {
				t.Fatalf("the refusal does not say the path escaped the roots: %s", msg)
			}
			if contains(msg, "outside the jail") {
				t.Fatalf("the refusal leaked the file's contents: %s", msg)
			}
		})
	}

	// A write through the same symlink must fail, and must not create the file:
	// a jail that refuses the call after the syscall would be no jail at all.
	escaped := filepath.Join(outside, "written-through-the-symlink.txt")
	s.fails("fleet_write", map[string]any{
		"path":    filepath.Join(workspace, "escape", "written-through-the-symlink.txt"),
		"content": "should never land",
	})
	if _, err := os.Stat(escaped); err == nil {
		t.Fatalf("a refused write created %s anyway", escaped)
	}

	// And on this agent there is no second route to the filesystem: exec is
	// what makes the roots meaningless, so a jailed agent refuses it outright.
	msg := s.fails("fleet_exec", map[string]any{"argv": []string{"cat", filepath.Join(outside, "secret.txt")}})
	if !contains(msg, "exec") {
		t.Fatalf("exec on a jailed agent should be refused as disabled, got: %s", msg)
	}
}

// probeAgent dials an agent with a specific identity and issues one RPC.
//
// The pool is the product's own dialer, so the TLS configuration under test is
// the configuration fleet-mcp uses — not a hand-rolled client that might trust
// something the real one does not.
func probeAgent(t *testing.T, caPEM, certPEM, keyPEM []byte, addr string) error {
	t.Helper()

	pool, err := client.NewPool(client.Config{CACertPEM: caPEM, CertPEM: certPEM, KeyPEM: keyPEM})
	if err != nil {
		t.Fatalf("build a client pool: %v", err)
	}
	defer func() { _ = pool.Close() }()

	host, err := pool.Host("probe", addr)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err = host.Health(ctx, &sandboxdv1.HealthRequest{})
	return err
}

// signControlLeaf issues a control-profile leaf from the CA in caDir.
func signControlLeaf(t *testing.T, f *fleet, caDir, subject string) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: subject},
	}, key)
	if err != nil {
		t.Fatalf("build CSR: %v", err)
	}

	csrPath := filepath.Join(caDir, "leaf.csr")
	certPath := filepath.Join(caDir, "leaf.crt")
	writeFile(t, csrPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	runCLI(t, bins.fleetctl, []string{
		"ca", "sign", "--ca-dir", caDir,
		"--profile", "control", "--subject", subject,
		"--csr", csrPath, "--out", certPath,
	}, f.ctlEnv())

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return readAll(t, certPath), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func readAll(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
