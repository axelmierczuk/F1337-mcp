package ca_test

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/security/ca"
	"github.com/axelmierczuk/fleet-mcp/internal/security/enroll"
)

// signAgentLeaf issues a leaf the way enrollment does, so a test can hold a
// certificate that was signed by a particular CA and then ask whether it still
// verifies later.
func signAgentLeaf(t *testing.T, authority *ca.CA, name string) []byte {
	t.Helper()
	key, err := enroll.GenerateKey()
	require.NoError(t, err)
	csrDER, err := enroll.BuildCSR(key, name, nil, nil)
	require.NoError(t, err)
	_, certPEM, err := authority.SignCSR(csrDER, ca.SignOptions{Profile: ca.ProfileAgent, Subject: name})
	require.NoError(t, err)
	return certPEM
}

// verifiesAgainstBundle checks a leaf the way every consumer of ca.crt does:
// build a pool from the whole file with AppendCertsFromPEM, then verify. That
// is the operation the rotation has to keep working, so it is the operation the
// test performs rather than a proxy for it.
func verifiesAgainstBundle(t *testing.T, bundlePEM, leafPEM []byte) bool {
	t.Helper()
	return verifiesAgainstBundleFor(t, bundlePEM, leafPEM, x509.ExtKeyUsageServerAuth)
}

// verifiesAgainstBundleFor is verifiesAgainstBundle for a chosen usage, so a
// test can ask the question the two profiles differ on.
func verifiesAgainstBundleFor(t *testing.T, bundlePEM, leafPEM []byte, usage x509.ExtKeyUsage) bool {
	t.Helper()
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(bundlePEM))

	block, _ := pem.Decode(leafPEM)
	require.NotNil(t, block)
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{usage},
	})
	return err == nil
}

// signControlLeaf issues the client-auth leaf this workstation presents.
func signControlLeaf(t *testing.T, authority *ca.CA, name string) []byte {
	t.Helper()
	key, err := enroll.GenerateKey()
	require.NoError(t, err)
	csrDER, err := enroll.BuildCSR(key, name, nil, nil)
	require.NoError(t, err)
	_, certPEM, err := authority.SignCSR(csrDER, ca.SignOptions{Profile: ca.ProfileControl, Subject: name})
	require.NoError(t, err)
	return certPEM
}

// leafOf parses a PEM leaf for assertions about what it carries.
func leafOf(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

// A rotation widens what the fleet trusts, and widening trust is where a
// separation quietly stops holding. The profile split has to survive it: a
// control leaf signed by one root must not become presentable as an agent leaf
// because a second root is now trusted too.
//
// Both halves are asserted, because the separation rests on two independent
// things and either alone would let this pass while the other rotted. The
// extended key usage is what x509 enforces on the chain, and the organizational
// unit is what the agent's own policy matches on — internal/agent's
// authorizePeer — and neither is a property of the root that signed.
func TestRotation_KeepsTheProfileSeparationAcrossRoots(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	first, err := ca.Init(dir, false)
	require.NoError(t, err)

	// Issued under the outgoing root, before the rotation.
	oldControl := signControlLeaf(t, first, "fleet-mcp")
	oldAgent := signAgentLeaf(t, first, "build-box")

	_, err = ca.Stage(dir)
	require.NoError(t, err)
	_, err = ca.Activate(dir)
	require.NoError(t, err)

	rotated, err := ca.Load(dir)
	require.NoError(t, err)
	require.Len(t, rotated.TrustedRoots(), 2, "the overlap is the state this test is about")

	// And under the incoming one, after it.
	newControl := signControlLeaf(t, rotated, "fleet-mcp")
	newAgent := signAgentLeaf(t, rotated, "gpu-01")

	bundle := mustRead(t, dir)
	for name, leaf := range map[string][]byte{
		"control leaf under the outgoing root": oldControl,
		"control leaf under the incoming root": newControl,
	} {
		assert.True(t, verifiesAgainstBundleFor(t, bundle, leaf, x509.ExtKeyUsageClientAuth), "%s must still authenticate a client", name)
		assert.False(t, verifiesAgainstBundleFor(t, bundle, leaf, x509.ExtKeyUsageServerAuth),
			"%s verified as a server certificate; the bundle trusting two roots must not merge the two profiles", name)
		assert.Equal(t, []string{ca.ProfileControl.OrganizationalUnit()}, leafOf(t, leaf).Subject.OrganizationalUnit,
			"%s lost the organizational unit the agent authorizes on", name)
	}
	for name, leaf := range map[string][]byte{
		"agent leaf under the outgoing root": oldAgent,
		"agent leaf under the incoming root": newAgent,
	} {
		assert.True(t, verifiesAgainstBundleFor(t, bundle, leaf, x509.ExtKeyUsageServerAuth), "%s must still authenticate a server", name)
		assert.False(t, verifiesAgainstBundleFor(t, bundle, leaf, x509.ExtKeyUsageClientAuth),
			"%s verified as a client certificate; a sandbox holding its own key could then drive every other sandbox", name)
		assert.Equal(t, []string{ca.ProfileAgent.OrganizationalUnit()}, leafOf(t, leaf).Subject.OrganizationalUnit,
			"%s lost the organizational unit the agent authorizes on", name)
	}
}

// The whole point of the rotation: a certificate signed by the outgoing CA keeps
// verifying while both roots are trusted, and stops only when the operator
// explicitly retires the old one.
func TestRotation_KeepsLiveCertificatesValidUntilRetire(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	first, err := ca.Init(dir, false)
	require.NoError(t, err)

	oldLeaf := signAgentLeaf(t, first, "build-box")
	require.True(t, verifiesAgainstBundle(t, mustRead(t, dir), oldLeaf))

	// Stage: the incoming CA joins the bundle without issuing.
	staged, err := ca.Stage(dir)
	require.NoError(t, err)
	require.NotNil(t, staged.Staged)
	assert.True(t, staged.Staging())
	assert.Equal(t, first.Certificate().Raw, staged.Issuer.Raw, "staging must not change who signs")
	assert.True(t, verifiesAgainstBundle(t, mustRead(t, dir), oldLeaf))

	// A leaf signed during the staged window is still signed by the old CA, so
	// an agent that has not yet received the widened bundle keeps working.
	duringStage, err := ca.Load(dir)
	require.NoError(t, err)
	assert.Equal(t, first.Certificate().Raw, duringStage.Certificate().Raw)

	// Activate: the staged CA takes over. The old leaf must still verify.
	activated, err := ca.Activate(dir)
	require.NoError(t, err)
	assert.False(t, activated.Staging())
	assert.Equal(t, staged.Staged.Raw, activated.Issuer.Raw)
	assert.True(t, verifiesAgainstBundle(t, mustRead(t, dir), oldLeaf),
		"a certificate issued before the rotation must survive it — this is the whole criterion")

	// A leaf issued now is signed by the new CA and also verifies.
	afterActivate, err := ca.Load(dir)
	require.NoError(t, err)
	newLeaf := signAgentLeaf(t, afterActivate, "gpu-01")
	assert.True(t, verifiesAgainstBundle(t, mustRead(t, dir), newLeaf))

	// Retire: the old root goes, and only then does the old leaf stop verifying.
	retired, err := ca.Retire(dir)
	require.NoError(t, err)
	assert.Empty(t, retired.Superseded)
	assert.False(t, verifiesAgainstBundle(t, mustRead(t, dir), oldLeaf),
		"retiring is the step that breaks old certificates; it must actually do so")
	assert.True(t, verifiesAgainstBundle(t, mustRead(t, dir), newLeaf))
}

// The staged CA's key becomes the signing key, and the outgoing one is not left
// on disk. A spare CA signing key lying around is the thing this directory's
// whole handling exists to avoid.
func TestActivate_ReplacesTheSigningKeyAndDropsTheStagedFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	first, err := ca.Init(dir, false)
	require.NoError(t, err)
	oldKey := mustReadFile(t, filepath.Join(dir, "ca.key"))

	_, err = ca.Stage(dir)
	require.NoError(t, err)
	_, err = ca.Activate(dir)
	require.NoError(t, err)

	assert.NotEqual(t, oldKey, mustReadFile(t, filepath.Join(dir, "ca.key")))
	for _, name := range []string{"ca-next.crt", "ca-next.key"} {
		_, statErr := os.Stat(filepath.Join(dir, name))
		assert.True(t, os.IsNotExist(statErr), "%s should be gone after activation", name)
	}

	// And the loaded CA can actually sign, which is the property a mismatched
	// certificate-and-key pair would break silently until the next enrollment.
	reloaded, err := ca.Load(dir)
	require.NoError(t, err)
	assert.NotEqual(t, first.Certificate().Raw, reloaded.Certificate().Raw)
	require.NotEmpty(t, signAgentLeaf(t, reloaded, "build-box"))
}

// Activate writes two files. A crash between them leaves the incoming key
// beside the outgoing certificate, which is exactly the pair Load refuses — so
// if Activate reached for Load first, the one command that could finish the
// activation was the one command that could not run, and the whole CA directory
// stayed unloadable: `ca fingerprint`, `serve`, `enroll mint` and `list` all go
// through Load too.
//
// Re-running Activate has to repair it. This test simulates the crash exactly:
// the key write landed, the bundle write did not, and the staged files are
// still there because Activate discards them only once both writes are done.
func TestActivate_FinishesAnActivationInterruptedBetweenItsTwoWrites(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	first, err := ca.Init(dir, false)
	require.NoError(t, err)
	oldLeaf := signAgentLeaf(t, first, "build-box")

	staged, err := ca.Stage(dir)
	require.NoError(t, err)

	// The crash.
	nextKey := mustReadFile(t, filepath.Join(dir, "ca-next.key"))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.key"), nextKey, 0o600))
	_, err = ca.Load(dir)
	require.Error(t, err, "the fixture is only meaningful if this state is one Load rejects")

	// The repair.
	activated, err := ca.Activate(dir)
	require.NoError(t, err, "re-running activate must finish an interrupted activation")
	assert.Equal(t, staged.Staged.Raw, activated.Issuer.Raw)

	// And the directory is whole: it loads, it signs, and it has not quietly
	// dropped the outgoing root that live certificates still chain to.
	repaired, err := ca.Load(dir)
	require.NoError(t, err)
	assert.Equal(t, staged.Staged.Raw, repaired.Certificate().Raw)
	require.NotEmpty(t, signAgentLeaf(t, repaired, "gpu-01"))
	assert.True(t, verifiesAgainstBundle(t, mustRead(t, dir), oldLeaf),
		"the repair must not lose the outgoing root; retiring is a separate, explicit step")

	for _, name := range []string{"ca-next.crt", "ca-next.key"} {
		_, statErr := os.Stat(filepath.Join(dir, name))
		assert.True(t, os.IsNotExist(statErr), "%s should be gone once the activation completes", name)
	}
}

func TestStage_RefusesASecondStage(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	_, err := ca.Init(dir, false)
	require.NoError(t, err)

	_, err = ca.Stage(dir)
	require.NoError(t, err)

	_, err = ca.Stage(dir)
	require.ErrorIs(t, err, ca.ErrRotationStaged)
}

func TestActivate_RefusesWithNothingStaged(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	_, err := ca.Init(dir, false)
	require.NoError(t, err)

	_, err = ca.Activate(dir)
	require.ErrorIs(t, err, ca.ErrNoRotationStaged)
}

// Retiring mid-stage would drop the outgoing root while the incoming one is
// still not issuing, which is the one ordering that leaves the fleet trusting a
// CA that signs nothing.
func TestRetire_RefusesWhileARotationIsStaged(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	_, err := ca.Init(dir, false)
	require.NoError(t, err)
	_, err = ca.Stage(dir)
	require.NoError(t, err)

	_, err = ca.Retire(dir)
	require.ErrorIs(t, err, ca.ErrRotationStaged)
}

// A --force init is a hard reset. A rotation staged against the CA it replaced
// must not survive it, or a later activation would promote a root belonging to
// a CA that no longer exists.
func TestInitForce_DiscardsAStagedRotation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	_, err := ca.Init(dir, false)
	require.NoError(t, err)
	_, err = ca.Stage(dir)
	require.NoError(t, err)

	_, err = ca.Init(dir, true)
	require.NoError(t, err)

	state, err := ca.Status(dir)
	require.NoError(t, err)
	assert.False(t, state.Staging())
	assert.Empty(t, state.Superseded)
}

// Load must tell "there is no CA here" apart from "the CA here is broken", so
// callers can answer the first with the command that fixes it.
func TestLoad_ReportsAnUninitializedDirectoryDistinctly(t *testing.T) {
	_, err := ca.Load(filepath.Join(t.TempDir(), "nothing-here"))
	require.ErrorIs(t, err, ca.ErrNotInitialized)
}

// The migration path leans on this: a host that enrols during the overlap gets
// the whole bundle, so it already trusts the incoming CA by the time that CA
// starts issuing. CertPEM is what the enrollment response hands over.
func TestCertPEM_CarriesEveryTrustedRootDuringARotation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	first, err := ca.Init(dir, false)
	require.NoError(t, err)
	require.Len(t, first.TrustedRoots(), 1)

	staged, err := ca.Stage(dir)
	require.NoError(t, err)

	overlapping, err := ca.Load(dir)
	require.NoError(t, err)

	trusted := overlapping.TrustedRoots()
	require.Len(t, trusted, 2)
	assert.Equal(t, first.Certificate().Raw, trusted[0].Raw, "the issuer comes first")
	assert.Equal(t, staged.Staged.Raw, trusted[1].Raw)

	// And what an enrolling host is handed is that whole bundle, not just the
	// certificate doing the signing.
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(overlapping.CertPEM()))
	assert.True(t, verifiesAgainstBundle(t, overlapping.CertPEM(), signAgentLeaf(t, overlapping, "build-box")))
}

// The control plane caches the leaf it serves the enrollment endpoint with.
// After activation that leaf chains to a CA that no longer signs, so it must be
// re-issued rather than served — an enrolling host pins the new fingerprint and
// would reject the old chain.
func TestServerCertificate_IsReissuedAfterActivation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	first, err := ca.Init(dir, false)
	require.NoError(t, err)

	before, err := first.ServerCertificate([]string{"127.0.0.1"}, time.Hour)
	require.NoError(t, err)

	_, err = ca.Stage(dir)
	require.NoError(t, err)
	_, err = ca.Activate(dir)
	require.NoError(t, err)

	rotated, err := ca.Load(dir)
	require.NoError(t, err)
	after, err := rotated.ServerCertificate([]string{"127.0.0.1"}, time.Hour)
	require.NoError(t, err)

	assert.NotEqual(t, before.Certificate[0], after.Certificate[0], "the cached leaf must not survive the rotation")
	// The chain it presents ends at the CA now doing the signing, which is what
	// an enrolling host pins.
	require.Len(t, after.Certificate, 2)
	assert.Equal(t, rotated.Certificate().Raw, after.Certificate[1])
}

func mustRead(t *testing.T, dir string) []byte {
	t.Helper()
	return mustReadFile(t, filepath.Join(dir, "ca.crt"))
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}
