package fleetctl_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/registry"
	"github.com/axelmierczuk/fleet-mcp/internal/security/ca"
)

// `fleetctl add` is tested through the command an operator types, against hosts
// that really serve — one with mTLS and one without.
//
// Both are needed for any of it to mean anything. Every assertion about the
// unauthenticated host below is only evidence because the authenticated one, in
// the same registry through the same command, is refused for the opposite
// reason: a command that had simply stopped checking would satisfy half this
// file.

// servingHost answers Health, which is the whole of what add asks a host.
type servingHost struct {
	sandboxdv1.UnimplementedHostServiceServer
}

func (servingHost) Health(context.Context, *sandboxdv1.HealthRequest) (*sandboxdv1.HealthResponse, error) {
	return &sandboxdv1.HealthResponse{
		Status:       sandboxdv1.HealthResponse_STATUS_SERVING,
		AgentVersion: "test",
	}, nil
}

// servePlaintextHost starts a gRPC server with no TLS at all — what an agent
// configured with `tls.enabled: false` actually serves — on a real port, since
// this is reached through the address in a registry entry rather than through an
// injected dialer.
func servePlaintextHost(t *testing.T) string {
	t.Helper()
	return serveHost(t, grpc.NewServer())
}

// serveMTLSHost starts a gRPC server presenting a leaf from the fleet CA in
// configDir and requiring one back, which is what an enrolled agent serves.
func serveMTLSHost(t *testing.T, configDir, name string) string {
	t.Helper()

	authority, err := ca.Load(filepath.Join(configDir, "ca"))
	require.NoError(t, err)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: name},
	}, priv)
	require.NoError(t, err)
	// An IP SAN rather than a DNS one: the client verifies the leaf against the
	// host half of the address it dialled, and that is a literal here.
	_, certPEM, err := authority.SignCSR(csrDER, ca.SignOptions{
		Profile:     ca.ProfileAgent,
		Subject:     name,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	})
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	require.NoError(t, err)

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(authority.Certificate())
	return serveHost(t, grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS12,
	}))))
}

func serveHost(t *testing.T, s *grpc.Server) string {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	sandboxdv1.RegisterHostServiceServer(s, servingHost{})
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	return lis.Addr().String()
}

// fleetWithCA is a workstation that has run `ca init` and issued itself a
// control leaf: the mTLS operator.
func fleetWithCA(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	out, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code, out)
	out, code = run(t, dir, "ca", "sign", "--profile", "control")
	require.Equal(t, 0, code, out)
	return dir
}

// registered reads the registry back. Every assertion that a refusal wrote
// nothing goes through this rather than through the command's own output, which
// is the half a broken refusal would still get right.
func registered(t *testing.T, configDir string) []registry.Sandbox {
	t.Helper()
	fleet, err := registry.Open(filepath.Join(configDir, "registry.yaml"))
	require.NoError(t, err)
	all, err := fleet.List()
	require.NoError(t, err)
	return all
}

// The no-mTLS default, end to end through the CLI: register a host that serves
// plaintext, and see it in the fleet marked as what it is.
//
// This is #101 itself. Before it, the only ways to create this entry were a
// model calling fleet_add or an operator editing YAML.
func TestAdd_RegistersAnUnauthenticatedHostAndListShowsIt(t *testing.T) {
	dir := t.TempDir()
	address := servePlaintextHost(t)

	out, code := run(t, dir, "add", "tailnet-box", "--address", address, "--insecure", "--timeout", "5s")
	require.Equal(t, 0, code, out)
	assert.Contains(t, out, "added tailnet-box")
	assert.Contains(t, out, address)
	// The posture, and the probe that confirmed it. "serving" is the agent's own
	// answer, so this is the whole claim: something is there, and it is
	// answering in the posture the entry records.
	assert.Contains(t, out, "auth none")
	assert.Contains(t, out, "health serving")
	assert.Contains(t, out, "without mTLS", "the result must say what it registered")

	all := registered(t, dir)
	require.Len(t, all, 1)
	assert.Equal(t, "tailnet-box", all[0].Name)
	assert.Equal(t, address, all[0].Address)
	assert.True(t, all[0].Insecure, "the posture the operator asked for must be what was persisted")

	// And the command the README then tells them to run agrees. `list` is a
	// separate probe through a separate pool, so this is the two views of the
	// fleet meeting rather than one value printed twice.
	listOut, code := run(t, dir, "list", "--timeout", "5s")
	require.Equal(t, 0, code, listOut)
	assert.Contains(t, listOut, "AUTH")
	assert.Contains(t, listOut, "tailnet-box")
	assert.Contains(t, listOut, "none")
	assert.Contains(t, listOut, "auth none (tailnet-box)")
}

// The silent downgrade, refused. A host that answers without mTLS registered as
// authenticated would report `auth mtls` in every view of the fleet for a
// connection nothing authenticates, which is what #85 exists to prevent.
func TestAdd_RefusesAHostThatAnsweredWithoutMTLSWhenNotToldSo(t *testing.T) {
	dir := fleetWithCA(t)
	address := servePlaintextHost(t)

	out, code := runCapturingErrors(t, dir, "add", "tailnet-box", "--address", address, "--timeout", "5s")
	require.NotEqual(t, 0, code, out)
	assert.Contains(t, out, "answered without mTLS")
	assert.Contains(t, out, "--insecure", "the refusal must name the flag that fixes it")
	assert.Contains(t, out, "Nothing was registered")
	assert.Empty(t, registered(t, dir), "a refused registration must leave no entry")

	// The same command with the flag it named must work, or the refusal above is
	// a command that cannot register this host at all rather than one that
	// insisted on being told.
	out, code = run(t, dir, "add", "tailnet-box", "--address", address, "--insecure", "--timeout", "5s")
	require.Equal(t, 0, code, out)
	assert.Contains(t, out, "auth none")
	require.Len(t, registered(t, dir), 1)
}

// The other direction, which #85 was equally explicit about: --insecure on a
// host that does authenticate. It costs only failed calls rather than a false
// claim, but it is still a posture this workstation got wrong, and a fleet
// member every call fails against is worth one refusal now.
func TestAdd_RefusesAnAuthenticatedHostRegisteredAsInsecure(t *testing.T) {
	dir := fleetWithCA(t)
	address := serveMTLSHost(t, dir, "build-box")

	out, code := runCapturingErrors(t, dir, "add", "build-box", "--address", address, "--insecure", "--timeout", "5s")
	require.NotEqual(t, 0, code, out)
	assert.Contains(t, out, "answered over mTLS")
	assert.Contains(t, out, "drop --insecure", "the refusal must name the flag that fixes it")
	assert.Contains(t, out, "Nothing was registered")
	assert.Empty(t, registered(t, dir), "a refused registration must leave no entry")
}

// The mTLS path: an enrolled-shaped host, registered without --insecure, and
// confirmed over a real handshake.
func TestAdd_RegistersAnAuthenticatedHost(t *testing.T) {
	dir := fleetWithCA(t)
	address := serveMTLSHost(t, dir, "build-box")

	out, code := run(t, dir, "add", "build-box", "--address", address, "--timeout", "5s")
	require.Equal(t, 0, code, out)
	assert.Contains(t, out, "auth mtls")
	assert.Contains(t, out, "health serving")
	assert.Contains(t, out, "does not enroll", "the result must say what registering did not do")

	all := registered(t, dir)
	require.Len(t, all, 1)
	assert.False(t, all[0].Insecure)
}

// A typo'd address is caught where it is still cheap, rather than becoming a
// fleet member `list` reports as unreachable forever.
func TestAdd_RefusesAnAddressNothingAnswers(t *testing.T) {
	dir := t.TempDir()

	// A held-open socket that never answers, which is the powered-off host that
	// still routes. A refused connection would fail on its own and prove less.
	out, code := runCapturingErrors(t, dir, "add", "ghost", "--address", blackHole(t), "--insecure", "--timeout", "300ms")
	require.NotEqual(t, 0, code, out)
	assert.Contains(t, out, "nothing answered at")
	assert.Contains(t, out, "--no-probe", "the refusal must name how to register a host that is not up yet")
	assert.Empty(t, registered(t, dir), "a refused registration must leave no entry")

	// And the unroutable shape too, so the refusal is not specific to silence.
	out, code = runCapturingErrors(t, dir, "add", "refused", "--address", "127.0.0.1:1", "--insecure", "--timeout", "300ms")
	require.NotEqual(t, 0, code, out)
	assert.Contains(t, out, "nothing answered at")
	assert.Empty(t, registered(t, dir))
}

// --no-probe is the one legitimate reason to write an entry nothing confirmed:
// a host that is not up yet. The entry says so, because "unknown" is also what
// a probe that could not authenticate produces.
//
// The bound is far above the deadline: this is not measuring latency, it is
// catching a --no-probe that dials anyway, which against this address would
// block rather than return.
func TestAdd_NoProbeRegistersWithoutContactingTheHost(t *testing.T) {
	dir := t.TempDir()
	address := blackHole(t)

	select {
	case out := <-runAsync(t, dir, "add", "not-up-yet", "--address", address, "--insecure", "--no-probe"):
		assert.Contains(t, out, "added not-up-yet")
		assert.Contains(t, out, "health unknown")
		assert.Contains(t, out, "--no-probe", "an unconfirmed entry must say why it is unconfirmed")
	case <-time.After(30 * time.Second):
		t.Fatal("`add --no-probe` contacted the host; it must write the entry without dialling")
	}

	all := registered(t, dir)
	require.Len(t, all, 1)
	assert.Equal(t, "not-up-yet", all[0].Name)
}

// A workstation with no control certificate cannot prove an mTLS host's
// posture, and that is a fact about this machine rather than about the host.
// Refusing over it would answer a question about the fleet with a question
// about the workstation — the same rule `list` applies when it reports health
// as unknown rather than failing.
func TestAdd_RegistersWhenThisWorkstationCannotProveThePosture(t *testing.T) {
	dir := t.TempDir()
	out, code := run(t, dir, "ca", "init")
	require.Equal(t, 0, code, out)
	// No `ca sign --profile control`: there is a CA but no leaf to present.
	address := serveMTLSHost(t, dir, "build-box")

	out, code = run(t, dir, "add", "build-box", "--address", address, "--timeout", "5s")
	require.Equal(t, 0, code, out)
	assert.Contains(t, out, "auth mtls")
	assert.Contains(t, out, "health unknown")
	assert.Contains(t, out, "not verified", "an entry nothing could confirm must say so")
	assert.Contains(t, out, "ca sign", "and must name what is missing")
	require.Len(t, registered(t, dir), 1)
}

// Registering never repoints an existing name: that is how a later call reaches
// the wrong host. The refusal names the address it kept and the command that
// releases it — `fleetctl remove`, not the tool a model would call.
func TestAdd_RefusesToOverwriteAnExistingName(t *testing.T) {
	dir := t.TempDir()

	out, code := run(t, dir, "add", "build-box", "--address", "build-box.internal:8722", "--no-probe")
	require.Equal(t, 0, code, out)

	out, code = runCapturingErrors(t, dir, "add", "build-box", "--address", "elsewhere.internal:8722", "--no-probe")
	require.NotEqual(t, 0, code, out)
	assert.Contains(t, out, "already registered")
	assert.Contains(t, out, "build-box.internal:8722", "the refusal must name the address it kept")
	assert.Contains(t, out, "fleetctl remove build-box", "the refusal must name the operator's remedy, not the model's")

	all := registered(t, dir)
	require.Len(t, all, 1)
	assert.Equal(t, "build-box.internal:8722", all[0].Address, "the address must be unchanged")

	// And a taken name is answered without dialling: the registration cannot
	// succeed whatever the host says, so the host is never contacted. Asserted
	// two ways, because either alone is weak — the answer is the registry's
	// rather than the probe's, and it arrives without waiting on a host that
	// never replies. The bound is far above the deadline: this is not measuring
	// latency, it is catching a command that probes first.
	select {
	case out := <-runAsyncCapturingErrors(t, dir, "add", "build-box", "--address", blackHole(t), "--insecure", "--timeout", "60s"):
		// The registry's answer, not the probe's. A command that dialled first
		// would report the silence and send the operator looking at a host that
		// was never the problem.
		assert.Contains(t, out, "already registered")
		assert.NotContains(t, out, "nothing answered")
	case <-time.After(30 * time.Second):
		t.Fatal("`add` on a taken name waited on the host; the registry already refuses it")
	}
}

// What cannot be registered is rejected before anything is dialled, and leaves
// nothing behind. The rules themselves are the registry's and are tested there;
// this is that the command applies them and that a rejection is not a
// half-written entry.
func TestAdd_RejectsWhatCannotBeRegistered(t *testing.T) {
	for name, args := range map[string][]string{
		"no name":     {"add", "", "--address", "host:8722", "--no-probe"},
		"bad name":    {"add", "build box", "--address", "host:8722", "--no-probe"},
		"handle name": {"add", "sbx_deadbeef", "--address", "host:8722", "--no-probe"},
		"no address":  {"add", "build-box", "--no-probe"},
		"bad address": {"add", "build-box", "--address", "build-box", "--no-probe"},
		"url address": {"add", "build-box", "--address", "https://build-box:8722", "--no-probe"},
		"bad label":   {"add", "build-box", "--address", "host:8722", "--label", "data centre=west", "--no-probe"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			out, code := runCapturingErrors(t, dir, args...)
			require.NotEqual(t, 0, code, out)
			assert.Empty(t, registered(t, dir), "a rejected registration must leave no entry")
		})
	}
}

// A malformed address is named as one, rather than spending the timeout failing
// to connect to it and reporting a silence.
//
// Deliberately without --no-probe: the checks run before anything is dialled,
// and the whole difference this makes is which of two errors the operator gets.
// A command that validated only on the way to the registry would reach here
// through the probe and answer "nothing answered at build-box", which sends
// somebody looking at the host instead of at what they typed.
func TestAdd_NamesAMalformedAddressRatherThanDiallingIt(t *testing.T) {
	dir := t.TempDir()

	out, code := runCapturingErrors(t, dir, "add", "build-box", "--address", "build-box", "--insecure", "--timeout", "30s")
	require.NotEqual(t, 0, code, out)
	assert.Contains(t, out, "not host:port", "the rejection must name what is wrong with the address")
	assert.NotContains(t, out, "nothing answered", "a malformed address must be rejected rather than dialled")
	assert.Empty(t, registered(t, dir))

	// And a name the registry will not accept, before the dial too.
	out, code = runCapturingErrors(t, dir, "add", "sbx_deadbeef", "--address", blackHole(t), "--insecure", "--timeout", "30s")
	require.NotEqual(t, 0, code, out)
	assert.Contains(t, out, "sbx_", "the rejection must name what is wrong with the name")
	assert.NotContains(t, out, "nothing answered")
	assert.Empty(t, registered(t, dir))
}

// The JSON document is the whole result, so a provisioning script never has to
// parse the table to reach a field the operator can see.
func TestAdd_JSONCarriesTheWholeResult(t *testing.T) {
	dir := t.TempDir()
	address := servePlaintextHost(t)

	out, code := run(t, dir, "add", "gpu-01", "--address", address, "--insecure",
		"--label", "arch=arm64", "--label", "owner=platform team", "--timeout", "5s", "--json")
	require.Equal(t, 0, code, out)

	var doc struct {
		Name    string            `json:"name"`
		Address string            `json:"address"`
		Auth    string            `json:"auth"`
		Labels  map[string]string `json:"labels"`
		Health  string            `json:"health"`
		Note    string            `json:"note"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &doc), "output is not one JSON document:\n%s", out)
	assert.Equal(t, "gpu-01", doc.Name)
	assert.Equal(t, address, doc.Address)
	assert.Equal(t, "none", doc.Auth)
	assert.Equal(t, "serving", doc.Health)
	assert.Equal(t, map[string]string{"arch": "arm64", "owner": "platform team"}, doc.Labels)
	assert.Contains(t, doc.Note, "without mTLS")

	// Labels reach the registry, not just the result.
	all := registered(t, dir)
	require.Len(t, all, 1)
	assert.Equal(t, map[string]string{"arch": "arm64", "owner": "platform team"}, all[0].Labels)

	// Nothing but the document on stdout: a script parsing it must not find a
	// warning in the middle of it, and registering an unauthenticated host is
	// the command most likely to emit one.
	assert.True(t, strings.HasPrefix(strings.TrimSpace(out), "{"), "stdout does not begin with the document:\n%s", out)
}

// `fleetctl add` and the fleet_add tool write the same entry. This is the
// operator's half read back through the same registry the model's half writes,
// which is what makes "one code path" checkable from here.
func TestAdd_WritesTheEntryTheModelsToolWrites(t *testing.T) {
	dir := t.TempDir()
	out, code := run(t, dir, "add", "build-box", "--address", "build-box.internal:8722",
		"--insecure", "--label", "arch=arm64", "--no-probe")
	require.Equal(t, 0, code, out)

	fleet, err := registry.Open(filepath.Join(dir, "registry.yaml"))
	require.NoError(t, err)
	sb, err := fleet.Get("build-box")
	require.NoError(t, err)

	// The note is the registry's, byte for byte, so the operator and the model
	// are told the same thing about what registering did not do.
	assert.Contains(t, out, registry.NoteRegisteredInsecure)
	assert.Equal(t, "build-box.internal:8722", sb.Address)
	assert.True(t, sb.Insecure)
	assert.Equal(t, map[string]string{"arch": "arm64"}, sb.Labels)
	assert.False(t, sb.EnrolledAt.IsZero(), "a registered entry must be dated")
}
