package enroll_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/security/enroll"
)

// Rounds 1, 2 and 3 each found the same defect one field over: listen_addresses
// widened the leaf's SANs, then requested_name widened the leaf's SANs, then
// requested_name widened the leaf's subject. Each round fixed the field it was
// looking at. Round 3's remedy was a trust table in prose enumerating every
// caller-controlled input — which is only worth what its completeness is worth,
// and prose does not fail a build when a seventh field is added to the proto.
//
// This is that table as a test. Every field of EnrollRequest, and of every
// message nested inside it, has to appear here with an explicit account of what
// it may influence. Adding a field to the proto without adding it here fails
// TestEnrollRequest_EveryFieldIsAccountedFor, and the person adding it has to
// answer the question the previous three rounds each answered too late: can
// this widen anything?
type fieldAccount struct {
	// boundedText marks a field carrying free text the enrolling host chooses
	// for itself. Everything so marked is persisted in the fleet registry and
	// printed back into an operator's terminal, so it must be length- and
	// charset-bounded before it gets there —
	// TestEnrollRequest_EveryBoundedFieldIsBoundedInPractice proves each one
	// actually is, so this column cannot become a claim the code does not keep.
	boundedText bool
	// why records what this field reaches and why it cannot widen an identity.
	why string
}

var enrollRequestSurface = map[string]fieldAccount{
	"token": {
		why: "Admission only. Constant-time compared against a stored SHA-256; " +
			"it selects a TokenRecord the operator minted, or it fails. Never persisted, never printed.",
	},
	"csr_der": {
		why: "SubjectPublicKeyInfo only. The leaf template is built fresh from SignOptions, so the " +
			"CSR's own subject, SANs, extensions and attributes are discarded — asserted by " +
			"TestEnroll_CSRContentsDoNotReachTheLeaf.",
	},
	"requested_name": {
		boundedText: true,
		why: "Registry label only. It must equal the token's reserved name, or be empty when the token " +
			"reserves one; a name the control plane did not choose reaches neither the subject nor the " +
			"SANs — asserted by TestEnroll_HostChosenNameStaysOutOfTheSubject.",
	},
	"platform.os":             {boundedText: true, why: "Registry value, printed by `fleetctl list`. Not an identity."},
	"platform.arch":           {boundedText: true, why: "Registry value, printed by `fleetctl list`. Not an identity."},
	"platform.kernel_version": {boundedText: true, why: "Registry value. Not an identity."},
	"platform.hostname":       {boundedText: true, why: "Registry value. Deliberately not the certified name — a host's claim about itself."},
	"platform.path_separator": {boundedText: true, why: "Registry value. Not an identity."},
	"listen_addresses": {
		boundedText: true,
		why: "May only narrow. Every host must already be in the token's authorized set; a loopback IP is " +
			"the one exception, allowed unconditionally because it names the enrolling host and nothing " +
			"else — asserted by TestEnroll_RequestedAddressesCannotWidenTheCertificate. Entry [0] becomes " +
			"the registry address when the token authorized none, which is the residual round 3 recorded.",
	},
	"agent_version": {boundedText: true, why: "Registry value, printed by `fleetctl list`. Not an identity."},
}

// TestEnrollRequest_EveryFieldIsAccountedFor is the test that ends the class.
// It fails when a field is added to EnrollRequest — or to any message reachable
// from it — without someone deciding what that field is allowed to influence.
func TestEnrollRequest_EveryFieldIsAccountedFor(t *testing.T) {
	t.Parallel()
	inProto := map[string]bool{}
	walkFields(t, (&sandboxdv1.EnrollRequest{}).ProtoReflect().Descriptor(), "", inProto, 0)

	for _, name := range sortedKeys(inProto) {
		if _, ok := enrollRequestSurface[name]; !ok {
			t.Errorf("EnrollRequest field %q is not accounted for in enrollRequestSurface.\n"+
				"Every caller-controlled field has to say what it reaches and whether it can widen an "+
				"identity. Three consecutive audit rounds found an escalation in a field nobody had "+
				"asked that question about — add the entry, then make it true.", name)
		}
	}
	for _, name := range sortedKeys(toSet(enrollRequestSurface)) {
		if !inProto[name] {
			t.Errorf("enrollRequestSurface accounts for %q, which is no longer a field of EnrollRequest; "+
				"remove the stale entry so the table keeps meaning what it says", name)
		}
	}
}

// TestEnrollRequest_EveryBoundedFieldIsBoundedInPractice keeps the table above
// from becoming prose of its own. A field marked boundedText is claimed to be
// length- and charset-checked before it is persisted or printed; this drives
// each one through the real RPC and requires the claim to hold.
//
// It is the half that catches the actual mistake: someone adds
// platform.cpu_model, records it here as bounded because every other platform
// field is, and does not add it to checkHostDescription.
func TestEnrollRequest_EveryBoundedFieldIsBoundedInPractice(t *testing.T) {
	t.Parallel()
	hostile := map[string]string{
		// Longer than any bound in this package — 128 bytes for a name, 256 for
		// a self-description — so one value tests them all.
		"oversized": strings.Repeat("a", 100_000),
		// The reason the charset is bounded at all: this rewrites what an
		// operator sees about their own fleet.
		"terminal escape sequence": "linux\x1b[2J\x1b[31m ALL SANDBOXES HEALTHY",
	}

	for _, field := range sortedKeys(toSet(enrollRequestSurface)) {
		if !enrollRequestSurface[field].boundedText {
			continue
		}
		for label, value := range hostile {
			t.Run(field+"/"+label, func(t *testing.T) {
				caObj := newTestCA(t)
				tokens := enroll.NewTokenStore()
				fleet := &recordingFleet{}
				svc := &enroll.Service{Tokens: tokens, CA: caObj, Fleet: fleet}
				lis := startControlPlane(t, svc, caObj)

				token, _, err := tokens.Mint(enroll.MintOptions{Name: "build-box"})
				require.NoError(t, err)

				req := &sandboxdv1.EnrollRequest{Token: token}
				setStringField(t, req, field, value)

				_, err = enrollOnce(t, lis, caObj, req)
				require.Error(t, err, "field %q is recorded as bounded but %s was accepted", field, label)
				assert.Equal(t, codes.InvalidArgument, status.Code(err),
					"a caller-supplied bound is the caller's fault, so it is InvalidArgument")
				assert.Empty(t, fleet.recorded, "a rejected request must not reach the fleet registry")
			})
		}
	}
}

// The bound must still admit what a real host reports, or the check is a
// different bug. This is the companion assertion to the one above: the same
// fields, populated the way an ordinary Windows or Linux host populates them.
func TestEnrollRequest_BoundedFieldsStillAdmitARealHost(t *testing.T) {
	t.Parallel()
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	fleet := &recordingFleet{}
	svc := &enroll.Service{Tokens: tokens, CA: caObj, Fleet: fleet}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{
		Token:           token,
		AgentVersion:    "0.1.0-rc.2+build.7 (go1.25.13)",
		ListenAddresses: []string{"127.0.0.1:9443"},
		Platform: &sandboxdv1.Platform{
			Os:            "windows",
			Arch:          "amd64",
			KernelVersion: "10.0.26100.2894 (WinBuild.160101.0800)",
			Hostname:      "build-box.corp.example.com",
			PathSeparator: `\`,
		},
	})
	require.NoError(t, err)
	require.Len(t, fleet.recorded, 1)
}

// walkFields collects the dotted path of every scalar field reachable from d.
// A message-typed field contributes its own fields rather than itself, because
// "platform" is not a sink — "platform.hostname" is.
func walkFields(t *testing.T, d protoreflect.MessageDescriptor, prefix string, out map[string]bool, depth int) {
	t.Helper()
	// Nothing in this schema is recursive, and a schema that became recursive
	// would be a bigger question than this test; refuse to hang on it.
	require.Less(t, depth, 8, "EnrollRequest nests more than 8 message levels deep")

	fields := d.Fields()
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		name := prefix + string(f.Name())
		if f.Kind() == protoreflect.MessageKind && !f.IsMap() && !f.IsList() {
			walkFields(t, f.Message(), name+".", out, depth+1)
			continue
		}
		out[name] = true
	}
}

// setStringField sets a dotted field path to value, appending rather than
// assigning for a repeated field. It goes through protoreflect rather than the
// generated setters so that the test walks the same field list the proto
// declares, instead of a hand-written copy of it that can drift.
func setStringField(t *testing.T, req *sandboxdv1.EnrollRequest, path, value string) {
	t.Helper()
	m := req.ProtoReflect()
	parts := strings.Split(path, ".")
	for ; len(parts) > 1; parts = parts[1:] {
		fd := m.Descriptor().Fields().ByName(protoreflect.Name(parts[0]))
		require.NotNil(t, fd, "no field %q on %s", parts[0], m.Descriptor().FullName())
		m = m.Mutable(fd).Message()
	}
	fd := m.Descriptor().Fields().ByName(protoreflect.Name(parts[0]))
	require.NotNil(t, fd, "no field %q on %s", parts[0], m.Descriptor().FullName())
	require.Equal(t, protoreflect.StringKind, fd.Kind(),
		"field %q is recorded as bounded text but is not a string", path)

	if fd.IsList() {
		m.Mutable(fd).List().Append(protoreflect.ValueOfString(value))
		return
	}
	m.Set(fd, protoreflect.ValueOfString(value))
}

func toSet(m map[string]fieldAccount) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
