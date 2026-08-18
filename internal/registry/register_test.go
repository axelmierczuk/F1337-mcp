package registry_test

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/registry"
)

// The bounds and the refusal to overwrite are tested here, in the package that
// owns them, rather than at each front end. They moved out of the MCP tools
// package when `fleetctl add` arrived: the operator and the model register
// through one function, so there is one place these rules can be wrong.

// TestCheckAddress_RejectsWhatCannotBeDialed. The host half becomes the TLS
// server name the agent's certificate is verified against, so an address that
// is not host:port fails later as a handshake error naming neither.
func TestCheckAddress_RejectsWhatCannotBeDialed(t *testing.T) {
	t.Parallel()
	for _, good := range []string{"build-box:8722", "build-box.internal:8722", "127.0.0.1:8722", "[::1]:8722", "host:65535"} {
		assert.NoErrorf(t, registry.CheckAddress(good), "%q should be accepted", good)
	}
	for _, bad := range []string{"", "build-box", "build-box:", ":8722", "build-box:0", "build-box:65536", "build-box:-1", "https://build-box:8722", "build/box:8722", "build box:8722"} {
		assert.Errorf(t, registry.CheckAddress(bad), "%q should be rejected", bad)
	}
}

func TestCheckName(t *testing.T) {
	t.Parallel()
	for _, good := range []string{"build-box", "gpu_01", "a", "host.internal"} {
		assert.NoErrorf(t, registry.CheckName(good), "%q should be accepted", good)
	}
	for _, bad := range []string{"", " ", "build box", "build\tbox", "café", "sbx_deadbeef"} {
		assert.Errorf(t, registry.CheckName(bad), "%q should be rejected", bad)
	}
}

// TestCheckLabels guards the free-form half of a registration: an operator or a
// model supplies it, the registry stores it, and every fleet listing carries it.
func TestCheckLabels(t *testing.T) {
	t.Parallel()
	assert.NoError(t, registry.CheckLabels(nil))
	assert.NoError(t, registry.CheckLabels(map[string]string{"arch": "arm64", "owner": "platform team", "empty": ""}))

	tooMany := map[string]string{}
	for i := range registry.MaxLabels + 1 {
		tooMany[strconv.Itoa(i)] = "v"
	}
	for name, labels := range map[string]map[string]string{
		"too many":          tooMany,
		"empty key":         {"": "v"},
		"key with a space":  {"data centre": "west"},
		"non-ASCII key":     {"café": "v"},
		"oversized key":     {strings.Repeat("k", registry.MaxLabelKeyLength+1): "v"},
		"oversized value":   {"k": strings.Repeat("v", registry.MaxLabelValueLength+1)},
		"value with a tab":  {"k": "a\tb"},
		"value with a line": {"k": "a\nb"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := registry.CheckLabels(labels)
			require.Error(t, err)
			assert.Contains(t, strings.ToLower(err.Error()), "label")
			assert.Less(t, len(err.Error()), 512, "the rejection must not echo the input back whole")
		})
	}

	// A rejected key is still named — the operator has to know which one — but
	// on a rune boundary, or the error itself is invalid UTF-8.
	err := registry.CheckLabels(map[string]string{strings.Repeat("é", 200): "v"})
	require.Error(t, err)
	assert.True(t, utf8.ValidString(err.Error()), "the rejection is not valid UTF-8: %q", err.Error())
}

// TestRegister_RejectsBeforeTouchingTheRegistry: every check runs before the
// file is written, so a malformed registration leaves nothing behind.
func TestRegister_RejectsBeforeTouchingTheRegistry(t *testing.T) {
	t.Parallel()

	for name, sb := range map[string]registry.Sandbox{
		"no name":     {Address: "host:8722"},
		"bad name":    {Name: "build box", Address: "host:8722"},
		"handle name": {Name: "sbx_deadbeef", Address: "host:8722"},
		"no address":  {Name: "build-box"},
		"bad address": {Name: "build-box", Address: "build-box"},
		"url address": {Name: "build-box", Address: "https://build-box:8722"},
		"bad label":   {Name: "build-box", Address: "host:8722", Labels: map[string]string{"": "v"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			reg, _ := newTestRegistry(t)
			_, err := reg.Register(sb)
			require.Error(t, err)

			all, listErr := reg.List()
			require.NoError(t, listErr)
			assert.Empty(t, all, "a rejected registration must not leave a registry entry")
		})
	}
}

// TestRegister_TrimsAndWrites: the trimming is shared too. An operator's shell
// and a model's JSON both hand over stray whitespace, and a name with a
// trailing space is a name no later command can type.
func TestRegister_TrimsAndWrites(t *testing.T) {
	t.Parallel()
	reg, _ := newTestRegistry(t)

	out, err := reg.Register(registry.Sandbox{Name: "  build-box  ", Address: " build-box.internal:8722\t"})
	require.NoError(t, err)
	assert.Equal(t, "build-box", out.Sandbox.Name)
	assert.Equal(t, "build-box.internal:8722", out.Sandbox.Address)
	assert.Equal(t, registry.NoteRegistered, out.Note)
	assert.Contains(t, out.Note, "does not enroll")

	sb, err := reg.Get("build-box")
	require.NoError(t, err)
	assert.Equal(t, "build-box.internal:8722", sb.Address)
	assert.False(t, sb.EnrolledAt.IsZero(), "a registered entry must be dated")
}

// TestRegister_SaysWhatItRegisteredWithoutMTLS. The two notes are different
// sentences rather than one with a suffix: the mTLS note says what still has to
// happen for the entry to work, and this one says what never will.
func TestRegister_SaysWhatItRegisteredWithoutMTLS(t *testing.T) {
	t.Parallel()
	reg, _ := newTestRegistry(t)

	out, err := reg.Register(registry.Sandbox{Name: "tailnet-box", Address: "100.83.4.17:8722", Insecure: true})
	require.NoError(t, err)
	assert.Equal(t, registry.NoteRegisteredInsecure, out.Note)
	assert.Contains(t, out.Note, "without mTLS")
	assert.NotEqual(t, registry.NoteRegistered, out.Note)

	sb, err := reg.Get("tailnet-box")
	require.NoError(t, err)
	assert.True(t, sb.Insecure, "the posture the caller asked for must be what was persisted")
}

// TestRegister_RefusesToOverwriteAnExistingName. Silently repointing a name at
// a new address is how a later call reaches the wrong host, so the error names
// the address it kept — and carries it, so each front end can name its own
// remedy without re-deriving the fact.
func TestRegister_RefusesToOverwriteAnExistingName(t *testing.T) {
	t.Parallel()
	reg, _ := newTestRegistry(t)

	_, err := reg.Register(registry.Sandbox{Name: "build-box", Address: "build-box.internal:8722"})
	require.NoError(t, err)

	_, err = reg.Register(registry.Sandbox{Name: "build-box", Address: "elsewhere.internal:8722"})
	require.Error(t, err)
	assert.ErrorIs(t, err, registry.ErrExists, "a caller that only asks whether the name is taken must still get an answer")

	var duplicate *registry.DuplicateError
	require.ErrorAs(t, err, &duplicate)
	assert.Equal(t, "build-box", duplicate.Name)
	assert.Equal(t, "build-box.internal:8722", duplicate.Address, "the error must carry the address it kept")
	assert.Contains(t, err.Error(), "already registered")
	assert.Contains(t, err.Error(), "build-box.internal:8722")

	sb, err := reg.Get("build-box")
	require.NoError(t, err)
	assert.Equal(t, "build-box.internal:8722", sb.Address, "the address must be unchanged")
}

// The registry file itself is not this test's business, but a Register that
// returned a Registration and wrote nothing would satisfy everything above if
// the reads went through the same in-memory value. They do not — Get reloads —
// and this asserts it from a second handle on the same file.
func TestRegister_PersistsToTheFile(t *testing.T) {
	t.Parallel()
	reg, path := newTestRegistry(t)

	_, err := reg.Register(registry.Sandbox{Name: "build-box", Address: "build-box.internal:8722", Insecure: true})
	require.NoError(t, err)

	reopened, err := registry.Open(path)
	require.NoError(t, err)
	sb, err := reopened.Get("build-box")
	require.NoError(t, err)
	assert.Equal(t, "build-box.internal:8722", sb.Address)
	assert.True(t, sb.Insecure)
}

// A DuplicateError must keep matching ErrExists, because enrollment's recorder
// and every other caller test for that and not for the type.
func TestDuplicateError_MatchesErrExists(t *testing.T) {
	t.Parallel()
	err := error(&registry.DuplicateError{Name: "a", Address: "a:1"})
	assert.True(t, errors.Is(err, registry.ErrExists))
}
