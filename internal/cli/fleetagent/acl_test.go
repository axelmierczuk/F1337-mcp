package fleetagent_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/cli/fleetagent"
)

// The icacls grants, which nothing on any runner here can let happen.
//
// Applying an ACL needs an elevated Windows token, so these are in the same
// position the Scheduled Task's argv was in before #79's first audit round:
// composed in a _windows.go file, invoked through a function with no seam, and
// asserted by nothing anywhere. They are also the half of #74 that makes the
// new default work — %ProgramData%\fleet is created by an elevated install, so
// without them an ordinary operator account cannot write its own state
// directory or read the certificate `enroll` left behind, and the daemon fails
// every start on its own files.

// icaclsRecorder captures the complete command line icacls.exe would have been
// given, verbatim.
//
// Verbatim matters: the recorder used to be handed the path and the options
// separately and put them back together itself, which meant every test here
// asserted a command line this package had never actually assembled — and
// icacls takes the object first and rejects it anywhere else. The seam hands
// over the finished argv now, so a transposition is a failure here rather than
// an install that grants nothing on a real host.
type icaclsRecorder struct {
	calls [][]string
	fail  error
}

func (r *icaclsRecorder) run(argv ...string) error {
	r.calls = append(r.calls, append([]string(nil), argv...))
	return r.fail
}

// The state and log directories: modify, inheritable, and applied to what is
// already there.
func TestWindowsACL_GrantsTheOwnedDirectoriesModify(t *testing.T) {
	rec := &icaclsRecorder{}
	require.NoError(t, fleetagent.NewWindowsACLForTest(rec.run).
		GrantOwnedDir(`C:\ProgramData\fleet\state`, `WORKSTATION\axel`))

	require.Len(t, rec.calls, 1)
	assert.Equal(t, []string{
		`C:\ProgramData\fleet\state`, "/grant", `WORKSTATION\axel:(OI)(CI)M`, "/T",
	}, rec.calls[0],
		"(OI)(CI) so new files inherit it, M because the daemon writes here, /T so the grant reaches what an earlier install already put there")
	assert.Equal(t, `C:\ProgramData\fleet\state`, rec.calls[0][0],
		"icacls takes the object first: `icacls /grant acct:(R) path` is a usage error, and this is the only place that ordering is decided")
}

// The enrollment material: read on each file, read-and-traverse on the
// directory when install judged it fleet's to hand over.
func TestWindowsACL_GrantsTheEnrollmentMaterialRead(t *testing.T) {
	rec := &icaclsRecorder{}
	files := []string{`C:\ProgramData\fleet\agent.yaml`, `C:\ProgramData\fleet\agent.key`}

	require.NoError(t, fleetagent.NewWindowsACLForTest(rec.run).
		GrantEnrollment(`WORKSTATION\axel`, `C:\ProgramData\fleet`, files))

	require.Len(t, rec.calls, 3)
	assert.Equal(t, []string{`C:\ProgramData\fleet\agent.yaml`, "/grant", `WORKSTATION\axel:(R)`}, rec.calls[0])
	assert.Equal(t, []string{`C:\ProgramData\fleet\agent.key`, "/grant", `WORKSTATION\axel:(R)`}, rec.calls[1])
	assert.Equal(t, []string{`C:\ProgramData\fleet`, "/grant", `WORKSTATION\axel:(OI)(CI)(RX)`}, rec.calls[2],
		"the daemon reads its enrollment directory; it does not write it")

	// A directory the caller judged not fleet's to reassign is left alone, and
	// the files inside it are still handed over.
	rec = &icaclsRecorder{}
	require.NoError(t, fleetagent.NewWindowsACLForTest(rec.run).
		GrantEnrollment(`WORKSTATION\axel`, "", files))
	assert.Len(t, rec.calls, 2, "no directory was named, so no directory may be granted")
}

// A failure to grant is a failure to install, and it has to say what it costs:
// the service registers cleanly and then fails every start opening its own
// certificate, which is a message no service manager produces.
func TestWindowsACL_AFailedGrantSaysWhatItCosts(t *testing.T) {
	rec := &icaclsRecorder{fail: errors.New("access is denied")}

	err := fleetagent.NewWindowsACLForTest(rec.run).
		GrantEnrollment(`WORKSTATION\axel`, "", []string{`C:\ProgramData\fleet\agent.key`})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access is denied")
	assert.Contains(t, err.Error(), "will not start without it")
	assert.Len(t, rec.calls, 1, "the first failure stops the handover; the install is over either way")
}

// The accounts that are granted nothing, and must have nothing invoked for
// them. A built-in service identity is already admitted by what %ProgramData%
// inherits, and handing icacls an empty principal would write an ACE for
// nobody.
func TestWindowsACL_GrantsNothingToAnAccountThatNeedsNothing(t *testing.T) {
	for _, account := range []string{
		`NT AUTHORITY\NetworkService`,
		"LocalSystem",
		`nt authority\localservice`,
		"",
	} {
		rec := &icaclsRecorder{}
		acl := fleetagent.NewWindowsACLForTest(rec.run)
		require.NoError(t, acl.GrantOwnedDir(`C:\ProgramData\fleet\state`, account), "account %q", account)
		require.NoError(t, acl.GrantEnrollment(account, `C:\ProgramData\fleet`,
			[]string{`C:\ProgramData\fleet\agent.key`}), "account %q", account)
		assert.Empty(t, rec.calls, "%q must not be granted anything", account)
	}

	// And an empty directory is nothing to grant on, whoever the account is.
	rec := &icaclsRecorder{}
	require.NoError(t, fleetagent.NewWindowsACLForTest(rec.run).GrantOwnedDir("", `WORKSTATION\axel`))
	assert.Empty(t, rec.calls)
}

// Whether a binary the service account cannot reach stops the install or only
// warns about it.
//
// It lived in the two platform files as a bare `true` and a bare `false`, which
// made "Windows refuses, Unix warns" a rule that only compiled on one host at a
// time and was therefore checked on neither. Refusing wrongly costs an operator
// an install that would have worked; warning wrongly costs them a service that
// fails every start with an error naming neither the path nor the account.
func TestExecutableAccessIsFatal(t *testing.T) {
	assert.True(t, fleetagent.ExecutableAccessIsFatalForTest("windows"),
		"a profile directory admits its owner, SYSTEM and the administrators and nobody else, so the answer is not a guess")
	for _, goos := range []string{"linux", "darwin"} {
		assert.False(t, fleetagent.ExecutableAccessIsFatalForTest(goos),
			"a supplementary group can grant what the mode bits appear to deny, so %s warns", goos)
	}
}
