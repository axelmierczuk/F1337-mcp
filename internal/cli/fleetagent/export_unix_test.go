//go:build !windows

package fleetagent

// LinuxServiceUserForTest exposes the Linux default-account rule with the
// account lookup supplied, so the pre-rebrand fallback can be asserted on a
// machine that has neither account. It lives here rather than in export_test.go
// because the rule it exposes is only compiled off Windows.
func LinuxServiceUserForTest(exists func(string) bool) string { return linuxServiceUser(exists) }

// ServiceUserNamesForTest are the current and pre-rebrand account names, so the
// test asserts on the same constants the rule reads rather than restating them.
const (
	ServiceUserNameForTest       = systemUserName
	LegacyServiceUserNameForTest = legacySystemUserName
)
