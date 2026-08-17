package fleetagent

import "github.com/axelmierczuk/fleet-mcp/internal/agent"

// EnrollmentMaterialForTest is the set of files `service install` has to hand
// to the account the daemon will run as.
func EnrollmentMaterialForTest(cfg *agent.Config, configPath string) []string {
	return enrollmentMaterial(cfg, configPath)
}

// EnrollmentDirIsOursForTest reports whether install may take ownership of a
// directory, which it may only do for the ones `enroll` creates.
func EnrollmentDirIsOursForTest(dir string) bool { return enrollmentDirIsOurs(dir) }

// GrantServiceUserAccessForTest exposes the ownership handover so it can be
// exercised against a real directory. Chowning to one's own account needs no
// privilege, which is what makes the success path testable at all.
func GrantServiceUserAccessForTest(name, dir string, files []string) error {
	return grantServiceUserAccess(name, dir, files)
}

// ServiceAccessByOwnershipForTest reports whether this platform grants the
// service account access by ownership.
const ServiceAccessByOwnershipForTest = serviceAccessByOwnership

// DefaultServiceUserForTest exposes the platform's default service account, so
// the "never a superuser" property can be asserted without an install.
func DefaultServiceUserForTest() (string, error) { return defaultServiceUser() }

// LegacyServiceNoteForTest exposes what an operator is told when this host
// still carries a service registered under the pre-rebrand name.
//
// The presence answer is supplied rather than read: no test can register a
// pre-rebrand service with a real service manager, and CI cannot register one
// at all.
func LegacyServiceNoteForTest(present bool) string { return legacyServiceNote(present) }

// LegacyServiceNameForTest is the pre-rebrand service name, so the test asserts
// on the same constant the note is built from.
const LegacyServiceNameForTest = legacyServiceName

// IsElevatedForTest reports whether this process can install a service.
//
// The tests that assert the *unprivileged* path have to skip when it is not,
// and they must ask the same question the code does. A test-local
// `runtime.GOOS == "windows" → false` is wrong on exactly the machine that
// matters: GitHub's Windows runners are administrators, so those tests ran
// elevated and failed against an error message meant for someone who is not.
func IsElevatedForTest() bool { return isElevated() }
