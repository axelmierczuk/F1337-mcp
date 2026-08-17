package sandboxdagent

// DefaultServiceUserForTest exposes the platform's default service account, so
// the "never a superuser" property can be asserted without an install.
func DefaultServiceUserForTest() (string, error) { return defaultServiceUser() }

// IsElevatedForTest reports whether this process can install a service.
//
// The tests that assert the *unprivileged* path have to skip when it is not,
// and they must ask the same question the code does. A test-local
// `runtime.GOOS == "windows" → false` is wrong on exactly the machine that
// matters: GitHub's Windows runners are administrators, so those tests ran
// elevated and failed against an error message meant for someone who is not.
func IsElevatedForTest() bool { return isElevated() }
