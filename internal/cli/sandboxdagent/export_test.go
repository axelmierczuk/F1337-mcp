package sandboxdagent

// DefaultServiceUserForTest exposes the platform's default service account, so
// the "never a superuser" property can be asserted without an install.
func DefaultServiceUserForTest() (string, error) { return defaultServiceUser() }
