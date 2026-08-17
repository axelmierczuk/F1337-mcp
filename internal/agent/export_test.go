package agent

// AuthorizePeerForTest exposes the client-authorization policy to the external
// test package.
//
// It is tested directly, not only through a handshake, because the OU check it
// performs overlaps with a check Go's TLS server does for free. Exercising it
// on its own is what proves the separation between agent and control leaves is
// this package's decision rather than a standard-library default that could
// change.
var AuthorizePeerForTest = authorizePeer

// AuditForTest exposes the daemon's audit-log construction, so the warnings it
// emits about its own configuration can be asserted on. They are the only thing
// standing between "every record names its host" and an operator finding out it
// does not when the records are already off-box.
var AuditForTest = auditFor

// PinSystemConfigDirForTest fixes what SystemConfigDir resolves to and returns a
// function restoring the previous resolver.
//
// It exists because the platforms that nest state and logs inside the config
// directory must derive them from the *resolved* directory, and that is not
// observable otherwise: the roots are compiled-in absolute paths on macOS, so a
// test cannot arrange for the new and old names to resolve differently.
func PinSystemConfigDirForTest(dir string) (restore func()) {
	previous := systemConfigDir
	systemConfigDir = func() string { return dir }
	return func() { systemConfigDir = previous }
}
