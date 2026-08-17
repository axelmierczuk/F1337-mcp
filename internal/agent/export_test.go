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

// NewJailForTest exposes the provisional path jail (see jail.go) so its
// containment behaviour can be asserted from the external test package.
var NewJailForTest = NewJail

// EqualPathFoldForTest exposes the path comparison with its case-folding
// decision as a parameter.
//
// The Windows half of it has to be assertable from a Linux or macOS runner:
// the bug it exists to prevent — Unicode simple folding treating U+212A as "k",
// so that a root of C:\workspace contains the unrelated directory
// C:\wor<U+212A>space — cannot be reproduced on a platform where the comparison
// is case-sensitive, and CI is not going to grow a Windows-only jail test.
var EqualPathFoldForTest = equalPathFold

// ClassifyWindowsPathForTest exposes the Windows path classifier, which is a
// pure string function for the same reason.
func ClassifyWindowsPathForTest(p string) string { return classifyWindowsPath(p).String() }
