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
