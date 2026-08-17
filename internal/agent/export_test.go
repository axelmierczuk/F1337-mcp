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
