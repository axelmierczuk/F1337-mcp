// Package enroll implements the enrollment protocol: minting single-use
// tokens and serving EnrollmentService.
//
// Agents generate their own keypair and submit only a CSR, so a private key
// never crosses the network. Enrollment is the one RPC path that is not
// mutually authenticated, because the enrolling host has no certificate
// yet: it is server-authenticated TLS, pinned by CA fingerprint, plus a
// single-use bearer token that this package marks used atomically before
// the CSR is ever signed.
package enroll
