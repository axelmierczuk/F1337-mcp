// Package enroll implements the enrollment protocol: minting single-use tokens
// and serving EnrollmentService.
//
// Agents generate their own keypair and submit only a CSR, so a private key
// never crosses the network.
//
// Implemented by milestone M0.
package enroll
