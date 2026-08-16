package ca

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
)

// Fingerprint returns the SHA-256 digest of cert's DER encoding, matching
// what `openssl x509 -fingerprint -sha256` computes.
func Fingerprint(cert *x509.Certificate) [32]byte {
	return sha256.Sum256(cert.Raw)
}

// Fingerprint returns the SHA-256 fingerprint of the CA's own certificate,
// for an operator to hand to `--ca-fingerprint` during enrollment.
func (c *CA) Fingerprint() [32]byte {
	return Fingerprint(c.cert)
}

// FormatFingerprint renders a fingerprint as colon-separated uppercase hex,
// matching openssl's `SHA256 Fingerprint=AA:BB:...` output.
func FormatFingerprint(sum [32]byte) string {
	var b strings.Builder
	for i, v := range sum {
		if i > 0 {
			b.WriteByte(':')
		}
		fmt.Fprintf(&b, "%02X", v)
	}
	return b.String()
}

// ParseFingerprint accepts a SHA-256 fingerprint in either colon-separated
// hex (openssl's format) or plain hex, case-insensitively, as an operator
// might paste it from either source.
func ParseFingerprint(s string) ([32]byte, error) {
	var out [32]byte
	clean := strings.ReplaceAll(strings.TrimSpace(s), ":", "")
	raw, err := hex.DecodeString(clean)
	if err != nil {
		return out, fmt.Errorf("ca: invalid fingerprint %q: %w", s, err)
	}
	if len(raw) != len(out) {
		return out, fmt.Errorf("ca: invalid fingerprint %q: want %d bytes, got %d", s, len(out), len(raw))
	}
	copy(out[:], raw)
	return out, nil
}
