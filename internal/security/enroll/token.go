package enroll

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

// TokenPrefix marks a string as a sandboxd enrollment token, so one is
// recognizable at a glance (in logs, in shell history) for what it is.
const TokenPrefix = "sbx_"

// DefaultTokenTTL is how long a minted token remains redeemable. Short by
// design: a bootstrap secret that lives for hours is a bootstrap secret
// someone will find in a shell history.
const DefaultTokenTTL = 15 * time.Minute

// tokenEntropyBytes is the amount of randomness in a minted token, before
// base64url encoding.
const tokenEntropyBytes = 32

var (
	// ErrTokenInvalid is returned when a token does not match any minted
	// token.
	ErrTokenInvalid = errors.New("enroll: invalid enrollment token")
	// ErrTokenExpired is returned when a token matches but its TTL has
	// elapsed.
	ErrTokenExpired = errors.New("enroll: enrollment token expired")
	// ErrTokenUsed is returned when a token matches but was already
	// redeemed.
	ErrTokenUsed = errors.New("enroll: enrollment token already used")
)

// TokenRecord describes a minted enrollment token. The token's plaintext
// value is never stored on a TokenRecord — only what was known about it at
// mint time and, after redemption, when and whether it was used.
type TokenRecord struct {
	// Name is the sandbox name reserved when the token was minted. Enroll
	// callers may still pass their own requested_name; RequestedName in the
	// wire request takes precedence when set.
	Name string
	// Labels are operator-assigned metadata to attach to the sandbox once
	// enrolled.
	Labels map[string]string
	// IssuedAt and ExpiresAt bound the token's validity.
	IssuedAt  time.Time
	ExpiresAt time.Time
	// Used and UsedAt record redemption. Used is set atomically by Redeem.
	Used   bool
	UsedAt time.Time
}

type tokenEntry struct {
	hash   [sha256.Size]byte
	record TokenRecord
}

// TokenStore holds minted enrollment tokens in memory, keyed by a SHA-256
// hash of the token value. The plaintext token is returned to the minting
// caller exactly once and never stored.
//
// Redeem marks a token used before returning success, under the same lock
// that checked its validity, so two concurrent redemptions of the same
// token can never both succeed.
type TokenStore struct {
	mu      sync.Mutex
	entries []*tokenEntry
}

// NewTokenStore returns an empty TokenStore.
func NewTokenStore() *TokenStore {
	return &TokenStore{}
}

// GenerateToken returns a fresh single-use token: 32 bytes from
// crypto/rand, base64url-encoded, prefixed "sbx_".
func GenerateToken() (string, error) {
	buf := make([]byte, tokenEntropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("enroll: generate token: %w", err)
	}
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// Mint generates a new token, records its hash with the given metadata and
// TTL, and returns the plaintext token. This is the only place the
// plaintext token exists outside the caller who receives it.
func (s *TokenStore) Mint(name string, labels map[string]string, ttl time.Duration) (string, TokenRecord, error) {
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}
	token, err := GenerateToken()
	if err != nil {
		return "", TokenRecord{}, err
	}

	now := time.Now().UTC()
	rec := TokenRecord{
		Name:      name,
		Labels:    labels,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	}
	hash := sha256.Sum256([]byte(token))

	s.mu.Lock()
	s.entries = append(s.entries, &tokenEntry{hash: hash, record: rec})
	s.mu.Unlock()

	return token, rec, nil
}

// Redeem validates token and, if it is unexpired and unused, atomically
// marks it used and returns the record that was minted with it. The mark
// happens inside the same critical section as the validity check, so
// concurrent callers redeeming the same token race for the lock, not for
// the certificate: exactly one wins, and it wins before any signing begins.
func (s *TokenStore) Redeem(token string) (TokenRecord, error) {
	hash := sha256.Sum256([]byte(token))
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, e := range s.entries {
		if subtle.ConstantTimeCompare(hash[:], e.hash[:]) != 1 {
			continue
		}
		if e.record.Used {
			return TokenRecord{}, ErrTokenUsed
		}
		if now.After(e.record.ExpiresAt) {
			return TokenRecord{}, ErrTokenExpired
		}
		e.record.Used = true
		e.record.UsedAt = now
		return e.record, nil
	}
	return TokenRecord{}, ErrTokenInvalid
}
