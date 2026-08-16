package enroll

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/axelmierczuk/sandboxd-mcp/internal/fsutil"
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

// spentTokenRetention is how long a used or expired token's record is kept
// before being pruned. Keeping it briefly is what lets a replayed token be
// reported as already used rather than as unrecognized, which is the
// difference between an operator debugging a double-run and one hunting a
// phantom.
const spentTokenRetention = 24 * time.Hour

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

// MintOptions describes the token to mint and, crucially, the identity the
// holder of that token is permitted to claim.
type MintOptions struct {
	// Name is the sandbox name reserved for this token.
	Name string
	// Labels are operator-assigned metadata to attach to the sandbox once
	// enrolled.
	Labels map[string]string
	// Addresses are the host:port endpoints the enrolling agent will listen
	// on, as the operator understands them. They bound which subject
	// alternative names the issued leaf may carry: an enrolling host cannot
	// widen this set, only decline to use it.
	Addresses []string
	// TTL is how long the token stays redeemable. Zero uses DefaultTokenTTL.
	TTL time.Duration
}

// TokenRecord describes a minted enrollment token. The token's plaintext
// value is never stored on a TokenRecord — only what was known about it at
// mint time and, after redemption, when and whether it was used.
type TokenRecord struct {
	// Name is the sandbox name reserved when the token was minted.
	Name string `yaml:"name,omitempty"`
	// Labels are operator-assigned metadata to attach to the sandbox once
	// enrolled.
	Labels map[string]string `yaml:"labels,omitempty"`
	// Addresses is the operator-authorized set of endpoints this token's
	// holder may be certified for.
	Addresses []string `yaml:"addresses,omitempty"`
	// IssuedAt and ExpiresAt bound the token's validity.
	IssuedAt  time.Time `yaml:"issued_at"`
	ExpiresAt time.Time `yaml:"expires_at"`
	// Used and UsedAt record redemption. Used is set atomically by Redeem.
	Used   bool      `yaml:"used"`
	UsedAt time.Time `yaml:"used_at,omitempty"`
}

// Expired reports whether the token's TTL had elapsed as of now.
func (r TokenRecord) Expired(now time.Time) bool { return now.After(r.ExpiresAt) }

type tokenEntry struct {
	// Hash is the hex-encoded SHA-256 of the token value. The plaintext is
	// never stored, here or on disk.
	Hash   string      `yaml:"hash"`
	Record TokenRecord `yaml:"record"`
}

type tokenState struct {
	Version int           `yaml:"version"`
	Tokens  []*tokenEntry `yaml:"tokens"`
}

// TokenStore holds minted enrollment tokens, keyed by a SHA-256 hash of the
// token value. The plaintext token is returned to the minting caller exactly
// once and never stored.
//
// A store may be backed by a file, which is what makes the CLI split work:
// `sandboxctl enroll mint` and `sandboxctl serve` are separate processes, so
// a token minted by one has to be redeemable by the other. File-backed stores
// re-read on every operation and hold an advisory file lock across the whole
// read-modify-write, so a mint concurrent with a redemption cannot clobber
// either.
//
// Redeem marks a token used before returning success, under the same lock
// that checked its validity, so two concurrent redemptions of the same token
// can never both succeed.
type TokenStore struct {
	mu   sync.Mutex
	path string        // empty for a memory-only store
	mem  []*tokenEntry // used only when path is empty
}

// NewTokenStore returns an empty, memory-only TokenStore. Tokens minted into
// it are lost when the process exits, which suits tests and a single-process
// embedding but not the mint/serve CLI split — use OpenTokenStore for that.
func NewTokenStore() *TokenStore {
	return &TokenStore{}
}

// OpenTokenStore returns a TokenStore persisted at path, creating the parent
// directory (mode 0700) if needed. An existing file is parsed eagerly, so a
// corrupt store is reported at startup rather than at the first enrollment.
func OpenTokenStore(path string) (*TokenStore, error) {
	s := &TokenStore{path: path}
	release, err := fsutil.Lock(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = release() }()
	if _, err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
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
// TTL, and returns the plaintext token. This is the only place the plaintext
// token exists outside the caller who receives it.
func (s *TokenStore) Mint(opts MintOptions) (string, TokenRecord, error) {
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}
	token, err := GenerateToken()
	if err != nil {
		return "", TokenRecord{}, err
	}

	now := time.Now().UTC()
	rec := TokenRecord{
		Name:      opts.Name,
		Labels:    copyLabels(opts.Labels),
		Addresses: append([]string(nil), opts.Addresses...),
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	}
	sum := sha256.Sum256([]byte(token))
	entry := &tokenEntry{Hash: hex.EncodeToString(sum[:]), Record: rec}

	if err := s.update(func(entries []*tokenEntry) ([]*tokenEntry, error) {
		return append(entries, entry), nil
	}); err != nil {
		return "", TokenRecord{}, err
	}
	return token, rec, nil
}

// Redeem validates token and, if it is unexpired and unused, atomically
// marks it used and returns the record that was minted with it. The mark
// happens inside the same critical section as the validity check, so
// concurrent callers redeeming the same token race for the lock, not for
// the certificate: exactly one wins, and it wins before any signing begins.
func (s *TokenStore) Redeem(token string) (TokenRecord, error) {
	sum := sha256.Sum256([]byte(token))
	want := []byte(hex.EncodeToString(sum[:]))
	now := time.Now().UTC()

	var (
		out    TokenRecord
		outErr = ErrTokenInvalid
	)
	err := s.update(func(entries []*tokenEntry) ([]*tokenEntry, error) {
		for _, e := range entries {
			if subtle.ConstantTimeCompare(want, []byte(e.Hash)) != 1 {
				continue
			}
			switch {
			case e.Record.Used:
				outErr = ErrTokenUsed
			case e.Record.Expired(now):
				outErr = ErrTokenExpired
			default:
				e.Record.Used = true
				e.Record.UsedAt = now
				out, outErr = e.Record, nil
			}
			break
		}
		return entries, nil
	})
	if err != nil {
		return TokenRecord{}, err
	}
	if outErr != nil {
		return TokenRecord{}, outErr
	}
	return out, nil
}

// List returns the metadata of every token still held, for `sandboxctl enroll
// list`. Records carry no token material, so this is safe to print.
func (s *TokenStore) List() ([]TokenRecord, error) {
	var out []TokenRecord
	err := s.update(func(entries []*tokenEntry) ([]*tokenEntry, error) {
		out = make([]TokenRecord, 0, len(entries))
		for _, e := range entries {
			out = append(out, e.Record)
		}
		return entries, nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// update runs fn against the store's entries and persists the result, holding
// the in-process mutex and (for a file-backed store) the cross-process file
// lock for the whole cycle.
//
// Spent tokens are pruned before fn runs, not after, so that fn — and any
// caller reading through it — sees the same set of tokens the store will
// persist. Pruning afterwards would let a listing report tokens that the very
// same call then deleted.
func (s *TokenStore) update(fn func([]*tokenEntry) ([]*tokenEntry, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()

	if s.path == "" {
		next, err := fn(prune(s.mem, now))
		if err != nil {
			return err
		}
		s.mem = next
		return nil
	}

	release, err := fsutil.Lock(s.path)
	if err != nil {
		return err
	}
	defer func() { _ = release() }()

	st, err := s.load()
	if err != nil {
		return err
	}
	next, err := fn(prune(st.Tokens, now))
	if err != nil {
		return err
	}
	st.Tokens = next
	return s.save(st)
}

func (s *TokenStore) load() (tokenState, error) {
	data, err := os.ReadFile(s.path) //nolint:gosec // path is operator-supplied, not attacker input
	if err != nil {
		if os.IsNotExist(err) {
			return tokenState{Version: schemaVersion}, nil
		}
		return tokenState{}, fmt.Errorf("enroll: read %s: %w", s.path, err)
	}
	if len(data) == 0 {
		return tokenState{Version: schemaVersion}, nil
	}
	var st tokenState
	if err := yaml.Unmarshal(data, &st); err != nil {
		return tokenState{}, fmt.Errorf("enroll: parse %s: %w", s.path, err)
	}
	return st, nil
}

func (s *TokenStore) save(st tokenState) error {
	if st.Version == 0 {
		st.Version = schemaVersion
	}
	data, err := yaml.Marshal(st)
	if err != nil {
		return fmt.Errorf("enroll: encode %s: %w", s.path, err)
	}
	// 0600: the file holds no plaintext tokens, but a hash plus the fleet
	// names and addresses it authorizes is not something to leave readable.
	if err := fsutil.WriteAtomic(s.path, data, 0o600); err != nil {
		return fmt.Errorf("enroll: save %s: %w", s.path, err)
	}
	return nil
}

// schemaVersion is bumped when the on-disk token store shape changes
// incompatibly.
const schemaVersion = 1

// prune drops tokens that have been spent — used or expired — for longer than
// spentTokenRetention.
func prune(entries []*tokenEntry, now time.Time) []*tokenEntry {
	out := entries[:0]
	for _, e := range entries {
		spentAt := e.Record.ExpiresAt
		if e.Record.Used && e.Record.UsedAt.After(spentAt) {
			spentAt = e.Record.UsedAt
		}
		spent := e.Record.Used || e.Record.Expired(now)
		if spent && now.Sub(spentAt) > spentTokenRetention {
			continue
		}
		out = append(out, e)
	}
	return out
}

func copyLabels(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
