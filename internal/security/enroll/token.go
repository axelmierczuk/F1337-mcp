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
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/axelmierczuk/fleet-mcp/internal/fsutil"
)

// TokenPrefix marks a string as a fleet enrollment token, so one is
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
	// ErrTokenRevoked is returned when a token matches but the operator
	// withdrew it before it was redeemed.
	ErrTokenRevoked = errors.New("enroll: enrollment token revoked")

	// ErrTokenIDUnknown is returned by Revoke when no token carries the given
	// id.
	ErrTokenIDUnknown = errors.New("enroll: no enrollment token with that id")
	// ErrTokenIDAmbiguous is returned by Revoke when an id prefix matches more
	// than one token.
	ErrTokenIDAmbiguous = errors.New("enroll: that token id matches more than one token")
)

// isTokenRejection reports whether err is the store refusing a token, as
// opposed to the store itself having failed.
//
// The distinction is what an operator is told. A refused token means "this
// credential is no good, mint another"; an unreadable or unwritable store means
// the control plane is broken and a second token will not help. Enrollment
// reports the first as Unauthenticated and the second as Internal, and without
// this a corrupt token store would send every enrolling host chasing its own
// perfectly good token.
//
// Every sentinel above that means "not redeemable" belongs here. A new one that
// does not is reported to operators as a control plane failure.
func isTokenRejection(err error) bool {
	return errors.Is(err, ErrTokenInvalid) ||
		errors.Is(err, ErrTokenExpired) ||
		errors.Is(err, ErrTokenUsed) ||
		errors.Is(err, ErrTokenRevoked)
}

// TokenIDLength is how many hex characters of a token's stored hash identify it
// to `fleetctl enroll list` and `fleetctl enroll revoke`.
//
// The id is derived from the hash rather than stored beside it, so it cannot
// drift from the entry it names, and it is safe to print for the same reason the
// hash is safe to store: the value it indexes carries 256 bits of entropy, so
// nothing about it is recoverable from its digest. It is deliberately not any
// part of the token itself — a listing must never show token material, in any
// output mode.
const TokenIDLength = 12

// minTokenIDPrefix is the shortest prefix Revoke will act on. A one-character
// id would routinely match several tokens, and the operator would learn that
// only from an error; requiring a few characters makes the common case exact.
const minTokenIDPrefix = 4

// Token states, as `fleetctl enroll list` reports them.
const (
	StatePending = "pending"
	StateUsed    = "used"
	StateExpired = "expired"
	StateRevoked = "revoked"
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
	// ID names this token without naming its value: the first TokenIDLength
	// hex characters of the stored hash. It is derived on every read and never
	// persisted, so it cannot disagree with the entry it identifies.
	ID string `yaml:"-"`
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
	// Revoked and RevokedAt record the operator withdrawing a token before
	// anyone redeemed it.
	Revoked   bool      `yaml:"revoked,omitempty"`
	RevokedAt time.Time `yaml:"revoked_at,omitempty"`
}

// Expired reports whether the token's TTL had elapsed as of now.
func (r TokenRecord) Expired(now time.Time) bool { return now.After(r.ExpiresAt) }

// clone returns a TokenRecord that shares no memory with r.
//
// Labels and Addresses are reference types, so the plain struct copy that
// returning a record from the store amounts to hands the caller a live view of
// the store's own entry. Two of the fields enrollment validates a request
// against live in there — Addresses is one of them — and validating before
// redeeming is only sound because nothing can change them between the two. That
// is an invariant of what a token authorizes, so the store is what has to keep
// it, rather than every caller that ever holds a record remembering not to
// write through it.
func (r TokenRecord) clone() TokenRecord {
	r.Labels = copyLabels(r.Labels)
	r.Addresses = append([]string(nil), r.Addresses...)
	return r
}

// State renders the token's state as of now, in the vocabulary `fleetctl
// enroll list` prints. It lives here rather than in the CLI so a token's state
// has one definition and the order of the checks — revoked before used before
// expired — cannot differ between two places that ask.
func (r TokenRecord) State(now time.Time) string {
	switch {
	case r.Revoked:
		return StateRevoked
	case r.Used:
		return StateUsed
	case r.Expired(now):
		return StateExpired
	default:
		return StatePending
	}
}

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
// `fleetctl enroll mint` and `fleetctl serve` are separate processes, so
// a token minted by one has to be redeemable by the other. File-backed stores
// re-read on every operation and hold an advisory file lock across the whole
// read-modify-write, so a mint concurrent with a redemption cannot clobber
// either.
//
// Redeem marks a token used before returning success, under the same lock
// that checked its validity, so two concurrent redemptions of the same token
// can never both succeed.
//
// What a token authorizes is fixed at mint time and never rewritten: Name,
// Labels, Addresses, IssuedAt and ExpiresAt are written once by Mint, and the
// only fields any later operation touches are Used/UsedAt and
// Revoked/RevokedAt. Enrollment relies on that. It validates a request against
// the record [TokenStore.Inspect] returned and commits with Redeem afterwards,
// which is only sound because the authorization it validated cannot have
// changed in between — and because the fields that *can* change are exactly the
// ones Redeem re-checks under the lock.
//
// Every record leaves the store as a deep copy, so that invariant is one the
// store keeps rather than one every caller has to remember not to break: Labels
// and Addresses are reference types, and handing out the entry's own would make
// any holder of a record able to rewrite what a token authorizes — from another
// goroutine, outside this lock, in the window enrollment validates in.
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
	out := entry.Record.clone()
	out.ID = entry.id()

	if err := s.update(func(entries []*tokenEntry) ([]*tokenEntry, bool, error) {
		return append(entries, entry), true, nil
	}); err != nil {
		return "", TokenRecord{}, err
	}
	return token, out, nil
}

// id returns the operator-facing identifier for this entry.
func (e *tokenEntry) id() string {
	if len(e.Hash) < TokenIDLength {
		return e.Hash
	}
	return e.Hash[:TokenIDLength]
}

// redeemable finds the entry token names and reports why it could not be
// redeemed as of now, or nil if it could be.
//
// It is the single definition of "redeemable", shared by [TokenStore.Inspect],
// which only asks, and [TokenStore.Redeem], which asks and then marks. Two
// copies of this would be two chances for the question enrollment validates
// against and the question redemption commits against to drift apart, and a
// token that passed one and failed the other is the whole defect the split
// exists to fix.
func redeemable(entries []*tokenEntry, token string, now time.Time) (*tokenEntry, error) {
	sum := sha256.Sum256([]byte(token))
	want := []byte(hex.EncodeToString(sum[:]))

	for _, e := range entries {
		if subtle.ConstantTimeCompare(want, []byte(e.Hash)) != 1 {
			continue
		}
		switch {
		case e.Record.Revoked:
			return e, ErrTokenRevoked
		case e.Record.Used:
			return e, ErrTokenUsed
		case e.Record.Expired(now):
			return e, ErrTokenExpired
		}
		return e, nil
	}
	return nil, ErrTokenInvalid
}

// Inspect returns the record behind token if it could be redeemed right now,
// without redeeming it.
//
// It is what lets enrollment check a request against the identity a token
// authorizes before spending the token. Redemption used to be the first thing
// [Service.Enroll] did, so a request refused afterwards for a mistyped address
// or a name the CA will not sign had already burned the operator's single-use
// secret, and the corrected retry then failed naming the token rather than the
// mistake.
//
// The record is a copy: writing to its Labels or Addresses changes nothing
// about what the token authorizes.
//
// The answer is advisory and may be stale the instant it is returned: another
// enrollment may redeem the token, or the operator may revoke it. Redeem is the
// authority. It re-asks, under the lock, everything asked here — that is what
// keeps the window this opens a window in which two callers may both *validate*,
// which is harmless, rather than one in which two may both redeem. Nothing may
// treat a successful Inspect as a claim on the token.
func (s *TokenStore) Inspect(token string) (TokenRecord, error) {
	now := time.Now().UTC()

	var (
		out    TokenRecord
		outErr error
	)
	err := s.update(func(entries []*tokenEntry) ([]*tokenEntry, bool, error) {
		e, lookupErr := redeemable(entries, token, now)
		outErr = lookupErr
		if outErr == nil {
			out = e.Record.clone()
			out.ID = e.id()
		}
		// Nothing was spent, so fn reports no change. Inspect runs on every
		// enrollment attempt, including the ones anyone on the network can
		// start, and a read that asked for a write each time would hand them
		// the control plane's disk and the lock `enroll mint` needs. (update
		// still persists a pruning that dropped a long-spent entry, as it does
		// for Redeem: that is bounded by the entries there are to drop, and one
		// call drains them.)
		return entries, false, nil
	})
	if err != nil {
		return TokenRecord{}, err
	}
	if outErr != nil {
		return TokenRecord{}, outErr
	}
	return out, nil
}

// Redeem validates token and, if it is unexpired and unused, atomically
// marks it used and returns the record that was minted with it. The mark
// happens inside the same critical section as the validity check, so
// concurrent callers redeeming the same token race for the lock, not for
// the certificate: exactly one wins, and it wins before anything irreversible
// is done on its behalf.
//
// This is the compare-and-swap enrollment's replay protection rests on, and it
// is the only thing that grants the right to proceed. It compares the stored
// entry's state — revoked, used, expired — and swaps Used to true in the same
// held lock, so the loser of a race observes the winner's mark and is refused
// with ErrTokenUsed. A caller that inspected the token beforehand has claimed
// nothing by doing so; it still has to win here.
func (s *TokenStore) Redeem(token string) (TokenRecord, error) {
	now := time.Now().UTC()

	var (
		out    TokenRecord
		outErr error
	)
	err := s.update(func(entries []*tokenEntry) ([]*tokenEntry, bool, error) {
		e, lookupErr := redeemable(entries, token, now)
		outErr = lookupErr
		if outErr == nil {
			e.Record.Used = true
			e.Record.UsedAt = now
			out = e.Record.clone()
			out.ID = e.id()
		}
		// Only a redemption that actually spent a token changed anything. A
		// token that matched nothing is the ordinary case for this endpoint —
		// it is reachable without a credential — and rewriting the whole store
		// for each such attempt makes an unauthenticated caller drive the
		// control plane's disk and hold the lock that `enroll mint` needs.
		return entries, outErr == nil, nil
	})
	if err != nil {
		return TokenRecord{}, err
	}
	if outErr != nil {
		return TokenRecord{}, outErr
	}
	return out, nil
}

// List returns the metadata of every token still held, for `fleetctl enroll
// list`. Records carry no token material, so this is safe to print.
func (s *TokenStore) List() ([]TokenRecord, error) {
	var out []TokenRecord
	err := s.update(func(entries []*tokenEntry) ([]*tokenEntry, bool, error) {
		out = make([]TokenRecord, 0, len(entries))
		for _, e := range entries {
			rec := e.Record.clone()
			rec.ID = e.id()
			out = append(out, rec)
		}
		return entries, false, nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Revoke withdraws the token identified by id — a prefix of the id `enroll
// list` prints — and returns the record it marked.
//
// The entry is marked rather than deleted. A revoked token that vanished from
// the listing would leave the operator who just revoked it with no confirmation
// and no record, and would report a later attempt to redeem it as an unknown
// token rather than as one somebody withdrew.
//
// Revoking a token that was already used or has already expired is refused: it
// is either a mistake about which token is which, or an operator believing they
// have closed a window that closed itself. Neither should read as success.
func (s *TokenStore) Revoke(id string) (TokenRecord, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	if len(id) < minTokenIDPrefix {
		return TokenRecord{}, fmt.Errorf("enroll: token id %q is too short; give at least %d characters of the id from `fleetctl enroll list`",
			id, minTokenIDPrefix)
	}

	now := time.Now().UTC()
	var (
		out    TokenRecord
		outErr error
	)
	err := s.update(func(entries []*tokenEntry) ([]*tokenEntry, bool, error) {
		var matches []*tokenEntry
		for _, e := range entries {
			if strings.HasPrefix(e.Hash, id) {
				matches = append(matches, e)
			}
		}
		switch {
		case len(matches) == 0:
			outErr = fmt.Errorf("%w: %s", ErrTokenIDUnknown, id)
			return entries, false, nil
		case len(matches) > 1:
			outErr = fmt.Errorf("%w: %s matches %d tokens; use more of the id", ErrTokenIDAmbiguous, id, len(matches))
			return entries, false, nil
		}

		e := matches[0]
		if state := e.Record.State(now); state != StatePending {
			outErr = fmt.Errorf("enroll: token %s is already %s, so there is nothing to revoke", e.id(), state)
			return entries, false, nil
		}
		e.Record.Revoked = true
		e.Record.RevokedAt = now
		out = e.Record.clone()
		out.ID = e.id()
		return entries, true, nil
	})
	if err != nil {
		return TokenRecord{}, err
	}
	if outErr != nil {
		return TokenRecord{}, outErr
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
//
// fn reports whether it changed anything. A file-backed store is rewritten only
// when it did, or when pruning removed something: an operation that read the
// store and changed nothing should not cost a write, because the operation that
// most often changes nothing is a redemption of a token nobody minted, and
// anyone on the network can ask for one of those.
func (s *TokenStore) update(fn func([]*tokenEntry) ([]*tokenEntry, bool, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()

	if s.path == "" {
		next, _, err := fn(prune(s.mem, now))
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
	kept := prune(st.Tokens, now)
	pruned := len(kept) != len(st.Tokens)
	next, changed, err := fn(kept)
	if err != nil {
		return err
	}
	if !changed && !pruned {
		return nil
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

// prune drops tokens that have been spent — used, revoked, or expired — for
// longer than spentTokenRetention.
func prune(entries []*tokenEntry, now time.Time) []*tokenEntry {
	out := entries[:0]
	for _, e := range entries {
		spentAt := e.Record.ExpiresAt
		if e.Record.Used && e.Record.UsedAt.After(spentAt) {
			spentAt = e.Record.UsedAt
		}
		// A token revoked well before its expiry is still retained until the
		// expiry passes: the operator who revoked it should be able to see that
		// it is revoked for as long as anyone might still try to use it.
		if e.Record.Revoked && e.Record.RevokedAt.After(spentAt) {
			spentAt = e.Record.RevokedAt
		}
		spent := e.Record.State(now) != StatePending
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
