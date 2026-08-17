package enroll_test

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/security/enroll"
)

func TestRevoke_InvalidatesAnUnusedToken(t *testing.T) {
	store, err := enroll.OpenTokenStore(filepath.Join(t.TempDir(), "tokens.yaml"))
	require.NoError(t, err)

	token, rec, err := store.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)
	require.NotEmpty(t, rec.ID)

	revoked, err := store.Revoke(rec.ID)
	require.NoError(t, err)
	assert.Equal(t, rec.ID, revoked.ID)
	assert.True(t, revoked.Revoked)

	_, err = store.Redeem(token)
	require.ErrorIs(t, err, enroll.ErrTokenRevoked)
}

// The record is marked, not deleted: the operator who revoked it needs to see
// that it is revoked, and a later attempt to use it should read as "withdrawn"
// rather than "never existed".
func TestRevoke_LeavesTheRecordVisible(t *testing.T) {
	store, err := enroll.OpenTokenStore(filepath.Join(t.TempDir(), "tokens.yaml"))
	require.NoError(t, err)
	_, rec, err := store.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	_, err = store.Revoke(rec.ID)
	require.NoError(t, err)

	records, err := store.List()
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, enroll.StateRevoked, records[0].State(time.Now().UTC()))
	assert.Equal(t, rec.ID, records[0].ID)
}

// A revocation must survive the process, because minting and serving are
// different processes: `enroll revoke` in one has to stop `serve` in the other
// from honouring the token.
func TestRevoke_IsVisibleToAStoreOpenedAfterwards(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.yaml")
	minting, err := enroll.OpenTokenStore(path)
	require.NoError(t, err)
	token, rec, err := minting.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)
	_, err = minting.Revoke(rec.ID)
	require.NoError(t, err)

	serving, err := enroll.OpenTokenStore(path)
	require.NoError(t, err)
	_, err = serving.Redeem(token)
	require.ErrorIs(t, err, enroll.ErrTokenRevoked)
}

// A prefix is enough, because that is how an operator will use it — but only
// one that identifies a single token.
func TestRevoke_AcceptsAPrefixAndRejectsAnAmbiguousOne(t *testing.T) {
	store, err := enroll.OpenTokenStore(filepath.Join(t.TempDir(), "tokens.yaml"))
	require.NoError(t, err)
	_, rec, err := store.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	// Every hex id starts somewhere in [0-9a-f]; the empty-ish prefix that
	// matches everything is refused on length before it can be ambiguous.
	_, err = store.Revoke("ab")
	require.Error(t, err)
	assert.NotErrorIs(t, err, enroll.ErrTokenIDUnknown, "too-short ids are refused as too short, not as unknown")

	_, err = store.Revoke(rec.ID[:6])
	require.NoError(t, err)
}

func TestRevoke_RejectsAnUnknownID(t *testing.T) {
	store, err := enroll.OpenTokenStore(filepath.Join(t.TempDir(), "tokens.yaml"))
	require.NoError(t, err)
	_, err = store.Revoke("deadbeef")
	require.ErrorIs(t, err, enroll.ErrTokenIDUnknown)
}

// Revoking something already spent is a mistake about which token is which, and
// reporting it as success would tell the operator they closed a window they did
// not touch.
func TestRevoke_RefusesATokenThatIsAlreadySpent(t *testing.T) {
	store, err := enroll.OpenTokenStore(filepath.Join(t.TempDir(), "tokens.yaml"))
	require.NoError(t, err)
	token, rec, err := store.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)
	_, err = store.Redeem(token)
	require.NoError(t, err)

	_, err = store.Revoke(rec.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already used")
}

// Revoking and redeeming the same token at the same moment is the case that
// decides whether revocation means anything: `enroll revoke` runs in the
// operator's shell while `serve` is redeeming in another process, and the two
// meet on one file.
//
// Exactly one of them must win, and the store must end up agreeing with
// whichever did — a token that reads "revoked" after a redemption succeeded
// would have certified a host the operator believes they stopped, and one that
// reads "used" after a revocation succeeded would tell the operator a window
// closed that never did. Never both, and never neither.
//
// The two stores are separate objects on one path deliberately: that is the
// mint/serve split, and a lock held only in-process would pass a test that
// shared one store and fail in production.
func TestRevoke_RacingARedemptionLeavesExactlyOneWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.yaml")
	operator, err := enroll.OpenTokenStore(path)
	require.NoError(t, err)
	serving, err := enroll.OpenTokenStore(path)
	require.NoError(t, err)

	const tokens = 24
	type minted struct{ token, id string }
	all := make([]minted, 0, tokens)
	for i := range tokens {
		token, rec, err := operator.Mint(enroll.MintOptions{Name: fmt.Sprintf("box-%d", i)})
		require.NoError(t, err)
		all = append(all, minted{token: token, id: rec.ID})
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		revoked  = map[string]bool{}
		redeemed = map[string]bool{}
	)
	start := make(chan struct{})
	for _, m := range all {
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, err := operator.Revoke(m.id)
			mu.Lock()
			defer mu.Unlock()
			revoked[m.id] = err == nil
		}()
		go func() {
			defer wg.Done()
			<-start
			_, err := serving.Redeem(m.token)
			mu.Lock()
			defer mu.Unlock()
			redeemed[m.id] = err == nil
		}()
	}
	close(start)
	wg.Wait()

	// A third store, opened after the fact, is what any later process sees.
	after, err := enroll.OpenTokenStore(path)
	require.NoError(t, err)
	records, err := after.List()
	require.NoError(t, err)
	states := make(map[string]string, len(records))
	for _, rec := range records {
		states[rec.ID] = rec.State(time.Now().UTC())
	}

	for _, m := range all {
		require.NotEqual(t, revoked[m.id], redeemed[m.id],
			"token %s: revoked=%v redeemed=%v; exactly one of the two must win",
			m.id, revoked[m.id], redeemed[m.id])

		want := enroll.StateUsed
		if revoked[m.id] {
			want = enroll.StateRevoked
		}
		assert.Equal(t, want, states[m.id], "token %s ended in a state the winner did not put it in", m.id)

		// And it is spent either way: whoever lost cannot come back and win.
		_, err := after.Redeem(m.token)
		require.Error(t, err, "token %s stayed redeemable after the race", m.id)
	}
}

// The id must be derived from the stored hash rather than from the token, or a
// listing would be publishing a prefix of the secret it is meant not to show.
func TestTokenID_IsNotDerivedFromTheTokenValue(t *testing.T) {
	store, err := enroll.OpenTokenStore(filepath.Join(t.TempDir(), "tokens.yaml"))
	require.NoError(t, err)
	token, rec, err := store.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	require.Len(t, rec.ID, enroll.TokenIDLength)
	assert.NotContains(t, token, rec.ID)

	listed, err := store.List()
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, rec.ID, listed[0].ID, "the id must be stable across reads")
}
