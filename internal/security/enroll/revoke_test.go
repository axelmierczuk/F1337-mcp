package enroll_test

import (
	"path/filepath"
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
