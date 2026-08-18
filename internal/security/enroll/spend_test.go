package enroll_test

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/security/ca"
	"github.com/axelmierczuk/fleet-mcp/internal/security/enroll"
)

// The defect #58 records: enrollment redeemed the token before it validated
// anything else, so a request refused for a reason that had nothing to do with
// the token had already spent it. The operator's corrected retry then failed
// with "enrollment token rejected" — which names the credential rather than the
// mistake — and minting a fresh token made that go away without ever explaining
// it.
//
// Each case here is a mistake an operator makes at the keyboard, followed by
// the same command typed correctly, with the same token. Driven over the RPC
// against a real enroll.Service rather than against the functions that changed:
// three rounds on #54 fixed something the operator never reached, because the
// test called the repaired function directly.
func TestEnroll_ARefusedRequestLeavesTheTokenSpendable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		refused *sandboxdv1.EnrollRequest
		expect  string
	}{
		{
			name:    "a name the token does not reserve",
			refused: &sandboxdv1.EnrollRequest{RequestedName: "somebody-else"},
			expect:  "reserves the name",
		},
		{
			name: "a mistyped --address",
			refused: &sandboxdv1.EnrollRequest{
				RequestedName:   "build-box",
				ListenAddresses: []string{"buidl-box.internal:8722"},
			},
			expect: "not authorized by this token",
		},
		{
			name:    "a space in --name",
			refused: &sandboxdv1.EnrollRequest{RequestedName: "build box"},
			expect:  "invalid character",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caObj := newTestCA(t)
			tokens := enroll.NewTokenStore()
			fleet := &recordingFleet{}
			svc := &enroll.Service{Tokens: tokens, CA: caObj, Fleet: fleet}
			lis := startControlPlane(t, svc, caObj)

			token, _, err := tokens.Mint(enroll.MintOptions{
				Name:      "build-box",
				Addresses: []string{"build-box.internal:8722"},
			})
			require.NoError(t, err)

			tc.refused.Token = token
			_, err = enrollOnce(t, lis, caObj, tc.refused)
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.Contains(t, status.Convert(err).Message(), tc.expect)
			assert.Empty(t, fleet.recorded, "a refused request must leave no fleet member behind")

			// The same token, and the command as the operator meant to type it.
			resp, err := enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{
				Token:           token,
				RequestedName:   "build-box",
				ListenAddresses: []string{"build-box.internal:8722"},
			})
			require.NoError(t, err, "the corrected retry must not need a second token")
			assert.Equal(t, "build-box", resp.GetAssignedName())

			// Single-use is the policy and stays the policy: what was wrong was
			// the ordering, not that a redeemed token is spent.
			_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{
				Token:         token,
				RequestedName: "build-box",
			})
			require.Error(t, err)
			assert.Equal(t, codes.Unauthenticated, status.Code(err))
		})
	}
}

// Moving redemption after validation opens a window in which several
// enrollments can hold the same valid, unspent token at once. This is that
// window, held open deliberately: every enrollment has provably passed
// [enroll.Service.Enroll]'s checks before any of them reaches the redemption
// that only one can win.
//
// Nothing here asserts on how long anything took. The barrier is a
// happens-before fact — the last caller through it is what releases the rest —
// and the assertions are on what the control plane recorded: how many
// certificates it issued, how many fleet members it created, and what the token
// store says afterwards. A machine under load makes this test slower and does
// not make it flakier.
func TestEnroll_ConcurrentEnrollmentsValidateTogetherAndOnlyOneSpendsTheToken(t *testing.T) {
	const racers = 8

	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	fleet := &syncFleet{}
	gate := newBarrier(racers)
	svc := &enroll.Service{
		Tokens: tokens,
		CA:     caObj,
		// The collision check is the last thing Enroll does before it spends
		// the token, so holding every caller here holds them all at exactly the
		// moment the reorder created.
		Names: &barrierNames{t: t, gate: gate},
		Fleet: fleet,
		// Rate limiting off, so what this measures is the redemption race and
		// nothing else: with the defaults, most of these would be turned away
		// before they ever reached the barrier — and the ones turned away would
		// never arrive at it, leaving the rest waiting.
		Limiter: enroll.NewRateLimiter(time.Minute, 0, 0),
	}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	var (
		mu       sync.Mutex
		issued   []string
		refusals []codes.Code
		// Every racer builds its own CSR from its own key, which is what makes
		// them eight different enrollments of one token rather than eight
		// copies of one. The winner's leaf has to carry the winner's key: a
		// certificate assembled from another racer's request would hand it an
		// identity for a private key it does not hold, and the store would say
		// the token was spent correctly all the same.
		winnerCert []byte
		winnerPub  *ecdsa.PublicKey
	)
	var wg sync.WaitGroup
	wg.Add(racers)
	for range racers {
		go func() {
			defer wg.Done()

			// Spelled out rather than run through enrollOnce, for two reasons
			// that matter only here: its require calls would be a FailNow on a
			// goroutine that is not the test's, and its five-second deadline is
			// one every racer spends waiting for the slowest of them to reach
			// the barrier. The deadline below is a failsafe against a hang, not
			// a bound anything asserts on.
			key, err := enroll.GenerateKey()
			if err != nil {
				t.Errorf("generate key: %v", err)
				return
			}
			csrDER, err := enroll.BuildCSR(key, "build-box", nil, nil)
			if err != nil {
				t.Errorf("build csr: %v", err)
				return
			}
			cc, err := dialControlPlane(lis, caObj.Fingerprint())
			if err != nil {
				t.Errorf("dial the control plane: %v", err)
				return
			}
			defer func() { _ = cc.Close() }()

			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			resp, err := sandboxdv1.NewEnrollmentServiceClient(cc).Enroll(ctx, &sandboxdv1.EnrollRequest{
				Token:         token,
				CsrDer:        csrDER,
				RequestedName: "build-box",
			})

			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				refusals = append(refusals, status.Code(err))
				return
			}
			issued = append(issued, resp.GetAssignedName())
			// Parsed on the test's own goroutine below: leafOf is a require
			// helper, and a FailNow from here would be a FailNow on the wrong
			// goroutine.
			winnerCert, winnerPub = resp.GetCertificatePem(), &key.PublicKey
		}()
	}
	wg.Wait()

	// First, that this test tested anything: all of them were held at the
	// barrier, so all of them had passed validation with an unspent token
	// before any of them redeemed. Without this the scenario would still be
	// green if Enroll stopped consulting the NameChecker at all, having proved
	// only that eight sequential enrollments behave.
	assert.Equal(t, racers, gate.arrivals(),
		"every enrollment must have reached the collision check with the token still unspent")

	assert.Equal(t, []string{"build-box"}, issued,
		"exactly one of %d enrollments that all validated may hold a certificate", racers)
	assert.Len(t, refusals, racers-1)
	for _, code := range refusals {
		assert.Equal(t, codes.Unauthenticated, code, "a loser is refused as a replay, not as a bad request")
	}
	assert.Len(t, fleet.records(), 1,
		"a loser must be refused before it takes a name, or a race leaves fleet members no host will ever answer for")

	// And the one certificate belongs to the racer that won, not to whichever
	// request happened to be in some other goroutine's hands.
	if assert.NotNil(t, winnerCert, "no certificate was issued at all") {
		assert.True(t, winnerPub.Equal(leafOf(t, winnerCert).PublicKey),
			"the issued leaf must carry the public key of the request that won the swap")
	}

	// And the token is spent rather than wedged: a later attempt is refused
	// too, and refused as a replayed token.
	_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{Token: token, RequestedName: "build-box"})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))

	// The store agrees, rather than the endpoint merely behaving as though it
	// did — a token left pending after a race is one a third host can still
	// spend tomorrow.
	_, err = tokens.Inspect(token)
	assert.ErrorIs(t, err, enroll.ErrTokenUsed)
}

// The first of the two consequences round 4 of #54 confirmed.
//
// An enrolling host may add loopback addresses of its own — they name that host
// and nothing else, so they cannot impersonate a peer — and `enroll mint`
// cannot know about them, because they arrive with the request. So a token
// minted at exactly the CA's limit, which mint accepts, reaches one over it at
// redemption. That refusal is correct. Its cost was not: the token was gone
// before the check ran.
func TestEnroll_ALoopbackSANOverflowLeavesTheTokenSpendable(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	fleet := &recordingFleet{}
	svc := &enroll.Service{Tokens: tokens, CA: caObj, Fleet: fleet}
	lis := startControlPlane(t, svc, caObj)

	// The reserved name plus MaxSANs-1 authorized addresses is exactly MaxSANs
	// subject alternative names.
	addrs := make([]string, 0, ca.MaxSANs-1)
	for i := 1; i < ca.MaxSANs; i++ {
		addrs = append(addrs, fmt.Sprintf("10.0.0.%d:8722", i))
	}
	require.NoError(t, enroll.CheckCertifiable("build-box", addrs),
		"the premise: this is a token `fleetctl enroll mint` accepts")

	token, _, err := tokens.Mint(enroll.MintOptions{Name: "build-box", Addresses: addrs})
	require.NoError(t, err)

	// `fleet-agent enroll --address 127.0.0.1:8722` is the seventeenth name.
	_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{
		Token:           token,
		RequestedName:   "build-box",
		ListenAddresses: []string{"127.0.0.1:8722"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "too many subject alternative names")
	assert.Empty(t, fleet.recorded)

	// Dropping --address is the whole fix, and the token is still there to pay
	// for it.
	resp, err := enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{
		Token:         token,
		RequestedName: "build-box",
	})
	require.NoError(t, err, "a SAN set the CA refused must not have cost the operator their token")
	assert.Equal(t, "build-box", resp.GetAssignedName())

	leaf := leafOf(t, resp.GetCertificatePem())
	assert.Equal(t, []string{"build-box"}, leaf.DNSNames)
	assert.Len(t, leaf.IPAddresses, ca.MaxSANs-1)
}

// The second consequence, and the same shape: what mint checked and what
// redemption certifies are not the same string.
//
// Collision resolution appends "-2", so a name one character under the DNS
// label limit — certifiable as itself, and accepted by mint as itself — is two
// bytes over it by the time the CA is asked. That refusal is correct too, and
// it used to arrive with the token already spent, on a host whose real problem
// was a name another fleet member was holding.
func TestEnroll_AnUncertifiableCollisionNameLeavesTheTokenSpendable(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	fleet := &recordingFleet{}
	longName := strings.Repeat("a", 63)
	names := newMutableNames(longName)
	svc := &enroll.Service{Tokens: tokens, CA: caObj, Names: names, Fleet: fleet}
	lis := startControlPlane(t, svc, caObj)

	require.NoError(t, enroll.CheckCertifiable(longName, nil),
		"the premise: this is a name `fleetctl enroll mint` accepts")

	token, _, err := tokens.Mint(enroll.MintOptions{Name: longName})
	require.NoError(t, err)

	_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{Token: token})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "longer than 63 characters")
	assert.Empty(t, fleet.recorded)

	// The operator removes the fleet member that was holding the name — and
	// that is all they have to do, because the token outlived the refusal.
	names.remove(longName)
	resp, err := enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{Token: token})
	require.NoError(t, err, "a name only collision resolution could refuse must not have cost the operator their token")
	assert.Equal(t, longName, resp.GetAssignedName())
}

// Inspect is the read half of the split: it answers the question Redeem asks
// without doing what Redeem does.
func TestTokenStore_InspectDoesNotSpendTheToken(t *testing.T) {
	store := enroll.NewTokenStore()
	token, _, err := store.Mint(enroll.MintOptions{
		Name:      "build-box",
		Labels:    map[string]string{"role": "build"},
		Addresses: []string{"10.0.0.5:8722"},
	})
	require.NoError(t, err)

	first, err := store.Inspect(token)
	require.NoError(t, err)
	again, err := store.Inspect(token)
	require.NoError(t, err, "inspecting a token must not spend it")
	assert.Equal(t, first, again)

	// What Inspect reports has to be what Redeem commits. Enrollment validates
	// the request against the first and is authorized by the second, so a
	// difference between them is a request checked against an authorization it
	// did not receive.
	//
	// Enrollment holds that record for the whole of the validation, so the
	// question is not only whether the store rewrites those fields — it is
	// whether anything holding a record can. Writing through it here is what
	// asks that, and it has to change nothing. Until the store cloned on the
	// way out it did not: Labels and Addresses came back as the entry's own map
	// and slice, which also made comparing the two records a comparison of a
	// value with itself, and this claim unfalsifiable.
	first.Labels["role"] = "tampered"
	first.Addresses[0] = "evil.internal:8722"

	redeemed, err := store.Redeem(token)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"role": "build"}, redeemed.Labels,
		"writing through a record the store handed out must not rewrite what the token authorizes")
	assert.Equal(t, []string{"10.0.0.5:8722"}, redeemed.Addresses,
		"writing through a record the store handed out must not rewrite what the token authorizes")
	assert.Equal(t, first.ID, redeemed.ID)
	assert.Equal(t, first.Name, redeemed.Name)
	assert.Equal(t, first.IssuedAt, redeemed.IssuedAt)
	assert.Equal(t, first.ExpiresAt, redeemed.ExpiresAt)

	_, err = store.Inspect(token)
	assert.ErrorIs(t, err, enroll.ErrTokenUsed, "a spent token is spent to Inspect too")
}

func TestTokenStore_InspectReportsEveryReasonRedeemWould(t *testing.T) {
	store := enroll.NewTokenStore()

	_, err := store.Inspect("sbx_nobody-minted-this")
	assert.ErrorIs(t, err, enroll.ErrTokenInvalid)

	revoked, rec, err := store.Mint(enroll.MintOptions{Name: "revoked-box"})
	require.NoError(t, err)
	_, err = store.Revoke(rec.ID)
	require.NoError(t, err)
	_, err = store.Inspect(revoked)
	assert.ErrorIs(t, err, enroll.ErrTokenRevoked)

	// A short TTL and a longer wait, as TestRedeem_Expired does it. Waiting only
	// ever makes an expiry more true, so a loaded machine cannot turn this into
	// a failure — and a token expired by a clock tick the platform may not have
	// could.
	expired, _, err := store.Mint(enroll.MintOptions{Name: "expired-box", TTL: 10 * time.Millisecond})
	require.NoError(t, err)
	time.Sleep(30 * time.Millisecond)
	_, err = store.Inspect(expired)
	assert.ErrorIs(t, err, enroll.ErrTokenExpired)
}

// Every enrollment attempt now inspects before it redeems, including the ones
// anyone on the network can start. A read that rewrote the store would hand an
// unauthenticated caller the control plane's disk and the cross-process lock
// `fleetctl enroll mint` needs — the cost Redeem already avoids paying, which
// the read half must not reintroduce.
func TestTokenStore_InspectDoesNotRewriteTheStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.yaml")
	store, err := enroll.OpenTokenStore(path)
	require.NoError(t, err)
	token, _, err := store.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	before, err := os.Stat(path)
	require.NoError(t, err)
	// Filesystem timestamp granularity is coarse enough that a write in the
	// same instant would be invisible.
	time.Sleep(20 * time.Millisecond)

	for range 10 {
		_, err := store.Inspect("sbx_nobody-minted-this")
		require.ErrorIs(t, err, enroll.ErrTokenInvalid)
		_, err = store.Inspect(token)
		require.NoError(t, err)
	}

	after, err := os.Stat(path)
	require.NoError(t, err)
	assert.True(t, before.ModTime().Equal(after.ModTime()),
		"inspecting a token must not rewrite the store")
}

// A control plane that cannot read its own token store has not rejected the
// operator's token, and must not say it has.
//
// "Enrollment token rejected" tells an operator to mint another one. Against a
// corrupt store the second token fails exactly as the first did — the same
// misdirected error #58 is about, one layer down, and now reachable from the
// read that was added in front of the redemption.
func TestEnroll_AnUnreadableTokenStoreIsNotBlamedOnTheToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.yaml")
	tokens, err := enroll.OpenTokenStore(path)
	require.NoError(t, err)
	token, _, err := tokens.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	caObj := newTestCA(t)
	svc := &enroll.Service{Tokens: tokens, CA: caObj}
	lis := startControlPlane(t, svc, caObj)

	// The store the serving process re-reads on every operation, no longer
	// parseable — a half-written file, an edit by hand.
	require.NoError(t, os.WriteFile(path, []byte("version: 1\ntokens:\n  - hash: [unclosed\n"), 0o600))

	_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{Token: token, RequestedName: "build-box"})
	require.Error(t, err)
	st := status.Convert(err)
	assert.Equal(t, codes.Internal, st.Code(), "the control plane is broken, not the operator's token")
	assert.NotContains(t, st.Message(), "rejected")
	assert.NotContains(t, st.Message(), path,
		"the control plane describes its own filesystem in its own log, not to an unauthenticated caller")
}

// barrier releases every caller only once all of them have arrived.
type barrier struct {
	mu       sync.Mutex
	arrived  int
	want     int
	released chan struct{}
}

func newBarrier(want int) *barrier {
	return &barrier{want: want, released: make(chan struct{})}
}

// wait blocks until want callers have arrived. The deadline is a failsafe, not
// an assertion: it turns "a caller never arrived" from a test that hangs until
// the package timeout into one that says which caller is missing.
func (b *barrier) wait(deadline time.Duration) error {
	b.mu.Lock()
	b.arrived++
	if b.arrived == b.want {
		close(b.released)
	}
	b.mu.Unlock()

	select {
	case <-b.released:
		return nil
	case <-time.After(deadline):
		return fmt.Errorf("only %d of %d enrollments reached the collision check", b.arrivals(), b.want)
	}
}

// arrivals is how many callers reached the barrier, so a scenario can assert
// that the window it meant to hold open was held open.
func (b *barrier) arrivals() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.arrived
}

// barrierNames is a NameChecker that holds every enrollment at the collision
// check until all of them are there. It reports no name as taken, so Enroll
// consults it exactly once per request.
type barrierNames struct {
	t    *testing.T
	gate *barrier
}

func (n *barrierNames) Exists(string) bool {
	// Thirty seconds for eight goroutines to each generate a key and finish a
	// handshake is a failsafe, not a budget: it turns a caller that never
	// arrives into a named failure instead of a package timeout.
	if err := n.gate.wait(30 * time.Second); err != nil {
		n.t.Error(err)
	}
	return false
}

// syncFleet is recordingFleet for the concurrent scenario, where a regression
// that let two enrollments win would otherwise surface as a race report rather
// than as the assertion it fails.
type syncFleet struct {
	mu       sync.Mutex
	recorded []enroll.EnrolledSandbox
}

func (f *syncFleet) Record(sb enroll.EnrolledSandbox) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recorded = append(f.recorded, sb)
	return nil
}

func (f *syncFleet) records() []enroll.EnrolledSandbox {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]enroll.EnrolledSandbox(nil), f.recorded...)
}

// mutableNames is a NameChecker an operator can change under the control plane,
// which is what removing a stale fleet member looks like from in here.
type mutableNames struct {
	mu       sync.Mutex
	existing map[string]bool
}

func newMutableNames(taken ...string) *mutableNames {
	n := &mutableNames{existing: map[string]bool{}}
	for _, name := range taken {
		n.existing[name] = true
	}
	return n
}

func (n *mutableNames) Exists(name string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.existing[name]
}

func (n *mutableNames) remove(name string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.existing, name)
}

// The record a caller is handed is its own, from every entry point.
//
// Enrollment's whole argument for validating before it redeems is that the
// fields it validates against — Name, Labels, Addresses, ExpiresAt — are
// settled at mint time and cannot change between the read and the swap. Two of
// them are a map and a slice, so a store that returned the entry's own would
// make every holder of a record a writer of them: from another goroutine,
// outside the store's lock, in exactly the window the split opens.
//
// No caller in this tree writes to one today, which is why this is about the
// store's contract rather than a bug being fixed. A contract enrollment's
// soundness rests on is the store's to keep.
func TestTokenStore_RecordsItHandsOutShareNothingWithTheStore(t *testing.T) {
	store := enroll.NewTokenStore()
	authorized := []string{"10.0.0.5:8722"}
	labels := map[string]string{"role": "build"}

	token, minted, err := store.Mint(enroll.MintOptions{
		Name:      "build-box",
		Labels:    labels,
		Addresses: authorized,
	})
	require.NoError(t, err)

	// The options the caller passed are not the store's copy either, so a mint
	// followed by the caller reusing its own slice cannot reach the entry.
	authorized[0] = "evil.internal:8722"
	labels["role"] = "tampered"

	minted.Labels["role"] = "tampered-through-mint"
	minted.Addresses[0] = "evil.internal:8722"

	listed, err := store.List()
	require.NoError(t, err)
	require.Len(t, listed, 1)
	listed[0].Labels["role"] = "tampered-through-list"
	listed[0].Addresses[0] = "evil.internal:8722"

	seen, err := store.Inspect(token)
	require.NoError(t, err)
	seen.Labels["role"] = "tampered-through-inspect"
	seen.Addresses[0] = "evil.internal:8722"

	// What the token authorizes is what it was minted with, whatever any of
	// those holders did with the copy it was given.
	redeemed, err := store.Redeem(token)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"role": "build"}, redeemed.Labels)
	assert.Equal(t, []string{"10.0.0.5:8722"}, redeemed.Addresses)

	// And Redeem's own record is a copy too, so the last holder cannot rewrite
	// the entry `fleetctl enroll list` prints afterwards.
	redeemed.Labels["role"] = "tampered-through-redeem"
	redeemed.Addresses[0] = "evil.internal:8722"
	after, err := store.List()
	require.NoError(t, err)
	require.Len(t, after, 1)
	assert.Equal(t, map[string]string{"role": "build"}, after[0].Labels)
	assert.Equal(t, []string{"10.0.0.5:8722"}, after[0].Addresses)
}

// hookedNames runs fn the first time the collision check is consulted, which is
// inside the window the reorder opens: after the request has been validated
// against a token Inspect said was redeemable, and before the swap that spends
// it. What fn does is what a concurrent operator, or a failing disk, does in
// that window.
type hookedNames struct {
	once sync.Once
	fn   func()
}

func (n *hookedNames) Exists(string) bool {
	n.once.Do(n.fn)
	return false
}

// A token revoked while the request that names it is being validated.
//
// Inspect said the token was redeemable, and by the time the swap is attempted
// it is not. Redeem re-asks under the lock, so it is the swap that refuses,
// which is the property the whole split rests on: the answer enrollment
// validated against is advisory, and the only thing that grants the right to
// proceed re-checks everything.
func TestEnroll_ATokenRevokedWhileItsRequestIsValidatedIsRefused(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	fleet := &recordingFleet{}

	token, rec, err := tokens.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	svc := &enroll.Service{Tokens: tokens, CA: caObj, Fleet: fleet, Names: &hookedNames{fn: func() {
		_, revokeErr := tokens.Revoke(rec.ID)
		assert.NoError(t, revokeErr, "the operator's revoke landed inside the window")
	}}}
	lis := startControlPlane(t, svc, caObj)

	_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{Token: token, RequestedName: "build-box"})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err),
		"a token withdrawn inside the window is refused as a token, not accepted on the strength of a stale read")
	assert.Empty(t, fleet.recorded,
		"an enrollment refused at the swap must leave no fleet member behind")

	// Revoked, not used: nothing was spent on its behalf.
	_, err = tokens.Inspect(token)
	assert.ErrorIs(t, err, enroll.ErrTokenRevoked)
}

// The same window, closed by the clock instead of the operator. Redeem takes
// its own `now`, so a token that expires between the read and the swap is
// refused by the swap.
func TestEnroll_ATokenThatExpiresWhileItsRequestIsValidatedIsRefused(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	fleet := &recordingFleet{}

	// A short TTL and a longer wait, as TestRedeem_Expired does it: waiting
	// only ever makes an expiry more true, so a loaded machine cannot turn this
	// into a failure.
	token, _, err := tokens.Mint(enroll.MintOptions{Name: "build-box", TTL: 100 * time.Millisecond})
	require.NoError(t, err)

	svc := &enroll.Service{Tokens: tokens, CA: caObj, Fleet: fleet, Names: &hookedNames{fn: func() {
		time.Sleep(300 * time.Millisecond)
	}}}
	lis := startControlPlane(t, svc, caObj)

	_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{Token: token, RequestedName: "build-box"})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Empty(t, fleet.recorded)
}

// The store breaking at the swap is not the token being refused either, and the
// distinction has to survive the wrapping reserve does on the way back.
//
// TestEnroll_AnUnreadableTokenStoreIsNotBlamedOnTheToken covers the read in
// front; this covers the write behind it, which is the path the reorder created
// and the only one where a store failure arrives wrapped in errNotRedeemed.
func TestEnroll_AStoreThatBreaksAtTheSwapIsNotBlamedOnTheToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.yaml")
	tokens, err := enroll.OpenTokenStore(path)
	require.NoError(t, err)
	token, _, err := tokens.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	caObj := newTestCA(t)
	fleet := &recordingFleet{}
	svc := &enroll.Service{Tokens: tokens, CA: caObj, Fleet: fleet, Names: &hookedNames{fn: func() {
		assert.NoError(t, os.WriteFile(path, []byte("version: 1\ntokens:\n  - hash: [unclosed\n"), 0o600))
	}}}
	lis := startControlPlane(t, svc, caObj)

	_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{Token: token, RequestedName: "build-box"})
	require.Error(t, err)
	st := status.Convert(err)
	assert.Equal(t, codes.Internal, st.Code(), "the control plane is broken, not the operator's token")
	assert.NotContains(t, st.Message(), "rejected")
	assert.NotContains(t, st.Message(), path)
	assert.Empty(t, fleet.recorded)
}

// The residual, pinned rather than described.
//
// Once the swap is won the token is spent, whatever happens next. That is the
// safe direction and it is what makes a certificate at most once per token: the
// obvious "improvement" — hold the swap until the leaf is signed — is what
// gives every loser of a race its own fleet record, which is the failure the
// ordering exists to prevent. If this ever goes green with the token still
// pending, the swap has moved.
func TestEnroll_ASigningFailureAfterTheSwapStillSpendsTheToken(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{Tokens: tokens, CA: brokenSigner{bundle: caObj.CertPEM()}}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{Token: token, RequestedName: "build-box"})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))

	_, err = tokens.Inspect(token)
	assert.ErrorIs(t, err, enroll.ErrTokenUsed,
		"the swap is what grants the right to proceed, so winning it spends the token even when what follows fails")
}
