package enroll_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/security/enroll"
)

// The name is not the only thing an enrolling host writes into the fleet
// registry. Everything it says about itself — the platform it claims, the
// version it claims, the addresses it names — is persisted beside the name and
// printed back in `fleetctl list`'s table.
//
// Round 2 bounded the name for precisely this reason and bounded nothing else,
// so a host holding one valid token could put a terminal escape sequence, a
// newline, or two hundred kilobytes into the operator's fleet listing.
func TestEnroll_HostDescriptionIsBounded(t *testing.T) {
	cases := map[string]*sandboxdv1.EnrollRequest{
		"escape sequence in os": {
			Platform: &sandboxdv1.Platform{Os: "linux\x1b[2J\x1b[31m ALL SANDBOXES HEALTHY"},
		},
		"newline in hostname": {
			Platform: &sandboxdv1.Platform{Hostname: "build-box\nprod-db  10.0.0.9:9443"},
		},
		"nul in path separator": {
			Platform: &sandboxdv1.Platform{PathSeparator: "\x00"},
		},
		"escape sequence in agent version": {
			AgentVersion: "0.1.0\x1b[8m",
		},
		"oversized architecture": {
			Platform: &sandboxdv1.Platform{Arch: strings.Repeat("a", 100_000)},
		},
		"oversized kernel version": {
			Platform: &sandboxdv1.Platform{KernelVersion: strings.Repeat("k", 257)},
		},
		"control character in listen address": {
			ListenAddresses: []string{"127.0.0.1:9443\r"},
		},
		// U+202E flips the rendering of everything after it, so a name reads
		// in a fleet listing as something other than what it is.
		"right-to-left override in hostname": {
			Platform: &sandboxdv1.Platform{Hostname: "build-\u202egnitset"},
		},
	}

	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			caObj := newTestCA(t)
			tokens := enroll.NewTokenStore()
			fleet := &recordingFleet{}
			svc := &enroll.Service{Tokens: tokens, CA: caObj, Fleet: fleet}
			lis := startControlPlane(t, svc, caObj)

			token, _, err := tokens.Mint(enroll.MintOptions{Name: "build-box"})
			require.NoError(t, err)
			req.Token = token

			_, err = enrollOnce(t, lis, caObj, req)
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.Empty(t, fleet.recorded, "a rejected request must not reach the registry")
		})
	}
}

// The bound has to leave room for what a real host actually reports. A kernel
// version string is long and full of punctuation, and a path separator is a
// backslash on Windows.
func TestEnroll_OrdinaryHostDescriptionIsAccepted(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	fleet := &recordingFleet{}
	svc := &enroll.Service{Tokens: tokens, CA: caObj, Fleet: fleet}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{
		Token:        token,
		AgentVersion: "0.1.0-rc.2+build.7 (go1.25.13)",
		Platform: &sandboxdv1.Platform{
			Os:            "windows",
			Arch:          "amd64",
			KernelVersion: "#45~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Mon Jul  1 12:00:00 UTC 2026",
			Hostname:      "build-box.corp.example.com",
			PathSeparator: `\`,
		},
	})
	require.NoError(t, err)
	require.Len(t, fleet.recorded, 1)
	assert.Equal(t, "windows", fleet.recorded[0].OS)
}

// A host that names more addresses than any host has is describing something
// other than itself. The count is bounded before the loop that walks it.
func TestEnroll_ListenAddressCountIsBounded(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	fleet := &recordingFleet{}
	svc := &enroll.Service{Tokens: tokens, CA: caObj, Fleet: fleet}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	addrs := make([]string, 5_000)
	for i := range addrs {
		addrs[i] = "127.0.0.1:9443"
	}
	_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{
		Token:           token,
		ListenAddresses: addrs,
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Empty(t, fleet.recorded)
}

// Redeeming a token nobody minted is the ordinary case for an endpoint anyone
// on the network can reach. Rewriting the whole token store for each such
// attempt makes an unauthenticated caller drive the control plane's disk, and
// makes it hold the cross-process lock that `fleetctl enroll mint` and
// `enroll list` need to make any progress at all.
func TestTokenStore_FailedRedemptionDoesNotRewriteTheStore(t *testing.T) {
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

	for i := 0; i < 10; i++ {
		_, err := store.Redeem("sbx_nobody-minted-this")
		require.ErrorIs(t, err, enroll.ErrTokenInvalid)
	}

	after, err := os.Stat(path)
	require.NoError(t, err)
	assert.True(t, before.ModTime().Equal(after.ModTime()),
		"a redemption that spent nothing must not rewrite the store")

	// A redemption that does spend a token still persists that, or the token
	// would be replayable.
	_, err = store.Redeem(token)
	require.NoError(t, err)
	spent, err := os.Stat(path)
	require.NoError(t, err)
	assert.False(t, after.ModTime().Equal(spent.ModTime()),
		"spending a token must be persisted")

	reopened, err := enroll.OpenTokenStore(path)
	require.NoError(t, err)
	_, err = reopened.Redeem(token)
	require.ErrorIs(t, err, enroll.ErrTokenUsed)
}
