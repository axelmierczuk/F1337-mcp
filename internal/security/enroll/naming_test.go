package enroll_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/security/enroll"
)

// The name is the other half of the identity a token authorizes, and round 1
// only closed the address half. A host holding one valid token asks to be
// enrolled under a different name; if the control plane obliges, the name lands
// in the leaf's SANs and that leaf is a working impersonation of whatever it
// names — for its whole life, to every client that trusts the fleet CA.
func TestEnroll_RequestedNameCannotWidenTheCertificate(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		// A DNS name: impersonates another fleet member dialled by name.
		"another fleet member": "prod-db.internal",
		// An IP literal: net.ParseIP succeeds, so it becomes an IP SAN and
		// impersonates whatever the control plane dials at that address.
		"an address": "10.0.0.9",
		// The control plane's own name: an agent leaf valid for it defeats the
		// hostname check that stops a fake enrollment endpoint harvesting
		// tokens.
		"the control plane": controlPlaneHost,
	}

	for name, claimed := range cases {
		t.Run(name, func(t *testing.T) {
			caObj := newTestCA(t)
			tokens := enroll.NewTokenStore()
			svc := &enroll.Service{Tokens: tokens, CA: caObj}
			lis := startControlPlane(t, svc, caObj)

			token, _, err := tokens.Mint(enroll.MintOptions{
				Name:      "dev-box",
				Addresses: []string{"dev-box.internal:9443"},
			})
			require.NoError(t, err)

			resp, err := enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{
				Token:         token,
				RequestedName: claimed,
			})
			if err == nil {
				leaf := leafOf(t, resp.GetCertificatePem())
				t.Fatalf("enrollment as %q succeeded; leaf names %v / %v",
					claimed, leaf.DNSNames, leaf.IPAddresses)
			}
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, codes.InvalidArgument, st.Code())
			assert.Contains(t, st.Message(), "dev-box", "the error should name what the token actually reserves")
		})
	}
}

// The requested name is the one identifier an unauthenticated caller puts into
// a certificate subject and a registry key, so it is bounded before it gets
// there.
func TestEnroll_RequestedNameIsBounded(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"too long":         strings.Repeat("a", 129),
		"control char":     "build\nbox",
		"non-ascii":        "build-böx",
		"embedded newline": "build-box\nrole: admin",
	}
	for name, claimed := range cases {
		t.Run(name, func(t *testing.T) {
			caObj := newTestCA(t)
			tokens := enroll.NewTokenStore()
			svc := &enroll.Service{Tokens: tokens, CA: caObj}
			lis := startControlPlane(t, svc, caObj)

			token, _, err := tokens.Mint(enroll.MintOptions{})
			require.NoError(t, err)

			_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{Token: token, RequestedName: claimed})
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

// A token that reserves no name lets the enrolling host pick one — that is a
// legitimate operator choice for bulk enrollment — but a name this side did not
// choose is a registry label, never a certified identity.
func TestEnroll_HostChosenNameIsNotCertified(t *testing.T) {
	t.Parallel()
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{Tokens: tokens, CA: caObj}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint(enroll.MintOptions{Addresses: []string{"10.0.0.5:9443"}})
	require.NoError(t, err)

	resp, err := enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{
		Token:         token,
		RequestedName: "prod-db.internal",
	})
	require.NoError(t, err)
	assert.Equal(t, "prod-db.internal", resp.GetAssignedName(), "the host may still be recorded under the name it asked for")

	leaf := leafOf(t, resp.GetCertificatePem())
	assert.NotContains(t, leaf.DNSNames, "prod-db.internal",
		"a name the control plane did not take from the token must not be certified")
	assert.NotEqual(t, "prod-db.internal", leaf.Subject.CommonName,
		"the subject is a certified field too, not a free-text label")
	require.Len(t, leaf.IPAddresses, 1)
	assert.Equal(t, "10.0.0.5", leaf.IPAddresses[0].String())
}

// The subject is where round 2's fix stopped short. It kept a host-chosen name
// out of the SANs and then passed that same name to the CA as the leaf's
// subject, so one valid token still yielded a CA-signed leaf whose common name
// was whatever its holder typed — including the control plane's own name.
//
// Nothing in the fleet resolves an identity from a common name today, which is
// the only reason this was latent rather than exploited: Go stopped honouring
// the common name for hostname verification years ago. It is still a certified
// field, it is still the field an operator reads off a certificate to decide
// what that certificate is, and the milestone that adds an audited principal
// will read it. A token authorizes an identity or it does not.
func TestEnroll_HostChosenNameStaysOutOfTheSubject(t *testing.T) {
	t.Parallel()
	for _, claimed := range []string{controlPlaneHost, "prod-db.internal", "10.0.0.9"} {
		t.Run(claimed, func(t *testing.T) {
			caObj := newTestCA(t)
			tokens := enroll.NewTokenStore()
			svc := &enroll.Service{Tokens: tokens, CA: caObj}
			lis := startControlPlane(t, svc, caObj)

			// A token that reserves no name is the only way a host gets to
			// choose one, and it is the path round 2 documented as safe.
			token, _, err := tokens.Mint(enroll.MintOptions{Addresses: []string{"10.0.0.5:9443"}})
			require.NoError(t, err)

			resp, err := enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{
				Token:         token,
				RequestedName: claimed,
			})
			require.NoError(t, err)
			assert.Equal(t, claimed, resp.GetAssignedName(), "the registry label is still the host's to pick")

			leaf := leafOf(t, resp.GetCertificatePem())
			assert.NotEqual(t, claimed, leaf.Subject.CommonName,
				"a name the control plane did not take from the token must not reach the certificate's subject")
			assert.NotContains(t, leaf.DNSNames, claimed)
			for _, ip := range leaf.IPAddresses {
				assert.NotEqual(t, claimed, ip.String())
			}
		})
	}
}

// A token that does reserve a name certifies that name, in the subject as well
// as the SANs — the fix above must not have thrown the ordinary case away.
func TestEnroll_ReservedNameIsCertifiedInTheSubject(t *testing.T) {
	t.Parallel()
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{Tokens: tokens, CA: caObj}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	resp, err := enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{Token: token})
	require.NoError(t, err)

	leaf := leafOf(t, resp.GetCertificatePem())
	assert.Equal(t, "build-box", leaf.Subject.CommonName)
	assert.Equal(t, []string{"build-box"}, leaf.DNSNames)
}

// Collision resolution hands out a distinct name; the leaf must carry that
// distinct name and not the one already in the fleet, or resolving the
// collision would issue a certificate for the incumbent.
func TestEnroll_CollisionResolvedNameIsWhatGetsCertified(t *testing.T) {
	t.Parallel()
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{
		Tokens: tokens,
		CA:     caObj,
		Names:  fakeNameChecker{existing: map[string]bool{"build-box": true}},
	}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	resp, err := enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{Token: token})
	require.NoError(t, err)
	assert.Equal(t, "build-box-2", resp.GetAssignedName())

	leaf := leafOf(t, resp.GetCertificatePem())
	assert.Equal(t, []string{"build-box-2"}, leaf.DNSNames,
		"the leaf must name the sandbox that was actually created, not the one it collided with")
}

// alwaysTaken stands in for registry.Exists when the registry cannot be read:
// it reports every name as taken, deliberately, because refusing to reuse a
// name it cannot rule out is the safe direction. Collision resolution has to
// terminate anyway.
type alwaysTaken struct{}

func (alwaysTaken) Exists(string) bool { return true }

func TestEnroll_UnresolvableCollisionTerminates(t *testing.T) {
	t.Parallel()
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{Tokens: tokens, CA: caObj, Names: alwaysTaken{}}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	key, err := enroll.GenerateKey()
	require.NoError(t, err)
	csrDER, err := enroll.BuildCSR(key, "", nil, nil)
	require.NoError(t, err)

	cc := requireDialControlPlane(t, lis, caObj.Fingerprint())
	// A deadline far longer than the handler should ever need. The failure
	// this guards against is the handler never answering at all, so the client
	// must not be the thing that gives up — a client timeout would look like a
	// pass while the server goroutine span forever behind it.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	_, err = sandboxdv1.NewEnrollmentServiceClient(cc).Enroll(ctx, &sandboxdv1.EnrollRequest{
		Token:  token,
		CsrDer: csrDER,
	})
	elapsed := time.Since(start)

	require.Error(t, err, "a name that can never be resolved must fail, not succeed")
	assert.NotEqual(t, codes.DeadlineExceeded, status.Code(err),
		"the handler must answer; a deadline here means collision resolution never terminated")
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.Less(t, elapsed, 10*time.Second, "collision resolution must give up quickly, not grind")
}

// racingRecorder is a fleet registry that only the first writer of a name wins,
// which is what a real registry's atomic add does. The collision check that
// precedes the write cannot be trusted: between it and the write, another host
// can take the name.
type racingRecorder struct {
	mu    sync.Mutex
	taken map[string]bool
	// stale is consulted by Exists but updated late, so every caller passes
	// the collision check for a name that Record then refuses. This is the
	// window a real registry has between its read lock and its write lock.
	stale map[string]bool
}

func newRacingRecorder() *racingRecorder {
	return &racingRecorder{taken: map[string]bool{}, stale: map[string]bool{}}
}

func (r *racingRecorder) Exists(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stale[name]
}

func (r *racingRecorder) Record(sb enroll.EnrolledSandbox) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.taken[sb.Name] {
		return fmt.Errorf("%w: %s", enroll.ErrNameTaken, sb.Name)
	}
	r.taken[sb.Name] = true
	return nil
}

// settle makes every name recorded so far visible to Exists, simulating the
// collision check catching up with reality.
func (r *racingRecorder) settle() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name := range r.taken {
		r.stale[name] = true
	}
}

// The registry write, not the collision check before it, is what reserves a
// name. Two hosts enrolling at the same instant both pass the check, so the
// loser of the write has to be handed the next free name rather than an
// Internal error and a spent token.
func TestEnroll_ConcurrentEnrollmentsGetDistinctNames(t *testing.T) {
	t.Parallel()
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	fleet := newRacingRecorder()
	svc := &enroll.Service{
		Tokens:  tokens,
		CA:      caObj,
		Names:   fleet,
		Fleet:   fleet,
		Limiter: enroll.NewRateLimiter(time.Minute, 0, 0),
	}
	lis := startControlPlane(t, svc, caObj)

	const hosts = 6
	minted := make([]string, hosts)
	for i := range minted {
		token, _, err := tokens.Mint(enroll.MintOptions{Name: "build-box"})
		require.NoError(t, err)
		minted[i] = token
	}

	var (
		mu     sync.Mutex
		names  = map[string]bool{}
		errsCh = make(chan error, hosts)
		wg     sync.WaitGroup
	)
	wg.Add(hosts)
	for _, token := range minted {
		go func(token string) {
			defer wg.Done()
			resp, err := enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{Token: token})
			if err != nil {
				errsCh <- err
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if names[resp.GetAssignedName()] {
				errsCh <- fmt.Errorf("two hosts were both assigned %q", resp.GetAssignedName())
				return
			}
			names[resp.GetAssignedName()] = true
		}(token)
	}
	wg.Wait()
	close(errsCh)

	for err := range errsCh {
		t.Errorf("concurrent enrollment failed: %v", err)
	}
	assert.Len(t, names, hosts, "every host must end up with its own name")
	fleet.settle()
}

// failingRecorder reports a failure carrying the kind of detail a real registry
// error does: an absolute path on the control plane's filesystem.
type failingRecorder struct{}

func (failingRecorder) Record(enroll.EnrolledSandbox) error {
	return errors.New("registry: save /home/operator/.config/fleet/registry.yaml: disk full")
}

// The enrolling host is unauthenticated. A registry failure is the control
// plane's problem, and its message names the control plane's filesystem, so it
// belongs in the log rather than in the response.
func TestEnroll_RegistryFailureDoesNotLeakControlPlaneDetail(t *testing.T) {
	t.Parallel()
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{Tokens: tokens, CA: caObj, Fleet: failingRecorder{}}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	_, err = enrollOnce(t, lis, caObj, &sandboxdv1.EnrollRequest{Token: token})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
	assert.NotContains(t, st.Message(), "/home/operator", "the control plane's paths must not be handed to an unauthenticated caller")
	assert.NotContains(t, strings.ToLower(st.Message()), "disk full")
}

// A request that cannot be signed must not leave a fleet member behind. The
// registry entry is written first, to reserve the name before signing, so
// everything that can reject the request has to run before that write.
func TestEnroll_UnsignableRequestRecordsNothing(t *testing.T) {
	t.Parallel()
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	fleet := &recordingFleet{}
	svc := &enroll.Service{Tokens: tokens, CA: caObj, Fleet: fleet}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint(enroll.MintOptions{Name: "build-box"})
	require.NoError(t, err)

	cc := requireDialControlPlane(t, lis, caObj.Fingerprint())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = sandboxdv1.NewEnrollmentServiceClient(cc).Enroll(ctx, &sandboxdv1.EnrollRequest{
		Token:  token,
		CsrDer: []byte("not a csr"),
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Empty(t, fleet.recorded, "a request rejected before signing must not create a fleet member")
}
