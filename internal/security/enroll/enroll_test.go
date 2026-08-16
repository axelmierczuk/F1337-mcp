package enroll_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/security/ca"
	"github.com/axelmierczuk/sandboxd-mcp/internal/security/enroll"
)

func newTestCA(t *testing.T) *ca.CA {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ca")
	c, err := ca.Init(dir, false)
	require.NoError(t, err)
	return c
}

// startControlPlane serves an enroll.Service over an in-memory bufconn
// listener, presenting the CA's own certificate as its server identity —
// exactly as sandboxctl serve will, since the enrolling host has nothing
// else to verify against yet.
func startControlPlane(t *testing.T, svc *enroll.Service, caObj *ca.CA) *bufconn.Listener {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{caObj.TLSCertificate()},
		MinVersion:   tls.VersionTLS12,
	})
	s := grpc.NewServer(grpc.Creds(creds))
	sandboxdv1.RegisterEnrollmentServiceServer(s, svc)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	return lis
}

func bufDialer(lis *bufconn.Listener) func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, _ string) (net.Conn, error) {
		return lis.DialContext(ctx)
	}
}

func dialControlPlane(lis *bufconn.Listener, fingerprint [32]byte, extra ...grpc.DialOption) (*grpc.ClientConn, error) {
	opts := append([]grpc.DialOption{grpc.WithContextDialer(bufDialer(lis))}, extra...)
	return enroll.Dial(enroll.DialOptions{
		// "passthrough:///" forces grpc to hand the dialer the literal
		// target rather than resolving it via DNS, which is what lets a
		// bufconn address (not a real, resolvable host) work here.
		Address:          "passthrough:///bufnet",
		CAFingerprint:    fingerprint,
		ExtraDialOptions: opts,
	})
}

func requireDialControlPlane(t *testing.T, lis *bufconn.Listener, fingerprint [32]byte, extra ...grpc.DialOption) *grpc.ClientConn {
	t.Helper()
	cc, err := dialControlPlane(lis, fingerprint, extra...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

type fakeNameChecker struct {
	existing map[string]bool
}

func (f fakeNameChecker) Exists(name string) bool { return f.existing[name] }

func TestFullLoop_MintEnrollValidatesAgainstCA(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{Tokens: tokens, CA: caObj}
	lis := startControlPlane(t, svc, caObj)

	token, rec, err := tokens.Mint("build-box", map[string]string{"role": "build"}, 0)
	require.NoError(t, err)
	assert.False(t, rec.Used)

	cc := requireDialControlPlane(t, lis, caObj.Fingerprint())
	client := sandboxdv1.NewEnrollmentServiceClient(cc)

	key, err := enroll.GenerateKey()
	require.NoError(t, err)
	csrDER, err := enroll.BuildCSR(key, "build-box", []string{"build-box"}, nil)
	require.NoError(t, err)

	resp, err := client.Enroll(context.Background(), &sandboxdv1.EnrollRequest{
		Token:           token,
		CsrDer:          csrDER,
		RequestedName:   "build-box",
		ListenAddresses: []string{"10.0.0.5:8722"},
		AgentVersion:    "0.1.0",
	})
	require.NoError(t, err)

	assert.Equal(t, "build-box", resp.GetAssignedName())
	assert.Equal(t, caObj.CertPEM(), resp.GetCaBundlePem())
	require.NotEmpty(t, resp.GetCertificatePem())

	leaf, err := caObj.VerifyLeaf(resp.GetCertificatePem(), x509.ExtKeyUsageServerAuth)
	require.NoError(t, err)
	assert.Equal(t, "build-box", leaf.Subject.CommonName)
}

func TestRedeem_UsedTwiceSequentially(t *testing.T) {
	store := enroll.NewTokenStore()
	token, _, err := store.Mint("build-box", nil, 0)
	require.NoError(t, err)

	_, err = store.Redeem(token)
	require.NoError(t, err)

	_, err = store.Redeem(token)
	require.ErrorIs(t, err, enroll.ErrTokenUsed)
}

func TestRedeem_ConcurrentRedemption_ExactlyOneSucceeds(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{Tokens: tokens, CA: caObj}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint("build-box", nil, 0)
	require.NoError(t, err)

	const n = 25
	var successes, usedRejections int32
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()

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
				t.Errorf("dial: %v", err)
				return
			}
			defer func() { _ = cc.Close() }()

			client := sandboxdv1.NewEnrollmentServiceClient(cc)
			_, err = client.Enroll(context.Background(), &sandboxdv1.EnrollRequest{
				Token:         token,
				CsrDer:        csrDER,
				RequestedName: "build-box",
			})
			if err == nil {
				atomic.AddInt32(&successes, 1)
				return
			}
			if st, ok := status.FromError(err); ok && st.Code() == codes.PermissionDenied {
				atomic.AddInt32(&usedRejections, 1)
			}
		}()
	}
	wg.Wait()

	assert.EqualValues(t, 1, atomic.LoadInt32(&successes), "exactly one concurrent redemption must succeed")
	assert.EqualValues(t, n-1, atomic.LoadInt32(&usedRejections), "every other redemption must be rejected as already used")
}

func TestRedeem_Expired(t *testing.T) {
	store := enroll.NewTokenStore()
	token, _, err := store.Mint("build-box", nil, 10*time.Millisecond)
	require.NoError(t, err)

	time.Sleep(30 * time.Millisecond)

	_, err = store.Redeem(token)
	require.ErrorIs(t, err, enroll.ErrTokenExpired)
}

func TestEnroll_ExpiredTokenRejectedOverRPC(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{Tokens: tokens, CA: caObj}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint("build-box", nil, 10*time.Millisecond)
	require.NoError(t, err)
	time.Sleep(30 * time.Millisecond)

	cc := requireDialControlPlane(t, lis, caObj.Fingerprint())
	client := sandboxdv1.NewEnrollmentServiceClient(cc)

	key, err := enroll.GenerateKey()
	require.NoError(t, err)
	csrDER, err := enroll.BuildCSR(key, "build-box", nil, nil)
	require.NoError(t, err)

	_, err = client.Enroll(context.Background(), &sandboxdv1.EnrollRequest{Token: token, CsrDer: csrDER, RequestedName: "build-box"})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.DeadlineExceeded, st.Code())
}

func TestEnroll_InvalidTokenRejected(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{Tokens: tokens, CA: caObj}
	lis := startControlPlane(t, svc, caObj)

	cc := requireDialControlPlane(t, lis, caObj.Fingerprint())
	client := sandboxdv1.NewEnrollmentServiceClient(cc)

	key, err := enroll.GenerateKey()
	require.NoError(t, err)
	csrDER, err := enroll.BuildCSR(key, "build-box", nil, nil)
	require.NoError(t, err)

	_, err = client.Enroll(context.Background(), &sandboxdv1.EnrollRequest{Token: "sbx_not-a-real-token", CsrDer: csrDER, RequestedName: "build-box"})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestDial_WrongFingerprintAbortsBeforeTokenSent(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{Tokens: tokens, CA: caObj}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint("build-box", nil, 0)
	require.NoError(t, err)

	wrongFingerprint := sha256.Sum256([]byte("not the real CA"))
	cc, err := dialControlPlane(lis, wrongFingerprint)
	require.NoError(t, err) // Dial itself is lazy; the handshake happens on first RPC.
	defer func() { _ = cc.Close() }()

	client := sandboxdv1.NewEnrollmentServiceClient(cc)
	key, err := enroll.GenerateKey()
	require.NoError(t, err)
	csrDER, err := enroll.BuildCSR(key, "build-box", nil, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = client.Enroll(ctx, &sandboxdv1.EnrollRequest{Token: token, CsrDer: csrDER, RequestedName: "build-box"})
	require.Error(t, err)

	// The handshake must have failed before the RPC — and the token inside
	// it — was ever written to the connection: the token is still
	// redeemable.
	_, err = tokens.Redeem(token)
	require.NoError(t, err)
}

func TestDial_RequiresFingerprintUnlessOptedOut(t *testing.T) {
	_, err := enroll.Dial(enroll.DialOptions{Address: "bufnet"})
	require.ErrorIs(t, err, enroll.ErrFingerprintRequired)

	_, err = enroll.Dial(enroll.DialOptions{Address: "bufnet", InsecureSkipPinning: true})
	require.NoError(t, err)
}

func TestEnroll_NameCollisionAssignsDistinctName(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{
		Tokens: tokens,
		CA:     caObj,
		Names:  fakeNameChecker{existing: map[string]bool{"build-box": true}},
	}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint("", nil, 0)
	require.NoError(t, err)

	cc := requireDialControlPlane(t, lis, caObj.Fingerprint())
	client := sandboxdv1.NewEnrollmentServiceClient(cc)

	key, err := enroll.GenerateKey()
	require.NoError(t, err)
	csrDER, err := enroll.BuildCSR(key, "build-box", nil, nil)
	require.NoError(t, err)

	resp, err := client.Enroll(context.Background(), &sandboxdv1.EnrollRequest{
		Token:         token,
		CsrDer:        csrDER,
		RequestedName: "build-box",
	})
	require.NoError(t, err)

	assert.NotEqual(t, "build-box", resp.GetAssignedName())
	assert.Contains(t, resp.GetAssignedName(), "build-box")
}

func TestPrivateKeyNeverAppearsOnWire(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{Tokens: tokens, CA: caObj}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint("build-box", nil, 0)
	require.NoError(t, err)

	key, err := enroll.GenerateKey()
	require.NoError(t, err)
	csrDER, err := enroll.BuildCSR(key, "build-box", nil, nil)
	require.NoError(t, err)

	var capturedWire []byte
	capture := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if msg, ok := req.(proto.Message); ok {
			b, err := proto.Marshal(msg)
			require.NoError(t, err)
			capturedWire = b
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}

	cc := requireDialControlPlane(t, lis, caObj.Fingerprint(), grpc.WithChainUnaryInterceptor(capture))
	client := sandboxdv1.NewEnrollmentServiceClient(cc)

	_, err = client.Enroll(context.Background(), &sandboxdv1.EnrollRequest{
		Token:         token,
		CsrDer:        csrDER,
		RequestedName: "build-box",
	})
	require.NoError(t, err)
	require.NotEmpty(t, capturedWire)

	// EnrollRequest has no field for a private key, but assert on the actual
	// marshaled bytes as a structural regression guard: the key's raw
	// scalar must never appear in what went out on the wire.
	rawKey, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	assert.False(t, bytes.Contains(capturedWire, rawKey))

	dBytes := key.D.Bytes()
	require.Greater(t, len(dBytes), 8, "test key scalar too small to assert on")
	assert.False(t, bytes.Contains(capturedWire, dBytes))
}

func TestEnroll_RejectsInvalidCSR(t *testing.T) {
	caObj := newTestCA(t)
	tokens := enroll.NewTokenStore()
	svc := &enroll.Service{Tokens: tokens, CA: caObj}
	lis := startControlPlane(t, svc, caObj)

	token, _, err := tokens.Mint("build-box", nil, 0)
	require.NoError(t, err)

	cc := requireDialControlPlane(t, lis, caObj.Fingerprint())
	client := sandboxdv1.NewEnrollmentServiceClient(cc)

	_, err = client.Enroll(context.Background(), &sandboxdv1.EnrollRequest{
		Token:         token,
		CsrDer:        []byte("not a csr"),
		RequestedName: "build-box",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())

	// The token must not have been burned by a request that never made it
	// past CSR parsing... except it already was, per the mark-before-sign
	// contract: the token is consumed on first redemption regardless of
	// whether signing subsequently fails, so a caller must mint a fresh one
	// to retry. Assert that contract explicitly.
	_, err = tokens.Redeem(token)
	require.ErrorIs(t, err, enroll.ErrTokenUsed)
}
