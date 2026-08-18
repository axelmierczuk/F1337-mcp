package client_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/client"
	"github.com/axelmierczuk/fleet-mcp/internal/registry"
)

// servePlaintextAgent starts a fake agent with no TLS at all — the transport an
// agent configured with `tls.enabled: false` actually serves.
func servePlaintextAgent(t *testing.T, agent sandboxdv1.HostServiceServer) (address string, dialOpt grpc.DialOption) {
	t.Helper()

	const name = "tailnet-box"
	lis := bufconn.Listen(4 * 1024 * 1024)
	s := grpc.NewServer()
	sandboxdv1.RegisterHostServiceServer(s, agent)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)

	return name + ":8722", grpc.WithContextDialer(dialerFor(name, lis))
}

// syncBuffer is a log sink a test can read while a pool is still writing to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A pool holding no credentials at all reaches a sandbox registered as
// insecure, and says out loud that it did.
//
// This is the workstation the option exists for: no CA, no control leaf, and a
// fleet that runs on a network which authenticates its own peers. Building the
// pool must not be the thing that fails there.
func TestPool_ReachesAnInsecureSandboxWithNoCredentialsAtAll(t *testing.T) {
	t.Parallel()

	fake := newFakeAgent()
	addr, dialOpt := servePlaintextAgent(t, fake)

	logs := &syncBuffer{}
	pool, err := client.NewPool(client.Config{
		DialOptions: []grpc.DialOption{dialOpt},
		Log:         slog.New(slog.NewTextHandler(logs, nil)),
	})
	require.NoError(t, err, "a pool with no mTLS material is a usable pool")
	t.Cleanup(func() { _ = pool.Close() })

	host, err := pool.Host(client.Target{Name: "tailnet-box", Address: addr, Insecure: true})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = host.Health(ctx, &sandboxdv1.HealthRequest{})
	require.NoError(t, err)
	// Not an exact count: the pool's background health loop probes a freshly
	// dialled channel immediately, so this call is not the only one to arrive.
	assert.Positive(t, fake.servedCount())

	// "Refuse to do so silently" is half the requirement: a control plane that
	// took an unauthenticated connection without mentioning it would be the one
	// participant in this posture that never says what it is.
	assert.Contains(t, logs.String(), "CONNECTING TO A SANDBOX THIS FLEET DOES NOT AUTHENTICATE")
	assert.Contains(t, logs.String(), "tailnet-box")
}

// The same pool refuses a sandbox that is *not* registered as insecure, naming
// what is missing rather than dialling something it cannot authenticate.
//
// The alternative — falling back to plaintext because there is no certificate
// to present — is the silent downgrade this whole design exists to make
// impossible.
func TestPool_RefusesAnMTLSSandboxWhenItHoldsNoCredentials(t *testing.T) {
	t.Parallel()

	pool, err := client.NewPool(client.Config{
		CredentialErr: errors.New("no control certificate at /home/op/.config/fleet/control.crt: run `fleetctl ca sign --profile control`"),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pool.Close() })

	_, err = pool.Host(client.Target{Name: "build-box", Address: "build-box:8722"})
	require.Error(t, err)
	assert.ErrorIs(t, err, client.ErrNoCredentials)
	assert.Contains(t, err.Error(), "build-box", "the refusal names the sandbox that could not be reached")
	assert.Contains(t, err.Error(), "fleetctl ca sign", "and the command that fixes it")

	// The loader's own words, not the sentinel: a listing says this once above
	// the table, and "run `fleetctl ca sign --profile control`" is the half an
	// operator can act on.
	require.Error(t, pool.CredentialErr())
	assert.Contains(t, pool.CredentialErr().Error(), "control certificate")
	assert.Zero(t, pool.DialCount(), "nothing was dialled")
}

// A pool that does hold credentials still dials an insecure target in
// plaintext. The posture is the registry's decision per sandbox, not a
// consequence of what this workstation happens to have on disk.
func TestPool_DialsAnInsecureTargetInPlaintextEvenHoldingACertificate(t *testing.T) {
	t.Parallel()

	fleet := newTestFleet(t)
	fake := newFakeAgent()
	addr, dialOpt := servePlaintextAgent(t, fake)

	certPEM, keyPEM := fleet.controlCert()
	pool, err := client.NewPool(client.Config{
		CACertPEM:   fleet.ca.CertPEM(),
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		DialOptions: []grpc.DialOption{dialOpt},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pool.Close() })

	host, err := pool.Host(client.TargetFor(registry.Sandbox{Name: "tailnet-box", Address: addr, Insecure: true}))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = host.Health(ctx, &sandboxdv1.HealthRequest{})
	require.NoError(t, err)
	assert.Positive(t, fake.servedCount())
}

// Getting the posture wrong fails loudly in both directions. That is the
// property that makes a per-sandbox flag safe to be wrong about: a mistake
// costs a connection, never an unnoticed downgrade.
func TestPool_MismatchedPostureFailsRatherThanFallingBack(t *testing.T) {
	t.Parallel()

	t.Run("mTLS dial to a plaintext agent", func(t *testing.T) {
		t.Parallel()
		fleet := newTestFleet(t)
		fake := newFakeAgent()
		addr, dialOpt := servePlaintextAgent(t, fake)

		certPEM, keyPEM := fleet.controlCert()
		pool, err := client.NewPool(client.Config{
			CACertPEM:   fleet.ca.CertPEM(),
			CertPEM:     certPEM,
			KeyPEM:      keyPEM,
			DialOptions: []grpc.DialOption{dialOpt},
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = pool.Close() })

		host, err := pool.Host(client.Target{Name: "tailnet-box", Address: addr})
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err = host.Health(ctx, &sandboxdv1.HealthRequest{})
		require.Error(t, err, "an mTLS client must not silently succeed against a plaintext agent")
		assert.Zero(t, fake.servedCount(), "and nothing reached the service")
	})

	t.Run("plaintext dial to an mTLS agent", func(t *testing.T) {
		t.Parallel()
		fleet := newTestFleet(t)
		fake := newFakeAgent()
		addr, dialOpt, _ := serveAgent(t, fleet.ca, "build-box", fake)

		pool, err := client.NewPool(client.Config{DialOptions: []grpc.DialOption{dialOpt}})
		require.NoError(t, err)
		t.Cleanup(func() { _ = pool.Close() })

		host, err := pool.Host(client.Target{Name: "build-box", Address: addr, Insecure: true})
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err = host.Health(ctx, &sandboxdv1.HealthRequest{})
		require.Error(t, err, "a plaintext client must not reach an agent that demands a certificate")
		assert.Zero(t, fake.servedCount())
	})
}

// A sandbox whose posture changes is redialled, exactly as one whose address
// changes is.
//
// Without this, an operator who turned mTLS on for a host would keep reaching
// it over the plaintext channel a running control plane had already pooled —
// and every view of the fleet would go on reporting the old posture.
func TestPool_RedialsWhenThePostureChanges(t *testing.T) {
	t.Parallel()

	fleet := newTestFleet(t)
	fake := newFakeAgent()
	addr, dialOpt := servePlaintextAgent(t, fake)

	certPEM, keyPEM := fleet.controlCert()
	pool, err := client.NewPool(client.Config{
		CACertPEM:   fleet.ca.CertPEM(),
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		DialOptions: []grpc.DialOption{dialOpt},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pool.Close() })

	insecureTarget := client.Target{Name: "tailnet-box", Address: addr, Insecure: true}
	_, err = pool.Conn(insecureTarget)
	require.NoError(t, err)
	_, err = pool.Conn(insecureTarget)
	require.NoError(t, err)
	require.EqualValues(t, 1, pool.DialCount(), "an unchanged target reuses its channel")

	_, err = pool.Conn(client.Target{Name: "tailnet-box", Address: addr})
	require.NoError(t, err)
	assert.EqualValues(t, 2, pool.DialCount(), "a changed posture is a new channel, not the old one")
}

// TargetFor is the one conversion from a registry entry, so the posture
// recorded and the posture dialled cannot drift.
func TestTargetFor_CarriesThePostureAndNamesIt(t *testing.T) {
	t.Parallel()

	secure := client.TargetFor(registry.Sandbox{Name: "build-box", Address: "build-box:8722"})
	assert.False(t, secure.Insecure)
	assert.True(t, secure.Authenticated())
	assert.Equal(t, client.AuthMTLS, secure.AuthName())

	open := client.TargetFor(registry.Sandbox{Name: "tailnet-box", Address: "100.83.4.17:8722", Insecure: true})
	assert.True(t, open.Insecure)
	assert.False(t, open.Authenticated())
	assert.Equal(t, client.AuthNone, open.AuthName())
	assert.Equal(t, "100.83.4.17:8722", open.Address)
}

// A malformed address is refused for an insecure target too. There is no
// certificate to verify against a name there, but a registry entry that is not
// host:port is broken either way and one error for it beats two.
func TestPool_RefusesAMalformedAddressWhicheverPostureItCarries(t *testing.T) {
	t.Parallel()

	pool, err := client.NewPool(client.Config{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pool.Close() })

	_, err = pool.Conn(client.Target{Name: "tailnet-box", Address: "no-port-here", Insecure: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not host:port")
	assert.False(t, strings.Contains(err.Error(), client.ErrNoCredentials.Error()),
		"an insecure target needs no credential, so this must not be reported as a missing one")
}
