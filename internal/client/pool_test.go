package client_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/client"
	"github.com/axelmierczuk/fleet-mcp/internal/security/ca"
)

func newTestPool(t *testing.T, fleet *testFleet, dialOpts ...grpc.DialOption) *client.Pool {
	t.Helper()
	certPEM, keyPEM := fleet.controlCert()
	pool, err := client.NewPool(client.Config{
		CACertPEM:   fleet.ca.CertPEM(),
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		DialOptions: dialOpts,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pool.Close() })
	return pool
}

func TestPool_ConnectAndIssueRPC(t *testing.T) {
	fleet := newTestFleet(t)
	agent := newFakeAgent()
	addr, dialOpt, _ := serveAgent(t, fleet.ca, "agent-a", agent)

	pool := newTestPool(t, fleet, dialOpt)

	hostClient, err := pool.Host("agent-a", addr)
	require.NoError(t, err)

	resp, err := hostClient.Health(context.Background(), &sandboxdv1.HealthRequest{})
	require.NoError(t, err)
	assert.Equal(t, sandboxdv1.HealthResponse_STATUS_SERVING, resp.GetStatus())
	assert.Equal(t, "0.1.0-test", resp.GetAgentVersion())
}

func TestPool_ReuseChannel_SecondCallDoesNotRedial(t *testing.T) {
	fleet := newTestFleet(t)
	agent := newFakeAgent()
	addr, dialOpt, _ := serveAgent(t, fleet.ca, "agent-a", agent)

	pool := newTestPool(t, fleet, dialOpt)

	_, err := pool.Conn("agent-a", addr)
	require.NoError(t, err)
	firstDialCount := pool.DialCount()
	require.EqualValues(t, 1, firstDialCount)

	_, err = pool.Conn("agent-a", addr)
	require.NoError(t, err)

	assert.EqualValues(t, firstDialCount, pool.DialCount(), "second call for the same sandbox must reuse the pooled channel")
}

func TestPool_UnreachableSandbox_DoesNotBlockOthers(t *testing.T) {
	fleet := newTestFleet(t)
	agent := newFakeAgent()
	upAddr, dialOpt, _ := serveAgent(t, fleet.ca, "up-box", agent)

	pool := newTestPool(t, fleet, dialOpt)

	upClient, err := pool.Host("up-box", upAddr)
	require.NoError(t, err)
	downClient, err := pool.Host("down-box", "down-box:8722")
	require.NoError(t, err)

	var wg sync.WaitGroup
	var upErr, downErr error
	var upElapsed, downElapsed time.Duration
	wg.Add(2)

	go func() {
		defer wg.Done()
		start := time.Now()
		_, upErr = upClient.Health(context.Background(), &sandboxdv1.HealthRequest{})
		upElapsed = time.Since(start)
	}()
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, downErr = downClient.Health(ctx, &sandboxdv1.HealthRequest{})
		downElapsed = time.Since(start)
	}()
	wg.Wait()

	require.NoError(t, upErr)
	assert.Less(t, upElapsed, 250*time.Millisecond, "a reachable sandbox must not be delayed by an unrelated unreachable one")

	require.Error(t, downErr)
	assert.GreaterOrEqual(t, downElapsed, 450*time.Millisecond, "the unreachable call must run for roughly its own deadline")
	assert.Less(t, downElapsed, 2*time.Second, "the unreachable call must fail within its deadline, not hang")
}

func TestPool_ServerCertFromDifferentCA_Rejected(t *testing.T) {
	fleet := newTestFleet(t)

	imposterDir := filepath.Join(t.TempDir(), "imposter-ca")
	imposterCA, err := ca.Init(imposterDir, false)
	require.NoError(t, err)

	agent := newFakeAgent()
	// The agent presents a leaf signed by a CA the pool does not trust.
	addr, dialOpt, _ := serveAgent(t, imposterCA, "agent-a", agent)

	pool := newTestPool(t, fleet, dialOpt)

	hostClient, err := pool.Host("agent-a", addr)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = hostClient.Health(ctx, &sandboxdv1.HealthRequest{})
	require.Error(t, err)
	// Assert on *why* it failed. A bare require.Error here would pass if the
	// RPC broke for any unrelated reason, which is exactly the way a
	// certificate check regresses without anyone noticing.
	assertTLSFailure(t, err)
}

func TestPool_AgentLeafAsClientCert_RejectedByServer(t *testing.T) {
	fleet := newTestFleet(t)
	agent := newFakeAgent()
	addr, dialOpt, _ := serveAgent(t, fleet.ca, "agent-a", agent)

	// Misconfigure the pool with an agent leaf instead of a control leaf as
	// its own client identity.
	agentCertPEM, agentKeyPEM := fleet.agentCert("fleet-mcp")
	pool, err := client.NewPool(client.Config{
		CACertPEM:   fleet.ca.CertPEM(),
		CertPEM:     agentCertPEM,
		KeyPEM:      agentKeyPEM,
		DialOptions: []grpc.DialOption{dialOpt},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pool.Close() })

	hostClient, err := pool.Host("agent-a", addr)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = hostClient.Health(ctx, &sandboxdv1.HealthRequest{})
	require.Error(t, err)

	// The agent rejects the client certificate during the handshake, so the
	// client sees a generic transport failure rather than a TLS alert —
	// under TLS 1.3 the client finishes its side before the server validates
	// the certificate. What matters, and what this asserts, is that the
	// request never reached the service.
	assert.Zero(t, agent.servedCount(),
		"a request bearing an agent leaf as its client certificate must never reach the service")
}

func TestPool_HealthCache_TransitionsToUnreachableWithinOneInterval(t *testing.T) {
	fleet := newTestFleet(t)
	agent := newFakeAgent()
	addr, dialOpt, server := serveAgent(t, fleet.ca, "agent-a", agent)

	certPEM, keyPEM := fleet.controlCert()
	pool, err := client.NewPool(client.Config{
		CACertPEM:      fleet.ca.CertPEM(),
		CertPEM:        certPEM,
		KeyPEM:         keyPEM,
		DialOptions:    []grpc.DialOption{dialOpt},
		HealthInterval: 50 * time.Millisecond,
		HealthTimeout:  40 * time.Millisecond,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pool.Close() })

	_, err = pool.Host("agent-a", addr)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		status, ok := pool.Health("agent-a")
		return ok && status.Reachable
	}, time.Second, 5*time.Millisecond, "health cache must report reachable once the agent has been probed")

	server.Stop()

	require.Eventually(t, func() bool {
		status, ok := pool.Health("agent-a")
		return ok && !status.Reachable
	}, 500*time.Millisecond, 5*time.Millisecond, "health cache must reflect unreachable within roughly one probe interval")
}

func TestPool_Close_RejectsFurtherConn(t *testing.T) {
	fleet := newTestFleet(t)
	agent := newFakeAgent()
	addr, dialOpt, _ := serveAgent(t, fleet.ca, "agent-a", agent)

	pool := newTestPool(t, fleet, dialOpt)

	_, err := pool.Conn("agent-a", addr)
	require.NoError(t, err)

	require.NoError(t, pool.Close())

	_, err = pool.Conn("agent-a", addr)
	require.Error(t, err)
}
