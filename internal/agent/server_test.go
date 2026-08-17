package agent_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	"github.com/axelmierczuk/fleet-mcp/internal/security/jail"
)

// Services registered through the seam are constructed once, before the
// listener opens, and get a fully populated Deps.
func TestServer_ServiceRegistrationSeam(t *testing.T) {
	fleet := newTestFleet(t)
	root := t.TempDir()
	// Exec disabled, so the jail assertions below are about a jail that is
	// actually in force; see TestServer_ExecEnabledDisablesTheJail.
	cfg := fleet.jailedConfig(t, root)

	var got agent.Deps
	var built atomic.Int64
	svc := newCountingService()

	h := start(t, cfg, []agent.Registration{{
		Name: "host",
		Factory: func(d agent.Deps) (agent.Service, error) {
			built.Add(1)
			got = d
			return svc, nil
		},
	}})

	assert.EqualValues(t, 1, built.Load(), "a factory runs exactly once per daemon")
	assert.Same(t, cfg, got.Config)
	assert.NotNil(t, got.Log)
	assert.NotNil(t, got.Status)
	assert.NotNil(t, got.Jail)
	assert.Equal(t, "0.0.0-test", got.Version)
	assert.False(t, got.StartedAt.IsZero())
	assert.True(t, got.Jail.Confined())
	assert.Equal(t, []string{resolved(t, root)}, got.Jail.Roots())
	assert.Equal(t, []string{"host"}, h.server.ServiceNames())
}

// Exec and the jail are mutually exclusive.
//
// A caller with ExecService never has to go through FileService to reach a
// path — argv ["sh","-c","echo x > /etc/passwd"] needs no shell flag and no
// write RPC — so on an exec-enabled agent the configured roots confine nothing.
// They are ignored rather than half-enforced, because a control that stops
// honest mistakes and not dishonest ones, while looking like a security
// control, is what operators plan around.
func TestServer_ExecEnabledDisablesTheJail(t *testing.T) {
	fleet := newTestFleet(t)
	root := t.TempDir()

	log, logs := capturedLogger()
	h := start(t, fleet.agentConfig(t, root), []agent.Registration{registration("host", newCountingService())},
		func(o *agent.Options) { o.Log = log })

	j := h.server.Deps().Jail
	assert.False(t, j.Confined(), "exec is enabled, so there is no jail")
	assert.Empty(t, j.Roots(),
		"an agent whose jail is off must report no roots: this is what fleet_select tells the model it may write to")

	// Resolution still works — services call Resolve unconditionally — it just
	// permits everything. An unconfined jail normalises rather than resolves:
	// there is no containment decision to make, so there is nothing symlink
	// resolution would be protecting.
	outside := filepath.Join(t.TempDir(), "elsewhere")
	got, err := j.Resolve(outside)
	require.NoError(t, err)
	assert.Equal(t, filepath.Clean(outside), got)
	assert.False(t, j.Atomic(), "an unconfined jail has no containment to make atomic")

	// And it is never silent: configured roots that are being ignored are said
	// out loud, with the reason, at every start.
	logged := logs.String()
	assert.Contains(t, logged, "ALLOWED_ROOTS ARE IGNORED")
	assert.Contains(t, logged, "level=WARN")
	assert.Contains(t, logged, "sh")
	assert.Contains(t, logged, "exec.enabled: false")
}

// With exec disabled the roots are a real boundary, and are enforced.
func TestServer_ExecDisabledEnforcesTheJail(t *testing.T) {
	fleet := newTestFleet(t)
	root := t.TempDir()

	h := start(t, fleet.jailedConfig(t, root), []agent.Registration{registration("host", newCountingService())})

	j := h.server.Deps().Jail
	require.True(t, j.Confined())
	assert.Equal(t, []string{resolved(t, root)}, j.Roots())

	_, err := j.Resolve(filepath.Join(t.TempDir(), "elsewhere"))
	require.ErrorIs(t, err, jail.ErrOutsideJail)
}

// A root that does not exist is a startup failure, not a jail that quietly
// confines to nothing.
//
// internal/security/jail refuses it at construction rather than tolerating it,
// and the reason is worth keeping asserted: a path that is missing now can be
// created later — as a symlink to anywhere — and a jail that had accepted it
// would then confine to whatever it pointed at. The provisional jail this
// replaced kept such a root, resolved through its nearest existing ancestor.
// The daemon's error has to name both the root and the way out.
func TestServer_MissingAllowedRootRefusesStartup(t *testing.T) {
	fleet := newTestFleet(t)
	missing := filepath.Join(t.TempDir(), "not-created-yet")

	_, err := agent.New(agent.Options{
		Config:   fleet.jailedConfig(t, missing),
		Log:      discardLogger(),
		Version:  "0.0.0-test",
		Services: []agent.Registration{registration("host", newCountingService())},
		Listener: newBufconn(t),
	})
	require.Error(t, err, "an allowed root that does not exist must not become a jail")
	assert.Contains(t, err.Error(), missing)
	assert.Contains(t, err.Error(), "must already exist")
}

// The same config with exec enabled starts, because there is no jail to build.
//
// This is the decision itself, asserted through the swap: with exec on the
// roots are not merely unenforced, they are never handed to the jail at all —
// so a root that would have failed construction cannot fail startup either.
func TestServer_MissingAllowedRootIsIrrelevantWhenExecIsEnabled(t *testing.T) {
	fleet := newTestFleet(t)
	missing := filepath.Join(t.TempDir(), "not-created-yet")

	log, logs := capturedLogger()
	h := start(t, fleet.agentConfig(t, missing), []agent.Registration{registration("host", newCountingService())},
		func(o *agent.Options) { o.Log = log })

	assert.False(t, h.server.Deps().Jail.Confined())
	assert.Empty(t, h.server.Deps().Jail.Roots())
	assert.Contains(t, logs.String(), "ALLOWED_ROOTS ARE IGNORED")
}

// An exec-disabled agent with no roots is the --no-jail case, and it says so.
func TestServer_ExecDisabledWithNoRootsWarns(t *testing.T) {
	fleet := newTestFleet(t)

	log, logs := capturedLogger()
	start(t, fleet.jailedConfig(t), []agent.Registration{registration("host", newCountingService())},
		func(o *agent.Options) { o.Log = log })

	assert.Contains(t, logs.String(), "STARTING WITHOUT A PATH JAIL")
	assert.Contains(t, logs.String(), "level=WARN")
}

// A factory that fails takes the daemon down with it, rather than leaving a
// server listening with one service silently missing.
func TestServer_FactoryErrorAbortsStartup(t *testing.T) {
	fleet := newTestFleet(t)
	_, err := agent.New(agent.Options{
		Config:  fleet.agentConfig(t),
		Log:     discardLogger(),
		Version: "0.0.0-test",
		Services: []agent.Registration{{
			Name:    "broken",
			Factory: func(agent.Deps) (agent.Service, error) { return nil, errors.New("no state directory") },
		}},
		Listener: newBufconn(t),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "broken")
	assert.Contains(t, err.Error(), "no state directory")
}

// rpcResult is what an in-flight call came back with, recorded at the moment
// it came back.
//
// The fields are exported for one reason, and it is not style. #59 reported
// this test's failure as `{resp:<nil> err:0xc000010100}` and the investigation
// stopped there for want of the error. That was fmt, not brevity: %+v walks a
// struct with reflection, reflect refuses to hand out an interface for an
// unexported field, and so fmt never gets to call Error() and prints the
// pointer instead. A struct with unexported fields cannot report an error it
// holds, however it is formatted.
type rpcResult struct {
	Resp *sandboxdv1.HealthResponse
	Err  error
	// CtxErr is the caller's own context at the moment the call returned. It
	// is what separates "the server cut this RPC" from "the client gave up on
	// it", which is the question #59 could not answer.
	CtxErr error
	// Elapsed is reported, never asserted on. A call cut at the shutdown
	// signal and a call that ran out its own 20s deadline are different
	// failures, and this is what tells them apart in the log.
	Elapsed time.Duration
}

// String spells out the gRPC status, because the code is the fact that
// separates the two hypotheses on #59: Unavailable or a transport close is the
// daemon cutting the call, DeadlineExceeded or Canceled is the caller or the
// test giving up on it.
func (r rpcResult) String() string {
	var what string
	switch st, ok := status.FromError(r.Err); {
	case r.Err == nil:
		what = fmt.Sprintf("no error, status %v", r.Resp.GetStatus())
	case ok:
		what = fmt.Sprintf("gRPC %s: %q", st.Code(), st.Message())
	default:
		what = fmt.Sprintf("non-status error: %v", r.Err)
	}
	return fmt.Sprintf("%s; caller context: %v; %s after the call started",
		what, r.CtxErr, r.Elapsed.Round(time.Millisecond))
}

// The shutdown contract: an RPC already running when the daemon is signalled
// gets to finish, and its result reaches the caller.
//
// The ordering this needs used to be established with a fixed 100ms sleep and
// then sampled once, which is the shape #59 suspects. Two things replace it.
// The daemon's listener refusing a dial is a recorded fact that the drain has
// started, so nothing has to be timed. And the handler records its own stream
// context being cancelled, which is how gRPC cuts an in-flight RPC — a fact
// written on the server at the moment it happens, covering the whole time the
// handler is in the call rather than one sampled instant.
//
// The client-side sample is kept as well, because that is the assertion #59
// tripped, and a run that trips it now says what the RPC actually came back
// with and what the daemon was doing at the time.
func TestServer_ShutdownDrainsInFlightRPCs(t *testing.T) {
	fleet := newTestFleet(t)
	svc := newCountingService()
	svc.block = make(chan struct{})

	// The daemon's own log, kept so that a failure here can say what the
	// shutdown path thought it was doing — whether it logged "drained" while
	// a handler was still inside a call, or hit its drain deadline and
	// cancelled. Neither is visible from the client side alone.
	log, serverLog := capturedLogger()
	h := start(t, fleet.agentConfig(t), []agent.Registration{registration("host", svc)},
		func(o *agent.Options) { o.Log = log })

	certPEM, keyPEM := fleet.controlLeaf()
	hostClient := h.hostClient(t, fleet.ca.CertPEM(), certPEM, keyPEM)

	results := make(chan rpcResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		started := time.Now()
		// Marked, so the handler holds this call and not the pool's background
		// health probe; see holdHeader.
		resp, err := hostClient.Health(hold(ctx), &sandboxdv1.HealthRequest{})
		results <- rpcResult{Resp: resp, Err: err, CtxErr: ctx.Err(), Elapsed: time.Since(started)}
	}()

	// Wait until the handler is genuinely inside *this* call, so the shutdown
	// that follows is racing a real in-flight RPC rather than an idle server.
	//
	// "This call" is the part #59 turned on: only a marked call closes
	// entered, and the marker is on the call above and nowhere else. A future
	// edit that drops it does not quietly weaken this into "some call entered"
	// — nothing closes entered at all and the wait below fails outright.
	select {
	case <-svc.entered:
	case <-time.After(10 * time.Second):
		t.Fatalf("handler never entered; daemon log:\n%s", serverLog)
	}

	// Signal shutdown while the call is still running, and wait for the
	// daemon to prove it started: GracefulStop closes the listener before it
	// waits on any handler. Only this test can release the handler, so a
	// refused dial here means the drain is under way with an RPC still in it.
	h.cancel()
	h.awaitNotAccepting(t, serverLog)

	// Nothing has come back yet: the drain is waiting on the handler. This is
	// the client's side of the contract, and the assertion #59 tripped.
	select {
	case r := <-results:
		t.Fatalf("an RPC already in flight came back while its handler was still running: %s\ndaemon log:\n%s",
			r, serverLog)
	default:
	}

	close(svc.block)

	select {
	case r := <-results:
		// The server's side, and the one that cannot be raced: gRPC cancels a
		// handler's context when it drops the stream, so an empty record here
		// means nothing cut this RPC at any point between the shutdown signal
		// and the handler being released.
		require.Empty(t, svc.wasCut(),
			"the shutdown cancelled an in-flight handler instead of waiting for it; the call saw %s\ndaemon log:\n%s",
			r, serverLog)
		require.NoError(t, r.Err,
			"an RPC already in flight must complete rather than being cut off: %s\nhandlers entered: %d\ndaemon log:\n%s",
			r, svc.servedCount(), serverLog)
		assert.Equal(t, sandboxdv1.HealthResponse_STATUS_SERVING, r.Resp.GetStatus())
	case <-time.After(10 * time.Second):
		t.Fatalf("in-flight RPC never returned; daemon log:\n%s", serverLog)
	}

	require.NoError(t, h.wait(t))
}

// A handler that will never return must not stop the daemon exiting. The drain
// is bounded, and the bound is enforced.
func TestServer_ShutdownCutsOffAtTheDrainDeadline(t *testing.T) {
	fleet := newTestFleet(t)
	svc := newCountingService()
	svc.block = make(chan struct{})
	t.Cleanup(func() { close(svc.block) })

	h := start(t, fleet.agentConfig(t), []agent.Registration{registration("host", svc)},
		func(o *agent.Options) { o.DrainTimeout = 300 * time.Millisecond })

	certPEM, keyPEM := fleet.controlLeaf()
	hostClient := h.hostClient(t, fleet.ca.CertPEM(), certPEM, keyPEM)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, _ = hostClient.Health(hold(ctx), &sandboxdv1.HealthRequest{})
	}()

	select {
	case <-svc.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("handler never entered")
	}

	start := time.Now()
	require.NoError(t, h.stop(t))
	assert.Less(t, time.Since(start), 8*time.Second,
		"shutdown must be bounded by the drain deadline, not by the stuck handler")
}

// Health reports DRAINING once shutdown has begun, so a control plane polling
// the fleet sees an agent going away rather than guessing from a dropped
// connection.
func TestServer_StatusBecomesDrainingOnShutdown(t *testing.T) {
	fleet := newTestFleet(t)
	svc := newCountingService()
	h := start(t, fleet.agentConfig(t), []agent.Registration{registration("host", svc)})

	state, _, _ := h.status.Snapshot()
	require.Equal(t, sandboxdv1.HealthResponse_STATUS_SERVING, state)

	require.NoError(t, h.stop(t))

	state, message, _ := h.status.Snapshot()
	assert.Equal(t, sandboxdv1.HealthResponse_STATUS_DRAINING, state)
	assert.NotEmpty(t, message)
}

// shutdownRecorder is a Service that records whether its Shutdown hook ran and
// what the deadline on its context was.
type shutdownRecorder struct {
	countingService
	ran         atomic.Bool
	hadDeadline atomic.Bool
}

func (s *shutdownRecorder) Shutdown(ctx context.Context) error {
	s.ran.Store(true)
	_, ok := ctx.Deadline()
	s.hadDeadline.Store(ok)
	return nil
}

// A Shutdowner runs after the drain, with a deadline.
func TestServer_ShutdownParticipantsRun(t *testing.T) {
	fleet := newTestFleet(t)
	rec := &shutdownRecorder{countingService: *newCountingService()}
	h := start(t, fleet.agentConfig(t), []agent.Registration{registration("host", rec)})

	require.NoError(t, h.stop(t))
	assert.True(t, rec.ran.Load(), "a Service implementing Shutdowner must have its hook run")
	assert.True(t, rec.hadDeadline.Load(), "the shutdown context must carry a deadline")
}

// A Shutdowner that fails is logged and does not stop the daemon exiting or
// prevent later participants from running.
func TestServer_ShutdownParticipantErrorDoesNotBlockExit(t *testing.T) {
	fleet := newTestFleet(t)
	second := &shutdownRecorder{countingService: *newCountingService()}
	h := start(t, fleet.agentConfig(t), []agent.Registration{
		registration("a-failing", &failingShutdowner{}),
		registration("b-recorder", second),
	})

	require.NoError(t, h.stop(t))
	assert.True(t, second.ran.Load(), "a failing participant must not stop the ones after it")
}

// A daemon whose accept loop dies on its own still runs its shutdown
// participants.
//
// The listener can go away without anyone cancelling the context: a socket
// closed from outside, or an accept failure gRPC judges permanent. Returning
// straight out of Serve there would skip every Shutdowner — and the supervisor's
// Shutdown is what persists the process records that let #11 re-adopt its
// children after a restart. Losing them because a socket died is a worse
// outcome than the dead socket.
func TestServer_AcceptLoopFailureStillRunsShutdowners(t *testing.T) {
	fleet := newTestFleet(t)
	rec := &shutdownRecorder{countingService: *newCountingService()}

	lis := bufconn.Listen(1024 * 1024)
	srv, err := agent.New(agent.Options{
		Config:   fleet.agentConfig(t),
		Log:      discardLogger(),
		Version:  "0.0.0-test",
		Services: []agent.Registration{registration("host", rec)},
		Listener: lis,
	})
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background()) }()

	// Kill the listener out from under the accept loop. Whether Serve got as
	// far as Accept first does not matter: either way the accept fails and
	// gRPC returns the error.
	require.NoError(t, lis.Close())

	select {
	case err := <-done:
		require.Error(t, err, "a dead accept loop is reported, not swallowed")
	case <-time.After(20 * time.Second):
		t.Fatal("Serve did not return after its listener was closed")
	}
	assert.True(t, rec.ran.Load(),
		"a Shutdowner must run even when the daemon is stopping because its listener died")
	state, _, _ := srv.Deps().Status.Snapshot()
	assert.Equal(t, sandboxdv1.HealthResponse_STATUS_DRAINING, state)
}

// failingShutdowner registers no gRPC handlers — only one service in a daemon
// may claim HostService — so this exercises the shutdown ordering alone.
type failingShutdowner struct{}

func (f *failingShutdowner) Register(grpc.ServiceRegistrar) {}
func (f *failingShutdowner) Shutdown(context.Context) error { return errors.New("could not flush") }

// The property the whole shutdown design exists for: a background process the
// daemon started outlives the daemon.
//
// The daemon must never signal a supervised child, and — on Unix — must not
// let its own termination reach one through a shared process group. This
// spawns a real child, shuts the daemon down, and asserts the child is still
// alive afterwards.
func TestServer_ShutdownDoesNotKillBackgroundProcesses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX sleep and signal 0 to probe liveness")
	}

	fleet := newTestFleet(t)
	spawner := &processSpawner{countingService: *newCountingService()}
	h := start(t, fleet.agentConfig(t), []agent.Registration{registration("host", spawner)})

	require.NoError(t, spawner.spawn(t))
	t.Cleanup(func() { _ = spawner.cmd.Process.Kill() })

	require.NoError(t, h.stop(t))

	// Signal 0 checks for existence without delivering anything.
	require.NoError(t, spawner.cmd.Process.Signal(syscallZero),
		"a supervised background process must survive the daemon's shutdown")
}

// processSpawner stands in for the supervisor: it owns a child process and,
// like the real one, flushes state on shutdown without touching it.
type processSpawner struct {
	countingService
	cmd *exec.Cmd
}

func (p *processSpawner) spawn(t *testing.T) error {
	t.Helper()
	p.cmd = exec.Command("sleep", "60")
	return p.cmd.Start()
}

func (p *processSpawner) Shutdown(context.Context) error {
	// Deliberately empty. This is the contract: persist records, never signal.
	return nil
}

// The server refuses to start without the pieces it cannot invent.
func TestServer_RequiresConfigAndLogger(t *testing.T) {
	fleet := newTestFleet(t)

	_, err := agent.New(agent.Options{Log: discardLogger()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Config")

	_, err = agent.New(agent.Options{Config: fleet.agentConfig(t)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Log")
}

// A missing certificate is a startup failure, not a daemon that comes up and
// fails every handshake.
func TestServer_MissingCertificateFailsStartup(t *testing.T) {
	fleet := newTestFleet(t)
	cfg := fleet.agentConfig(t)
	cfg.TLS.Certificate = filepath.Join(t.TempDir(), "nope.crt")

	_, err := agent.New(agent.Options{Config: cfg, Log: discardLogger(), Listener: newBufconn(t)})
	require.Error(t, err)
}

// A panic in one handler must not take the daemon down: the supervisor it
// hosts is the only record of the fleet's background processes.
func TestServer_PanickingHandlerDoesNotKillTheDaemon(t *testing.T) {
	fleet := newTestFleet(t)
	svc := &panickingService{}
	h := start(t, fleet.agentConfig(t), []agent.Registration{registration("host", svc)})

	certPEM, keyPEM := fleet.controlLeaf()
	hostClient := h.hostClient(t, fleet.ca.CertPEM(), certPEM, keyPEM)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := hostClient.Health(ctx, &sandboxdv1.HealthRequest{})
	require.Error(t, err)

	// Still serving: a second call gets a real answer.
	resp, err := hostClient.GetHostInfo(ctx, &sandboxdv1.GetHostInfoRequest{})
	require.NoError(t, err)
	assert.Equal(t, "still-here", resp.GetAgentVersion())
}

type panickingService struct {
	sandboxdv1.UnimplementedHostServiceServer
}

func (p *panickingService) Register(r grpc.ServiceRegistrar) {
	sandboxdv1.RegisterHostServiceServer(r, p)
}

func (p *panickingService) Health(context.Context, *sandboxdv1.HealthRequest) (*sandboxdv1.HealthResponse, error) {
	panic("boom")
}

func (p *panickingService) GetHostInfo(context.Context, *sandboxdv1.GetHostInfoRequest) (*sandboxdv1.GetHostInfoResponse, error) {
	return &sandboxdv1.GetHostInfoResponse{AgentVersion: "still-here"}, nil
}

// Register is the package-level seam. It is exercised here rather than through
// a service package so a duplicate registration's panic is asserted directly.
func TestRegister(t *testing.T) {
	name := "test-seam-" + strconv.Itoa(os.Getpid())
	agent.Register(name, func(agent.Deps) (agent.Service, error) { return newCountingService(), nil })

	var found bool
	for _, reg := range agent.Registered() {
		if reg.Name == name {
			found = true
		}
	}
	assert.True(t, found, "Register must make the service visible to Registered")

	assert.Panics(t, func() {
		agent.Register(name, func(agent.Deps) (agent.Service, error) { return newCountingService(), nil })
	}, "registering one name twice is a wiring mistake and must not survive to runtime")

	assert.Panics(t, func() { agent.Register("", nil) })
}

func resolved(t *testing.T, path string) string {
	t.Helper()
	target, err := filepath.EvalSymlinks(path)
	require.NoError(t, err)
	return target
}
