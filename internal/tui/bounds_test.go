package tui

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/client"
	"github.com/axelmierczuk/fleet-mcp/internal/registry"
)

// What one keystroke turns into on the wire, and how long it is allowed to
// take.
//
// Everything here was previously asserted one step short of the thing that
// matters: that boundFollow returns a minute rather than that the request
// carries one, that a stop is "graceful" to the Source rather than that the
// agent is told to stop and stay stopped, that the timeout is a sensible
// number rather than that any call is under it. Deleting every
// context.WithTimeout in source.go, or the follow bound, or the flags a stop
// is made of, left this package green.

// ------------------------------------------------------------- fake fleet

// recordedCall is what one agent call looked like from the far side.
//
// The context is read here rather than kept, because a context outlives the
// call that carried it: source.go cancels each one on the way out, so a
// recorded context would report Canceled for every call by the time a test
// looked at it.
type recordedCall struct {
	method      string
	deadline    time.Time
	hadDeadline bool
	ctxErr      error
	req         any
}

// fakeAgent is a ProcessServiceClient and a HostServiceClient that records the
// context and the request it was called with, and answers with nothing.
type fakeAgent struct {
	calls []recordedCall
	err   error
	// stream is what GetProcessLogs hands back. Nil means an empty one.
	stream *fakeStream
}

func (f *fakeAgent) record(ctx context.Context, method string, req any) {
	dl, ok := ctx.Deadline()
	f.calls = append(f.calls, recordedCall{
		method: method, deadline: dl, hadDeadline: ok, ctxErr: ctx.Err(), req: req,
	})
}

func (f *fakeAgent) last() recordedCall {
	return f.calls[len(f.calls)-1]
}

func (f *fakeAgent) ListProcesses(ctx context.Context, in *sandboxdv1.ListProcessesRequest, _ ...grpc.CallOption) (*sandboxdv1.ListProcessesResponse, error) {
	f.record(ctx, "ListProcesses", in)
	return &sandboxdv1.ListProcessesResponse{}, f.err
}

func (f *fakeAgent) GetProcessLogs(ctx context.Context, in *sandboxdv1.GetProcessLogsRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[sandboxdv1.GetProcessLogsResponse], error) {
	f.record(ctx, "GetProcessLogs", in)
	if f.err != nil {
		return nil, f.err
	}
	return &fakeLogStream{inner: f.stream}, nil
}

func (f *fakeAgent) SignalProcess(ctx context.Context, in *sandboxdv1.SignalProcessRequest, _ ...grpc.CallOption) (*sandboxdv1.SignalProcessResponse, error) {
	f.record(ctx, "SignalProcess", in)
	return &sandboxdv1.SignalProcessResponse{}, f.err
}

func (f *fakeAgent) RestartProcess(ctx context.Context, in *sandboxdv1.RestartProcessRequest, _ ...grpc.CallOption) (*sandboxdv1.RestartProcessResponse, error) {
	f.record(ctx, "RestartProcess", in)
	return &sandboxdv1.RestartProcessResponse{}, f.err
}

func (f *fakeAgent) StartProcess(ctx context.Context, in *sandboxdv1.StartProcessRequest, _ ...grpc.CallOption) (*sandboxdv1.StartProcessResponse, error) {
	f.record(ctx, "StartProcess", in)
	return &sandboxdv1.StartProcessResponse{}, f.err
}

func (f *fakeAgent) RemoveProcess(ctx context.Context, in *sandboxdv1.RemoveProcessRequest, _ ...grpc.CallOption) (*sandboxdv1.RemoveProcessResponse, error) {
	f.record(ctx, "RemoveProcess", in)
	return &sandboxdv1.RemoveProcessResponse{}, f.err
}

func (f *fakeAgent) GetHostInfo(ctx context.Context, in *sandboxdv1.GetHostInfoRequest, _ ...grpc.CallOption) (*sandboxdv1.GetHostInfoResponse, error) {
	f.record(ctx, "GetHostInfo", in)
	return &sandboxdv1.GetHostInfoResponse{}, f.err
}

func (f *fakeAgent) Health(ctx context.Context, in *sandboxdv1.HealthRequest, _ ...grpc.CallOption) (*sandboxdv1.HealthResponse, error) {
	f.record(ctx, "Health", in)
	return &sandboxdv1.HealthResponse{}, f.err
}

var (
	_ sandboxdv1.ProcessServiceClient = (*fakeAgent)(nil)
	_ sandboxdv1.HostServiceClient    = (*fakeAgent)(nil)
)

// fakeLogStream adapts a scripted fakeStream to the generated streaming
// client, which carries a dozen methods this file has no use for.
type fakeLogStream struct {
	grpc.ServerStreamingClient[sandboxdv1.GetProcessLogsResponse]
	inner *fakeStream
}

func (f *fakeLogStream) Recv() (*sandboxdv1.GetProcessLogsResponse, error) {
	if f.inner == nil {
		return nil, io.EOF
	}
	return f.inner.Recv()
}

// fakePool answers with one agent for every sandbox, and with whatever health
// it was given.
type fakePool struct {
	agent  *fakeAgent
	health map[string]client.HealthStatus
	err    error
	// asked records the sandboxes Health was called for, which is what
	// "Sandboxes issues no RPCs, it reads the cache" is asserted with.
	asked []string
}

func (p *fakePool) Host(string, string) (sandboxdv1.HostServiceClient, error) {
	return p.agent, p.err
}

func (p *fakePool) Process(string, string) (sandboxdv1.ProcessServiceClient, error) {
	return p.agent, p.err
}

func (p *fakePool) Health(name string) (client.HealthStatus, bool) {
	p.asked = append(p.asked, name)
	h, ok := p.health[name]
	return h, ok
}

type fakeFleet struct {
	sandboxes []registry.Sandbox
	err       error
}

func (f *fakeFleet) List() ([]registry.Sandbox, error) { return f.sandboxes, f.err }

var (
	_ agentClients = (*fakePool)(nil)
	_ fleetLister  = (*fakeFleet)(nil)
)

func testSource(pool *fakePool, fleet *fakeFleet) *fleetSource {
	return &fleetSource{fleet: fleet, pool: pool, timeout: defaultCallTimeout}
}

// ------------------------------------------------------------- deadlines

// TestEveryCallToOneSandboxIsBounded.
//
// "One unreachable sandbox does not stall or blank the view" is an acceptance
// criterion, and it rests entirely on these deadlines: a pool call returns a
// client without touching the network, so the only thing between a pane and a
// TCP connect to a black hole is the context the RPC is issued under.
//
// The bounds are checked as a range rather than as an equality. Each is a sum
// of a call timeout and whatever the agent is allowed to spend before it can
// answer — a grace period for a stop, a follow window for a log — so what
// matters is that one exists and that it clears the far side's own bound
// rather than expiring first and reporting a timeout for a call that worked.
func TestEveryCallToOneSandboxIsBounded(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		call   func(*fleetSource, context.Context) error
		method string
		// atLeast is what the agent may spend before it can answer at all.
		atLeast time.Duration
		atMost  time.Duration
	}{
		{
			name: "processes",
			call: func(s *fleetSource, ctx context.Context) error {
				_, err := s.Processes(ctx, "alpha", "10.0.0.11:9443")
				return err
			},
			method: "ListProcesses", atLeast: 0, atMost: defaultCallTimeout,
		},
		{
			name: "detail",
			call: func(s *fleetSource, ctx context.Context) error {
				_, err := s.Detail(ctx, "alpha", "10.0.0.11:9443", false)
				return err
			},
			method: "GetHostInfo", atLeast: 0, atMost: defaultCallTimeout,
		},
		{
			name: "logs",
			call: func(s *fleetSource, ctx context.Context) error {
				_, err := s.Logs(ctx, "alpha", "10.0.0.11:9443", "p-web", LogOptions{FollowFor: 2 * time.Second, TailLines: 10})
				return err
			},
			// Later than the follow the agent was asked for: the agent's own
			// deadline ends the stream with a summary, ours would end it with
			// a timeout and no logs at all.
			method: "GetProcessLogs", atLeast: 2 * time.Second, atMost: 2*time.Second + defaultCallTimeout,
		},
		{
			name: "signal",
			call: func(s *fleetSource, ctx context.Context) error {
				return s.Signal(ctx, "alpha", "10.0.0.11:9443", "p-web", "KILL", false)
			},
			method: "SignalProcess", atLeast: 0, atMost: defaultCallTimeout,
		},
		{
			name: "graceful stop",
			call: func(s *fleetSource, ctx context.Context) error {
				return s.Signal(ctx, "alpha", "10.0.0.11:9443", "p-web", "TERM", true)
			},
			// A graceful stop blocks on the agent for the whole grace period
			// before it answers, so a deadline shorter than that would report
			// a timeout for a stop that was working.
			method: "SignalProcess", atLeast: gracePeriod, atMost: gracePeriod + defaultCallTimeout,
		},
		{
			name: "restart",
			call: func(s *fleetSource, ctx context.Context) error {
				return s.Restart(ctx, "alpha", "10.0.0.11:9443", "p-web")
			},
			method: "RestartProcess", atLeast: gracePeriod, atMost: gracePeriod + defaultCallTimeout,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			agent := &fakeAgent{}
			src := testSource(&fakePool{agent: agent}, &fakeFleet{})

			before := time.Now()
			require.NoError(t, tc.call(src, context.Background()))
			require.Len(t, agent.calls, 1)

			got := agent.last()
			require.Equal(t, tc.method, got.method)
			require.Truef(t, got.hadDeadline,
				"%s was issued with no deadline: one unreachable sandbox stalls the pane", tc.method)
			left := got.deadline.Sub(before)
			require.Greaterf(t, left, tc.atLeast,
				"%s would give up before the agent can answer", tc.method)
			require.LessOrEqualf(t, left, tc.atMost+time.Second,
				"%s is bounded by %s, which is not a per-sandbox deadline", tc.method, left)
		})
	}
}

// TestACancelledRunCancelsWhatIsInFlight. The deadline is the far side's
// budget; this is the near side leaving.
func TestACancelledRunCancelsWhatIsInFlight(t *testing.T) {
	t.Parallel()

	agent := &fakeAgent{}
	src := testSource(&fakePool{agent: agent}, &fakeFleet{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := src.Processes(ctx, "alpha", "10.0.0.11:9443")
	require.NoError(t, err, "the fake answers regardless; what is under test is the context it was handed")
	require.ErrorIs(t, agent.last().ctxErr, context.Canceled,
		"the call was issued under a fresh context, so a shutdown cannot stop it")
}

// ------------------------------------------------------------ log windows

// TestTheFollowBoundReachesTheRequest.
//
// boundFollow returning a minute is not the acceptance criterion. The
// criterion is that the request the agent receives carries a finite follow,
// whatever the schedule asked for — and the two are different assertions:
// leaving the bound out of the request left every test in this tree green.
func TestTheFollowBoundReachesTheRequest(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		opts LogOptions
		want time.Duration
	}{
		{"a window inside the bound", LogOptions{FollowFor: 2 * time.Second}, 2 * time.Second},
		{"a window past it", LogOptions{FollowFor: time.Hour}, maxFollow},
		{"no follow at all", LogOptions{}, 0},
		{"a negative one", LogOptions{FollowFor: -time.Hour}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			agent := &fakeAgent{}
			src := testSource(&fakePool{agent: agent}, &fakeFleet{})

			_, err := src.Logs(context.Background(), "alpha", "10.0.0.11:9443", "p-web", tc.opts)
			require.NoError(t, err)

			req, ok := agent.last().req.(*sandboxdv1.GetProcessLogsRequest)
			require.True(t, ok)
			require.Equal(t, "p-web", req.GetProcessId())
			if tc.want == 0 {
				require.False(t, req.GetFollow(), "a window that follows nothing must not ask to follow")
				return
			}
			require.True(t, req.GetFollow())
			require.NotNil(t, req.GetFollowDuration(), "a follow with no duration is an unbounded stream")
			require.Equal(t, tc.want, req.GetFollowDuration().AsDuration())
		})
	}
}

// TestTheTailIsBoundedToo, so a schedule asking for four million lines of
// history does not become a request for them.
func TestTheTailIsBoundedToo(t *testing.T) {
	t.Parallel()

	agent := &fakeAgent{}
	src := testSource(&fakePool{agent: agent}, &fakeFleet{})

	_, err := src.Logs(context.Background(), "alpha", "10.0.0.11:9443", "p-web",
		LogOptions{TailLines: 1 << 30, FollowFor: time.Second})
	require.NoError(t, err)
	req := agent.last().req.(*sandboxdv1.GetProcessLogsRequest)
	require.LessOrEqual(t, req.GetTailLines(), uint32(1<<20))

	// And a negative one is not sent as four billion.
	_, err = src.Logs(context.Background(), "alpha", "10.0.0.11:9443", "p-web",
		LogOptions{TailLines: -1, FollowFor: time.Second})
	require.NoError(t, err)
	req = agent.last().req.(*sandboxdv1.GetProcessLogsRequest)
	require.Equal(t, uint32(0), req.GetTailLines())
}

// ------------------------------------------------------- mutating actions

// TestAStopIsAStop.
//
// The confirmation prompt says "SIGTERM, then SIGKILL after 10s", and that
// sentence is a promise about three fields of one request. It is also the only
// place in the program that sets disable_restart, which is the difference
// between stopping a dev server and watching the supervisor put it back.
func TestAStopIsAStop(t *testing.T) {
	t.Parallel()

	agent := &fakeAgent{}
	src := testSource(&fakePool{agent: agent}, &fakeFleet{})

	require.NoError(t, src.Signal(context.Background(), "alpha", "10.0.0.11:9443", "p-web", "TERM", true))
	req := agent.last().req.(*sandboxdv1.SignalProcessRequest)
	require.Equal(t, "p-web", req.GetProcessId())
	require.True(t, req.GetGracefulStop(), "the stop key sent a bare signal")
	require.Equal(t, gracePeriod, req.GetGracePeriod().AsDuration(),
		"the grace period on the wire is not the one the prompt named")
	require.True(t, req.GetDisableRestart(),
		"an operator's stop must not be undone by the restart policy a second later")
}

// TestAnExplicitSignalIsOnlyThatSignal. The picker sends what it named, and
// none of the graceful stop's extras: SIGUSR1 is a message to a process, not a
// request to stop it and keep it stopped.
func TestAnExplicitSignalIsOnlyThatSignal(t *testing.T) {
	t.Parallel()

	for name, want := range map[string]sandboxdv1.SignalProcessRequest_Signal{
		"TERM": sandboxdv1.SignalProcessRequest_SIGNAL_TERM,
		"KILL": sandboxdv1.SignalProcessRequest_SIGNAL_KILL,
		"INT":  sandboxdv1.SignalProcessRequest_SIGNAL_INT,
		"HUP":  sandboxdv1.SignalProcessRequest_SIGNAL_HUP,
		"USR1": sandboxdv1.SignalProcessRequest_SIGNAL_USR1,
		"USR2": sandboxdv1.SignalProcessRequest_SIGNAL_USR2,
	} {
		agent := &fakeAgent{}
		src := testSource(&fakePool{agent: agent}, &fakeFleet{})

		require.NoError(t, src.Signal(context.Background(), "alpha", "10.0.0.11:9443", "p-web", name, false))
		req := agent.last().req.(*sandboxdv1.SignalProcessRequest)
		require.Equalf(t, want, req.GetSignal(), "SIG%s", name)
		require.Falsef(t, req.GetGracefulStop(), "SIG%s became a graceful stop", name)
		require.Falsef(t, req.GetDisableRestart(), "SIG%s suppressed the restart policy", name)
	}

	// A signal the wire does not have never reaches it.
	agent := &fakeAgent{}
	src := testSource(&fakePool{agent: agent}, &fakeFleet{})
	require.Error(t, src.Signal(context.Background(), "alpha", "10.0.0.11:9443", "p-web", "QUIT", false))
	require.Empty(t, agent.calls, "an unknown signal was sent and left for the agent to reject")
}

// TestARestartCarriesTheGracePeriodAndDoesNotBlockOnReadiness. A restart that
// waited for a readiness probe would hold the pane while a dev server took its
// eight seconds to bind.
func TestARestartCarriesTheGracePeriodAndDoesNotBlockOnReadiness(t *testing.T) {
	t.Parallel()

	agent := &fakeAgent{}
	src := testSource(&fakePool{agent: agent}, &fakeFleet{})

	require.NoError(t, src.Restart(context.Background(), "alpha", "10.0.0.11:9443", "p-web"))
	req := agent.last().req.(*sandboxdv1.RestartProcessRequest)
	require.Equal(t, "p-web", req.GetProcessId())
	require.Equal(t, gracePeriod, req.GetGracePeriod().AsDuration())
	require.False(t, req.GetWaitForReady())
}

// ----------------------------------------------------------- the listing

// TestSandboxesReadsTheCacheAndIssuesNoRPCs.
//
// Both halves matter and neither was covered by anything cheaper than a
// seventy-second end-to-end run. Health comes from the pool's background loop,
// which is the only thing in this program that probes on a schedule; a listing
// that probed for itself would be one round trip per sandbox every two
// seconds, which is what makes a large fleet unwatchable.
func TestSandboxesReadsTheCacheAndIssuesNoRPCs(t *testing.T) {
	t.Parallel()

	agent := &fakeAgent{}
	pool := &fakePool{agent: agent, health: map[string]client.HealthStatus{
		"alpha": {Reachable: true, Status: sandboxdv1.HealthResponse_STATUS_SERVING, CheckedAt: time.Now(), AgentVersion: "v0.4.1"},
		"gamma": {CheckedAt: time.Now(), Err: status.Error(codes.Unavailable, "connection refused")},
	}}
	src := testSource(pool, &fakeFleet{sandboxes: []registry.Sandbox{
		{Name: "alpha", Address: "10.0.0.11:9443", AgentVersion: "stale"},
		{Name: "gamma", Address: "10.0.0.13:9443"},
		{Name: "delta", Address: "10.0.0.14:9443"},
	}})

	rows, err := src.Sandboxes(context.Background())
	require.NoError(t, err)
	require.Len(t, rows, 3)

	require.Equal(t, client.HealthServing, rows[0].Health)
	require.Equal(t, "v0.4.1", rows[0].Agent, "the live probe's agent version did not replace the registry's")
	require.Equal(t, client.HealthUnreachable, rows[1].Health, "a probe that looked and found nothing is not reported as unreachable")
	require.Equal(t, "no answer within the timeout", rows[1].Detail)
	require.Equal(t, client.HealthUnknown, rows[2].Health, "a sandbox nothing has probed yet must read unknown, not unreachable")

	require.Equal(t, []string{"alpha", "gamma", "delta"}, pool.asked,
		"the listing did not read the health cache for every sandbox")
	require.Empty(t, agent.calls, "the listing issued an RPC; health is the pool's background loop's job")
}

// TestAMalformedAddressIsAFactAboutOneSandbox, not a failure of the listing.
func TestAMalformedAddressIsAFactAboutOneSandbox(t *testing.T) {
	t.Parallel()

	src := testSource(&fakePool{agent: &fakeAgent{}, err: errors.New("client: sandbox bad has address \"nope\", which is not host:port")},
		&fakeFleet{sandboxes: []registry.Sandbox{{Name: "bad", Address: "nope"}}})

	rows, err := src.Sandboxes(context.Background())
	require.NoError(t, err, "one unusable address failed the whole listing")
	require.Len(t, rows, 1)
	require.Equal(t, client.HealthUnreachable, rows[0].Health)
	require.Contains(t, rows[0].Detail, "not host:port")
}

// ------------------------------------------------- the registry the CLI reads

// TestTheSourceReadsTheRegistryTheCLIReads, through the same package and the
// same file, so `fleetctl list` and the fleet pane cannot hold different
// fleets.
func TestTheSourceReadsTheRegistryTheCLIReads(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "registry.yaml")
	fleet, err := registry.Open(path)
	require.NoError(t, err)
	require.NoError(t, fleet.Add(registry.Sandbox{
		Name: "alpha", Address: "10.0.0.11:9443",
		Platform: registry.Platform{OS: "linux", Arch: "amd64"}, EnrolledAt: time.Now(),
	}))

	pool := &fakePool{agent: &fakeAgent{}}
	src := &fleetSource{fleet: fleet, pool: pool, timeout: defaultCallTimeout}
	rows, err := src.Sandboxes(context.Background())
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, "alpha", rows[0].Name)
	require.Equal(t, "linux/amd64", rows[0].Platform)

	_, err = os.Stat(path)
	require.NoError(t, err)
}

// TestProjectedProcessesCarryTheDetailThePaneDraws, from a wire status through
// the shared vocabulary to the row.
func TestProjectedProcessesCarryTheDetailThePaneDraws(t *testing.T) {
	t.Parallel()

	now := time.Now()
	agent := &fakeAgent{}
	agent.err = nil
	src := testSource(&fakePool{agent: agent}, &fakeFleet{})
	_, err := src.Processes(context.Background(), "alpha", "10.0.0.11:9443")
	require.NoError(t, err)

	p := projectProcess(&sandboxdv1.ProcessStatus{
		ProcessId: "p-web", Name: "web-dev-server", Pid: 4211,
		State:          sandboxdv1.ProcessState_PROCESS_STATE_READY,
		StartedAt:      timestamppb.New(now.Add(-90 * time.Second)),
		ListeningPorts: []uint32{8443, 8080},
	}, now)
	require.Equal(t, []uint32{8080, 8443}, p.Ports, "ports are shown in the order the agent happened to list them")
	require.Equal(t, "1m30s", p.Uptime)
}
