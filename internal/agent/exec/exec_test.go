package exec

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/platform"
	"github.com/axelmierczuk/fleet-mcp/internal/security/policy"
)

// fakeStream records what a handler sent, standing in for the gRPC stream.
//
// It is deliberately a stand-in rather than a real server: every property these
// tests are about — chunking, ordering, the terminal result, what happens when
// the caller goes away — is decided in the handler, and a real server would add
// a listener, a CA and a client to every one of them without changing a single
// assertion. The one thing it cannot cover, the principal coming off a verified
// certificate chain, is covered directly in TestExec_AuditRecordsThePrincipal.
type fakeStream struct {
	grpc.ServerStream

	ctx context.Context

	mu       sync.Mutex
	messages []*sandboxdv1.ExecResponse
	sendErr  error
	// onSend, when set, runs before each Send. A test uses it to cancel the
	// call from inside the stream.
	onSend func(*sandboxdv1.ExecResponse)
	// blockSend, when set, parks every Send until it is closed. This is what a
	// caller that has stopped reading its own stream does to the handler:
	// grpc-go's Send waits for a flow-control window the client is no longer
	// opening.
	blockSend chan struct{}
	// parked, when set, receives every message whose Send parked on blockSend,
	// at the moment it parks. It is the fixture's record of what the caller
	// stopped reading, and the two answers mean opposite things: an output
	// chunk is a copier stuck in Send, which is the one thing os/exec's Wait
	// cannot come back from, while a terminal result means the copiers had
	// already finished and there was never anything to be stuck on. See
	// TestExec_StalledOutputStreamDoesNotWedgeTheHandler.
	parked chan *sandboxdv1.ExecResponse
}

func newFakeStream(ctx context.Context) *fakeStream { return &fakeStream{ctx: ctx} }

func (s *fakeStream) Context() context.Context { return s.ctx }

func (s *fakeStream) Send(msg *sandboxdv1.ExecResponse) error {
	s.mu.Lock()
	hook := s.onSend
	err := s.sendErr
	block := s.blockSend
	parked := s.parked
	s.mu.Unlock()

	if hook != nil {
		hook(msg)
	}
	if block != nil {
		if parked != nil {
			// Non-blocking, so the record can never be what holds a Send that
			// is supposed to be held by the caller. A reader that wants every
			// message rather than the first one sizes the channel for them.
			select {
			case parked <- msg:
			default:
			}
		}
		<-block
	}
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = append(s.messages, msg)
	return nil
}

// output returns everything sent on one stream, concatenated in order.
func (s *fakeStream) output(stream sandboxdv1.Stream) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	for _, msg := range s.messages {
		if chunk := msg.GetOutput(); chunk != nil && chunk.GetStream() == stream {
			b.Write(chunk.GetData())
		}
	}
	return b.String()
}

func (s *fakeStream) chunks() []*sandboxdv1.OutputChunk {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*sandboxdv1.OutputChunk
	for _, msg := range s.messages {
		if chunk := msg.GetOutput(); chunk != nil {
			out = append(out, chunk)
		}
	}
	return out
}

// result returns the terminal ExecResult, or nil when the stream never got one.
func (s *fakeStream) result() *sandboxdv1.ExecResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, msg := range s.messages {
		if res := msg.GetResult(); res != nil {
			return res
		}
	}
	return nil
}

// harness is a Service wired to a temporary audit log.
type harness struct {
	svc       *Service
	audit     *policy.Audit
	auditPath string
	logs      *strings.Builder
}

type harnessOption func(*policy.Config, *policy.AuditConfig)

func withDeny(rules ...string) harnessOption {
	return func(p *policy.Config, _ *policy.AuditConfig) { p.Deny = rules }
}

func withAllow(rules ...string) harnessOption {
	return func(p *policy.Config, _ *policy.AuditConfig) { p.Allow = rules }
}

func withCaps(caps policy.Caps) harnessOption {
	return func(p *policy.Config, _ *policy.AuditConfig) { p.Caps = caps }
}

func withAudit(mutate func(*policy.AuditConfig)) harnessOption {
	return func(_ *policy.Config, a *policy.AuditConfig) { mutate(a) }
}

func newHarness(t *testing.T, opts ...harnessOption) *harness {
	t.Helper()

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	polCfg := policy.Config{Caps: policy.Caps{
		DefaultTimeout: 30 * time.Second,
		MaxTimeout:     5 * time.Minute,
		MaxOutputBytes: 2 * 1024 * 1024,
		MaxConcurrent:  8,
	}}
	auditCfg := policy.AuditConfig{Path: auditPath, Enabled: true, MaxBytes: 1 << 20, RetainSegments: 3}
	for _, opt := range opts {
		opt(&polCfg, &auditCfg)
	}

	pol, err := policy.New(polCfg)
	require.NoError(t, err)

	logs := &strings.Builder{}
	auditLog := policy.NewAudit(auditCfg)
	// Windows will not unlink a file that is still open, and the log holds its
	// handle for the life of the daemon by design — so t.TempDir's cleanup
	// fails there unless the handle goes first. Registered after t.TempDir
	// above, so it runs before it.
	t.Cleanup(func() { _ = auditLog.Close() })
	base := BaseEnv()

	return &harness{
		svc: &Service{
			log:        slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
			policy:     pol,
			audit:      auditLog,
			enabled:    true,
			baseEnv:    base,
			defaultDir: defaultWorkingDir(base),
			// Short, so the escalation is observable inside a test's patience.
			// Nothing here asserts on the duration itself.
			killGrace: 200 * time.Millisecond,
			ioDrain:   500 * time.Millisecond,
		},
		audit:     auditLog,
		auditPath: auditPath,
		logs:      logs,
	}
}

// run executes a request against the harness and returns the stream and the
// RPC error.
func (h *harness) run(t *testing.T, req *sandboxdv1.ExecRequest) (*fakeStream, error) {
	t.Helper()
	return h.runCtx(context.Background(), t, req)
}

func (h *harness) runCtx(ctx context.Context, t *testing.T, req *sandboxdv1.ExecRequest) (*fakeStream, error) {
	t.Helper()
	stream := newFakeStream(ctx)

	done := make(chan error, 1)
	go func() { done <- h.svc.Exec(req, stream) }()

	select {
	case err := <-done:
		return stream, err
	case <-time.After(60 * time.Second):
		t.Fatal("Exec did not return; the handler is wedged")
		return nil, nil
	}
}

// records parses the audit log back, which is also the JSONL assertion: a file
// that does not parse fails every test that reads it.
func (h *harness) records(t *testing.T) []policy.Record {
	t.Helper()
	require.NoError(t, h.audit.Close())
	return parseRecords(t, h.auditPath)
}

func parseRecords(t *testing.T, path string) []policy.Record {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		require.NoError(t, err)
	}
	var out []policy.Record
	for i, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		var rec policy.Record
		require.NoErrorf(t, json.Unmarshal([]byte(line), &rec), "line %d is not valid JSON: %s", i+1, line)
		out = append(out, rec)
	}
	return out
}

// helperReq builds a request that re-runs the test binary in a helper mode.
func helperReq(mode string, args ...string) *sandboxdv1.ExecRequest {
	return &sandboxdv1.ExecRequest{
		Argv: selfArgv(args...),
		Env:  []string{helperEnvFor(mode)},
	}
}

func TestExec_EchoReturnsExitZeroAndItsOutput(t *testing.T) {
	h := newHarness(t)

	stream, err := h.run(t, helperReq("echo", "hello"))
	require.NoError(t, err)

	require.Equal(t, "hello", stream.output(sandboxdv1.Stream_STREAM_STDOUT))
	res := stream.result()
	require.NotNil(t, res, "the stream must end with an ExecResult")
	require.Equal(t, int32(0), res.GetExitCode())
	require.False(t, res.GetTimedOut())
	require.False(t, res.GetSignaled())
	require.False(t, res.GetTruncation().GetTruncated())
	require.Positive(t, res.GetDuration().AsDuration())
}

func TestExec_NonZeroExitIsAResultNotAnError(t *testing.T) {
	h := newHarness(t)

	stream, err := h.run(t, helperReq("exit", "3"))
	require.NoError(t, err, "a command that fails is still a successful RPC")

	res := stream.result()
	require.NotNil(t, res)
	require.Equal(t, int32(3), res.GetExitCode())

	records := h.records(t)
	require.Len(t, records, 1)
	require.Equal(t, policy.OutcomeOK, records[0].Outcome, "a non-zero exit is a recorded outcome, not an audit failure")
	require.NotNil(t, records[0].ExitCode)
	require.Equal(t, int32(3), *records[0].ExitCode)
}

func TestExec_StreamsAreDistinguishableAndOrderedWithinEachStream(t *testing.T) {
	h := newHarness(t)

	stream, err := h.run(t, helperReq("streams"))
	require.NoError(t, err)

	require.Equal(t, "out0\nout1\nout2\n", stream.output(sandboxdv1.Stream_STREAM_STDOUT))
	require.Equal(t, "err0\nerr1\nerr2\n", stream.output(sandboxdv1.Stream_STREAM_STDERR))

	for _, chunk := range stream.chunks() {
		require.NotEqual(t, sandboxdv1.Stream_STREAM_UNSPECIFIED, chunk.GetStream(),
			"every chunk says which stream it came from")
	}
}

func TestExec_StdinIsWrittenThenClosed(t *testing.T) {
	h := newHarness(t)

	req := helperReq("cat")
	req.Stdin = []byte("hello from stdin")

	// A stdin left open would hang here rather than returning: the helper
	// copies until EOF.
	stream, err := h.run(t, req)
	require.NoError(t, err)
	require.Equal(t, "hello from stdin", stream.output(sandboxdv1.Stream_STREAM_STDOUT))
	require.Equal(t, int32(0), stream.result().GetExitCode())
}

func TestExec_TimeoutKillsTheCommandAndReportsIt(t *testing.T) {
	h := newHarness(t)

	// The spawn helper rather than a bare sleep, so the pid the agent killed
	// can be checked against the OS afterwards. It sleeps for ten minutes;
	// anything still alive at the end of this test is a survivor.
	pidFile := filepath.Join(t.TempDir(), "pids")
	req := helperReq("spawn", pidFile)
	req.Timeout = durationpb.New(500 * time.Millisecond)

	started := time.Now()
	stream, err := h.run(t, req)
	require.NoError(t, err, "a timeout is a result, not an RPC error")

	res := stream.result()
	require.NotNil(t, res)
	require.True(t, res.GetTimedOut())
	// Ordering, not duration: the call must return long before the command's
	// own ten minutes, without asserting how long the kill took.
	require.Less(t, time.Since(started), 30*time.Second)

	leader, _ := readPIDs(t, pidFile)
	requireProcessGone(t, leader)

	records := h.records(t)
	require.Len(t, records, 1)
	require.Equal(t, policy.OutcomeTimedOut, records[0].Outcome)
	require.True(t, records[0].TimedOut)
}

func TestExec_TimeoutKillsTheWholeProcessGroup(t *testing.T) {
	h := newHarness(t)

	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")
	req := helperReq("spawn", pidFile)
	req.Timeout = durationpb.New(time.Second)

	stream, err := h.run(t, req)
	require.NoError(t, err)
	require.True(t, stream.result().GetTimedOut())

	// The pid is read from the file the grandchild's parent wrote, not from
	// the agent's report of what it killed: asking the API whether it killed
	// the tree would pass whether or not it did.
	leader, child := readPIDs(t, pidFile)
	requireProcessGone(t, leader)
	requireProcessGone(t, child)
}

func TestExec_CancellingTheCallKillsTheCommand(t *testing.T) {
	h := newHarness(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")
	stream := newFakeStream(ctx)
	// Cancel as soon as the command has produced anything, which is after it
	// has spawned its child.
	stream.onSend = func(*sandboxdv1.ExecResponse) { cancel() }

	req := helperReq("spawn", pidFile)
	done := make(chan error, 1)
	go func() { done <- h.svc.Exec(req, stream) }()

	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("Exec did not return after its caller cancelled")
	}

	leader, child := readPIDs(t, pidFile)
	requireProcessGone(t, leader)
	requireProcessGone(t, child)

	records := h.records(t)
	require.Len(t, records, 1)
	require.Equal(t, policy.OutcomeCancelled, records[0].Outcome)
}

// A caller that stops reading its own stream must not be able to hold the
// handler open forever.
//
// os/exec's Wait waits for the output-copying goroutines unconditionally once
// it has closed the pipes, and this one writes to a gRPC stream rather than to
// a file — so a client that is still connected but has stopped calling Recv
// parks it in Send indefinitely. Everything downstream of Wait then never
// happens: the concurrency slot is never released, no audit record is written
// for a command that really ran, and the RPC ends only when the daemon drains.
//
// The command itself is killed on schedule either way, which is what makes this
// invisible from the outside: there is no runaway process to notice — so the
// command's own tree is what this asserts on, not just the handler returning.
// A handler that gives up while leaving the processes it started behind has
// traded one invisible failure for another.
//
// # The stall is established as a fact before any of that is asserted
//
// The handler only gives up on a command it has killed, and it kills on the
// command's own timeout — a clock that starts when the process does. The stall
// it gives up on comes from the helper's first write, which is a second clock:
// the helper is another copy of this test binary and it starts a grandchild
// before it writes, so two process creations have to fit inside the budget. A
// runner slow enough to spend the whole budget on them leaves the copier
// nothing to park on. The handler then takes the ordinary path and it is the
// *terminal result* that parks — on a Send the abandon path deliberately never
// touches — so the handler really does wedge and the failsafe below is what
// ends the test. That reads as "Exec did not return", which is true and says
// nothing about the behaviour under test.
//
// That is #72, whose failure was at exactly 30.00s: the bound's own value, not
// a duration anything took. Reproduced deterministically by giving the command
// a 1ms budget — the only Send entered is the result, and the handler does not
// return in 10s.
//
// So the fixture reads back which Send parked rather than assuming, and an
// attempt that never stalled a copier is repeated with more budget rather than
// reported as a wedge. Nothing here is asserted on how long anything took.
func TestExec_StalledOutputStreamDoesNotWedgeTheHandler(t *testing.T) {
	budget := 500 * time.Millisecond
	for attempt := 1; attempt <= 4; attempt++ {
		if stallsTheOutputCopier(t, attempt, budget) {
			return
		}
		t.Logf("attempt %d: the command's %s budget expired before the helper wrote anything, "+
			"so the terminal result parked instead of a copier; nothing was stalled, retrying with more budget",
			attempt, budget)
		budget *= 2
	}
	t.Fatalf("no attempt stalled the output copier, the last with a %s budget: "+
		"this machine cannot start the helper and its grandchild inside that, or the helper no longer writes to stdout", budget/2)
}

// stallFailsafe bounds a wait that only a genuine hang can exceed.
//
// Nothing is asserted on it: the handler's own bound is the command's budget
// plus the harness's kill grace and IO drain, which is 1.2s at the first
// attempt's budget. It exists so that a handler that never comes back fails the
// test instead of hanging the suite.
const stallFailsafe = 30 * time.Second

// stallsTheOutputCopier runs the scenario once with the given command budget
// and reports whether the copier ended up parked in Send — the state the
// handler's abandon path exists for.
//
// Everything the handler owes such a caller is asserted here. false means the
// fixture never got it into that state, which is a fact about this machine and
// says nothing about the handler either way.
func stallsTheOutputCopier(t *testing.T, attempt int, budget time.Duration) bool {
	h := newHarness(t)

	block := make(chan struct{})
	// Released at the end so the parked Send can finish; on the path this test
	// is about, the handler has returned long before this runs. Idempotent
	// because the abandoned-attempt path below releases it early, to get the
	// handler back before the next attempt starts another command.
	release := sync.OnceFunc(func() { close(block) })
	defer release()

	stream := newFakeStream(context.Background())
	stream.blockSend = block
	stream.parked = make(chan *sandboxdv1.ExecResponse, 4)

	// The spawn helper rather than a bare producer of output: it writes its
	// pids to a file before its first write to stdout, so the pids survive a
	// stream that never accepts anything.
	pidFile := filepath.Join(t.TempDir(), "stalled.pid")
	req := helperReq("spawn", pidFile)
	req.Timeout = durationpb.New(budget)

	returned := make(chan error, 1)
	go func() { returned <- h.svc.Exec(req, stream) }()

	// Which Send parked is the recorded fact this test turns on.
	var stalled *sandboxdv1.ExecResponse
	select {
	case stalled = <-stream.parked:
	case err := <-returned:
		t.Fatalf("attempt %d: Exec returned %v without any Send parking, so the caller never stalled anything", attempt, err)
	case <-time.After(stallFailsafe):
		t.Fatalf("attempt %d: nothing reached the stream in %s and Exec has not returned, so the command never produced output nor failed", attempt, stallFailsafe)
	}
	if stalled.GetOutput() == nil {
		require.NotNil(t, stalled.GetResult(), "a stream carries output chunks and one terminal result, nothing else")
		// The copiers had already finished, so there is no wedge to be rescued
		// from and the handler is parked where nothing will free it. Let it go
		// and say so; the caller retries with a budget the helper can beat.
		release()
		select {
		case <-returned:
		case <-time.After(stallFailsafe):
			t.Fatalf("attempt %d: Exec did not return in %s even after the stream started accepting again", attempt, stallFailsafe)
		}
		return false
	}

	var err error
	select {
	case err = <-returned:
	case <-time.After(stallFailsafe):
		t.Fatalf("attempt %d: Exec did not return for a caller that stopped reading its stream, "+
			"whose output copier has been parked in Send since before the command's %s budget expired", attempt, budget)
	}

	require.Error(t, err)
	require.Equal(t, codes.Aborted, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "stopped reading")

	// The handler's own record of the decision, written where it made it: it
	// saw the stream stop accepting data and took the exit path, rather than
	// returning for some other reason that also ends in Aborted.
	require.Contains(t, h.logs.String(), "giving up on a command whose output stream stopped accepting data")

	// The slot is back, so the next call is not queued behind a call that will
	// never end.
	require.Equal(t, 0, h.svc.policy.InUse())

	// And the command is gone, tree and all. Giving up on delivering a result
	// is not giving up on the process that produced it.
	leader, child := readPIDs(t, pidFile)
	requireProcessGone(t, leader)
	requireProcessGone(t, child)

	records := h.records(t)
	require.Len(t, records, 1, "a command that ran is recorded even when its result could not be delivered")
	require.Equal(t, policy.OutcomeTimedOut, records[0].Outcome)
	require.True(t, records[0].TimedOut)
	require.NotEmpty(t, records[0].Error)
	return true
}

// A caller parked on its terminal result costs a goroutine, not capacity.
//
// This is the one message #72 does not cover. Its fix bounds a stalled *output*
// stream, and it works by giving up on a command the watchdog has already
// killed — but by the time the terminal result is sent, Wait has returned and
// done is closed, so the watchdog is gone. sendResult is a plain Send, grpc-go
// returns from one of those only when the flow-control window opens or the
// stream ends, and a client that stays connected, stops calling Recv and set no
// deadline of its own does neither. Before the fix that parked the handler with
// its concurrency slot still held, permanently, once per such call.
//
// So the agent is given exactly one slot, and the assertions are what that slot
// is worth: it is back while the first handler is still inside Send, and a
// second command runs to completion on it. Neither is a duration. The wedged
// handler's own Send is what the fixture holds, so "still inside Send" is a
// state this test establishes rather than waits for.
//
// The command writes nothing at all, which is what makes the result the only
// message on the stream — there is no copier to stall, so the fixture cannot
// accidentally reproduce #72's case instead of this one, and the parked message
// is read back rather than assumed either way.
func TestExec_ACallerParkedOnItsResultDoesNotHoldItsSlot(t *testing.T) {
	h := newHarness(t, withCaps(policy.Caps{
		DefaultTimeout: 30 * time.Second,
		MaxTimeout:     time.Minute,
		MaxOutputBytes: 1 << 20,
		MaxConcurrent:  1,
	}))

	block := make(chan struct{})
	// Released at the end, so the parked Send finishes and the handler returns
	// inside the test rather than after it.
	unblock := sync.OnceFunc(func() { close(block) })
	defer unblock()

	stream := newFakeStream(context.Background())
	stream.blockSend = block
	stream.parked = make(chan *sandboxdv1.ExecResponse, 1)

	wedged := make(chan error, 1)
	go func() { wedged <- h.svc.Exec(helperReq("exit", "0"), stream) }()

	var parked *sandboxdv1.ExecResponse
	select {
	case parked = <-stream.parked:
	case err := <-wedged:
		t.Fatalf("Exec returned %v without any Send parking, so nothing was wedged", err)
	case <-time.After(stallFailsafe):
		t.Fatalf("nothing reached the stream in %s and Exec has not returned", stallFailsafe)
	}
	require.NotNil(t, parked.GetResult(),
		"a command that writes nothing has only its result to send, so that is what must have parked")

	// The recorded fact. The release happens before sendResult in the handler's
	// own order, so a message parked in Send means the slot is already back;
	// there is nothing here to race with.
	require.Equal(t, 0, h.svc.policy.InUse(),
		"the command has finished, so its slot stands for nothing running")

	// And the handler really is still in there: it cannot return until the
	// fixture lets its Send finish, which it has not.
	select {
	case err := <-wedged:
		t.Fatalf("Exec returned %v while its terminal Send was still parked", err)
	default:
	}

	// What the slot is for. The agent has one, the wedged caller is sitting on
	// its result, and a second command runs on it start to finish.
	second, err := h.run(t, helperReq("echo", "second"))
	require.NoError(t, err, "a caller parked on its own result must not cost the next caller its capacity")
	require.Equal(t, "second", second.output(sandboxdv1.Stream_STREAM_STDOUT))

	// Nothing was thrown away to buy that: the wedged caller still gets the
	// result of a command that succeeded, whenever it starts reading again.
	unblock()
	select {
	case err := <-wedged:
		require.NoError(t, err)
	case <-time.After(stallFailsafe):
		t.Fatalf("Exec did not return in %s after the stream started accepting again", stallFailsafe)
	}
	res := stream.result()
	require.NotNil(t, res)
	require.Equal(t, int32(0), res.GetExitCode())

	records := h.records(t)
	require.Len(t, records, 2)
	require.Equal(t, policy.OutcomeOK, records[0].Outcome, "the wedged call ran a command that succeeded")
	require.Equal(t, policy.OutcomeOK, records[1].Outcome, "and so did the one that used the slot it gave back")
}

// A descendant that outlived its parent does not outlive the RPC.
//
// This is the one the kill path never sees: the command succeeded, so nothing
// timed out and nobody hung up, and by the time Wait returns the process that
// would have carried its children down with it is already gone. Only the sweep
// at the end of the call reaches what it left — `sh -c 'daemon &'` is the shape
// — and exec is one-shot by contract, so docs/tools.md points anything
// longer-lived at fleet_process_start.
//
// Round 1 raised the log level on a failing sweep. It did not check that the
// sweep works, and nothing else did either: every other kill test runs a
// command that is still alive when the agent decides to kill it.
func TestExec_ADescendantThatOutlivesItsParentDoesNotOutliveTheCall(t *testing.T) {
	h := newHarness(t)

	pidFile := filepath.Join(t.TempDir(), "detached.pid")
	stream, err := h.run(t, helperReq("spawn-exit", pidFile))
	require.NoError(t, err)

	res := stream.result()
	require.NotNil(t, res)
	require.Equal(t, int32(0), res.GetExitCode(), "the command succeeded; nothing killed it")
	require.False(t, res.GetTimedOut())

	// The command's own pid is gone because it exited. Its child was never
	// signalled by anything on the timeout path, and is still sleeping out its
	// ten minutes unless the sweep took it.
	_, grandchild := readPIDs(t, pidFile)
	requireProcessGone(t, grandchild)
}

// The escalation starts politely, and that half is a guarantee of its own.
//
// docs/tools.md promises SIGTERM to the process group on expiry and SIGKILL
// only after the grace period, which is what lets a command that traps it flush
// and exit on its own terms. Nothing here looked at that: every other kill test
// in this file either runs a tree that ignores SIGTERM — where only the KILL
// can be what ended it — or asserts that the process is gone without asking
// what it died of. Deleting the TERM step therefore left the whole package
// green, with every command in the fleet killed outright.
func TestExec_TheEscalationStartsWithSIGTERM(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no catchable termination request: SignalTerm terminates the job object, and terminatingSignal reports no signal at all")
	}
	h := newHarness(t)
	// The product's own grace rather than the harness's shortened one. Nothing
	// below is asserted on how long anything took: a command that has not died
	// of SIGTERM within the grace is a command SIGTERM did not reach, and the
	// SIGKILL that follows is then what this test sees. Shortening it would
	// make the assertion a race between signal delivery and the next timer.
	h.svc.killGrace = defaultKillGrace

	// A helper that takes the default disposition for SIGTERM, so what it died
	// of is what was sent to it.
	req := helperReq("sleep", "600")
	req.Timeout = durationpb.New(500 * time.Millisecond)

	stream, err := h.run(t, req)
	require.NoError(t, err)

	res := stream.result()
	require.NotNil(t, res)
	require.True(t, res.GetTimedOut())
	require.True(t, res.GetSignaled())
	require.Equal(t, "SIGTERM", res.GetSignal(),
		"the command took the default disposition, so SIGKILL here means the polite half of the escalation never happened")
}

// A descendant holding the output pipe open does not hold the call open.
//
// os/exec's Wait does not return while anything still holds the write end of
// the command's stdout, and a grandchild that inherited it does — `sh -c
// 'daemon &'` is the shape. So a command that finished in a millisecond would
// keep its RPC, its concurrency slot and its audit record waiting until the
// timeout, and then be reported as having timed out. Cmd.WaitDelay is what
// bounds that; see defaultIODrain.
//
// Nothing asserted it. Every other grandchild in this file is started with no
// pipes at all, so deleting WaitDelay left the package, and the end-to-end
// suite, green.
//
// # The grandchild really holding the pipe is asserted, not assumed
//
// Everything below except the drain's own record is also true of a command
// whose descendant inherited nothing: it exits, it is not timed out, its code
// is zero, and the sweep takes the descendant with the call. The one thing
// only this shape produces is os/exec returning ErrWaitDelay — which it does
// only for a process that has exited while something still holds its pipes —
// and the handler logs exactly there. Without that line asserted, deleting the
// grandchild's inherited stdout left this test green while it measured
// nothing, which is #70's mistake aimed at a fixture instead of a clock.
func TestExec_ADescendantHoldingTheOutputPipeDoesNotHoldTheCall(t *testing.T) {
	h := newHarness(t)

	pidFile := filepath.Join(t.TempDir(), "holding.pid")
	req := helperReq("spawn-exit-holding-stdout", pidFile)
	// Far longer than the harness's drain, so a call that waited for the pipe
	// instead of for the drain is reported as a timeout rather than as a
	// result. The value is a bound on the failure, not on the behaviour.
	req.Timeout = durationpb.New(10 * time.Second)

	stream, err := h.run(t, req)
	require.NoError(t, err)

	res := stream.result()
	require.NotNil(t, res)
	require.False(t, res.GetTimedOut(),
		"the command exited on its own; only its descendant still held the output pipe")
	require.Equal(t, int32(0), res.GetExitCode())

	// The drain is what ended the wait, and this is the handler's own record of
	// it: os/exec reports ErrWaitDelay only for a process that exited while
	// something still held its pipes, so this line is simultaneously the
	// product behaviour under test and the proof the fixture established the
	// shape it claims to. Everything else here is what a command with no
	// descendant at all reports.
	require.Contains(t, h.logs.String(), "stopped reading output after the process exited",
		"the wait ended on the pipes closing rather than on the drain, so the grandchild never held the command's stdout and nothing above is about WaitDelay")

	// And the descendant goes with the call like any other.
	_, grandchild := readPIDs(t, pidFile)
	requireProcessGone(t, grandchild)

	records := h.records(t)
	require.Len(t, records, 1)
	require.Equal(t, policy.OutcomeOK, records[0].Outcome)
	require.False(t, records[0].TimedOut)
}

// A tree that declines SIGTERM is still gone when the timeout expires.
//
// The escalation has two halves and only the second one is a guarantee. With
// every process in the group ignoring SIGTERM, the polite half cannot be what
// ends this — so a group kill that reached only the leader, or an escalation
// that stopped at TERM, leaves a survivor the caller cannot reach.
func TestExec_ATreeThatIgnoresSIGTERMIsStillKilledOnTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no SIGTERM to ignore: the job object is terminated, which a process cannot decline")
	}
	h := newHarness(t)

	pidFile := filepath.Join(t.TempDir(), "stubborn.pid")
	req := helperReq("ignore-term-spawn", pidFile)
	req.Timeout = durationpb.New(500 * time.Millisecond)

	stream, err := h.run(t, req)
	require.NoError(t, err)

	res := stream.result()
	require.NotNil(t, res)
	require.True(t, res.GetTimedOut())
	require.True(t, res.GetSignaled(), "a process that ignored SIGTERM can only have died of SIGKILL")
	require.Equal(t, "SIGKILL", res.GetSignal())

	leader, child := readPIDs(t, pidFile)
	requireProcessGone(t, leader)
	requireProcessGone(t, child)
}

// The same tree, killed because its caller went away rather than because it
// ran too long.
//
// Cancellation and expiry take the same path out of the watcher, and that is
// exactly why it is worth asserting separately: the two differ only in which
// select case fired, so a change that gets one right and the other wrong is a
// one-line change.
func TestExec_ATreeThatIgnoresSIGTERMIsStillKilledWhenTheCallerGoesAway(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no SIGTERM to ignore: the job object is terminated, which a process cannot decline")
	}
	h := newHarness(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pidFile := filepath.Join(t.TempDir(), "stubborn.pid")
	stream := newFakeStream(ctx)
	// The helper prints its child's pid once the tree is up, so cancelling on
	// the first send is cancelling a call whose whole tree exists.
	stream.onSend = func(*sandboxdv1.ExecResponse) { cancel() }

	done := make(chan error, 1)
	go func() { done <- h.svc.Exec(helperReq("ignore-term-spawn", pidFile), stream) }()

	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("Exec did not return after its caller cancelled")
	}

	leader, child := readPIDs(t, pidFile)
	requireProcessGone(t, leader)
	requireProcessGone(t, child)

	records := h.records(t)
	require.Len(t, records, 1)
	require.Equal(t, policy.OutcomeCancelled, records[0].Outcome)
}

func TestExec_IgnoringSIGTERMEscalatesToKill(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no SIGTERM to ignore: the job object is terminated, which a process cannot decline")
	}
	h := newHarness(t)

	req := helperReq("ignore-term")
	req.Timeout = durationpb.New(500 * time.Millisecond)

	stream, err := h.run(t, req)
	require.NoError(t, err)

	res := stream.result()
	require.NotNil(t, res)
	require.True(t, res.GetTimedOut())
	require.True(t, res.GetSignaled(), "a process that ignored SIGTERM can only have died of SIGKILL")
	require.Equal(t, "SIGKILL", res.GetSignal())
}

func TestExec_OutputOverTheCapIsTruncatedAndTheCommandStillTerminates(t *testing.T) {
	h := newHarness(t)

	const capBytes = 64 * 1024
	const produced = 4 * 1024 * 1024

	req := helperReq("spew", strconv.Itoa(produced))
	req.MaxOutputBytes = capBytes
	// Deliberately generous: if the cap stopped the agent draining the pipe,
	// the helper would block in write(2) and this test would fail by timing
	// out rather than by asserting anything.
	req.Timeout = durationpb.New(30 * time.Second)

	stream, err := h.run(t, req)
	require.NoError(t, err)

	res := stream.result()
	require.NotNil(t, res)
	require.False(t, res.GetTimedOut(), "the command must finish, not deadlock on a full pipe")
	require.Equal(t, int32(0), res.GetExitCode())

	require.True(t, res.GetTruncation().GetTruncated())
	require.Positive(t, res.GetTruncation().GetBytesOmitted())
	require.Positive(t, res.GetTruncation().GetLinesOmitted())

	sent := len(stream.output(sandboxdv1.Stream_STREAM_STDOUT))
	require.LessOrEqual(t, sent, capBytes)
	require.EqualValues(t, produced, uint64(sent)+res.GetTruncation().GetBytesOmitted(),
		"every byte the command wrote is either delivered or counted as omitted")
}

func TestExec_ChunksStayUnderTheWireLimit(t *testing.T) {
	h := newHarness(t)

	req := helperReq("spew", strconv.Itoa(512*1024))
	stream, err := h.run(t, req)
	require.NoError(t, err)

	chunks := stream.chunks()
	require.NotEmpty(t, chunks)
	for _, chunk := range chunks {
		require.LessOrEqual(t, len(chunk.GetData()), maxChunkBytes)
	}
}

func TestExec_MissingBinaryNamesIt(t *testing.T) {
	h := newHarness(t)

	_, err := h.run(t, &sandboxdv1.ExecRequest{Argv: []string{"definitely-not-a-real-command"}})
	require.Error(t, err)
	require.Equal(t, codes.NotFound, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "definitely-not-a-real-command")
	require.Contains(t, status.Convert(err).Message(), "PATH")

	records := h.records(t)
	require.Len(t, records, 1)
	require.Equal(t, policy.OutcomeError, records[0].Outcome)
}

func TestExec_EmptyArgvIsRefused(t *testing.T) {
	h := newHarness(t)

	_, err := h.run(t, &sandboxdv1.ExecRequest{})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestExec_WorkingDirIsUsedAndCheckedButNotConfined(t *testing.T) {
	h := newHarness(t)

	dir := t.TempDir()
	req := helperReq("cwd")
	req.WorkingDir = dir

	stream, err := h.run(t, req)
	require.NoError(t, err)

	// EvalSymlinks because macOS resolves /var and /tmp through symlinks, and
	// the child reports the resolved form.
	want, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	got, err := filepath.EvalSymlinks(stream.output(sandboxdv1.Stream_STREAM_STDOUT))
	require.NoError(t, err)
	require.Equal(t, want, got)

	// A path outside any configured root is an ordinary path here: exec and
	// the jail are mutually exclusive, and this service must not invent a
	// confinement it does not have. See docs/security.md.
	outside := t.TempDir()
	req.WorkingDir = outside
	_, err = h.run(t, req)
	require.NoError(t, err)
}

func TestExec_UnusableWorkingDirIsAClearError(t *testing.T) {
	h := newHarness(t)

	req := helperReq("cwd")
	req.WorkingDir = filepath.Join(t.TempDir(), "no-such-directory")

	_, err := h.run(t, req)
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "no-such-directory")
}

func TestExec_ShellModeRoutesThroughThePlatformShell(t *testing.T) {
	h := newHarness(t)

	req := &sandboxdv1.ExecRequest{Argv: []string{"echo", "shell-mode"}, Shell: true}
	stream, err := h.run(t, req)
	require.NoError(t, err)
	require.Equal(t, int32(0), stream.result().GetExitCode())
	require.Contains(t, stream.output(sandboxdv1.Stream_STREAM_STDOUT), "shell-mode")

	records := h.records(t)
	require.Len(t, records, 1)
	require.True(t, records[0].Shell)
	require.Equal(t, shellArgv([]string{"echo", "shell-mode"}), records[0].Argv,
		"the record shows the argv that actually ran")
}

// A quoted argument survives the trip through the shell.
//
// The two platforms render it differently — sh strips the quotes, cmd's echo
// keeps them — so the assertion is on the text, not on the quoting. What it
// rules out is the command line being mangled on the way in: os/exec quotes
// each argument the way the C runtime parses them, cmd.exe does not parse them
// that way, and `cmd /c` would otherwise receive the whole command wrapped in
// quotes it recovers from by stripping the wrong ones.
func TestExec_ShellModeSurvivesAQuotedArgument(t *testing.T) {
	h := newHarness(t)

	stream, err := h.run(t, &sandboxdv1.ExecRequest{
		Argv:  []string{"echo", `"hi there"`},
		Shell: true,
	})
	require.NoError(t, err)
	require.Equal(t, int32(0), stream.result().GetExitCode())
	require.Contains(t, stream.output(sandboxdv1.Stream_STREAM_STDOUT), "hi there")
}

func TestExec_TimeoutAboveTheMaximumIsRefusedRatherThanClamped(t *testing.T) {
	h := newHarness(t, withCaps(policy.Caps{
		DefaultTimeout: time.Second,
		MaxTimeout:     2 * time.Second,
		MaxOutputBytes: 1 << 20,
	}))

	req := helperReq("exit", "0")
	req.Timeout = durationpb.New(time.Hour)

	_, err := h.run(t, req)
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "2s")
}

func TestExec_DisabledServiceRefusesAndSaysWhy(t *testing.T) {
	h := newHarness(t)
	h.svc.enabled = false

	_, err := h.run(t, helperReq("echo", "hi"))
	require.Error(t, err)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "exec.enabled")

	records := h.records(t)
	require.Len(t, records, 1)
	require.Equal(t, policy.OutcomeDenied, records[0].Outcome)
}

func TestExec_ConcurrencyCapIsEnforced(t *testing.T) {
	h := newHarness(t, withCaps(policy.Caps{
		DefaultTimeout: 20 * time.Second,
		MaxTimeout:     time.Minute,
		MaxOutputBytes: 1 << 20,
		MaxConcurrent:  1,
	}))

	// Hold the only slot. The caller here never cancels: the refusal has to
	// come from the agent being full, not from the caller giving up, which is
	// a different outcome and a different audit record.
	release, err := h.svc.policy.Acquire(context.Background())
	require.NoError(t, err)

	refused := helperReq("echo", "hi")
	refused.Timeout = durationpb.New(300 * time.Millisecond)
	_, err = h.run(t, refused)
	require.Error(t, err)
	require.Equal(t, codes.ResourceExhausted, status.Code(err))

	// And the slot is a slot: give it back and the next call runs.
	release()
	stream, err := h.run(t, helperReq("echo", "through"))
	require.NoError(t, err)
	require.Equal(t, "through", stream.output(sandboxdv1.Stream_STREAM_STDOUT))

	records := h.records(t)
	require.Len(t, records, 2)
	require.Equal(t, policy.OutcomeError, records[0].Outcome)
	require.Equal(t, policy.OutcomeOK, records[1].Outcome)
}

// The slot bounds a command that is running, and it is held for exactly that
// long.
//
// The other half of #81. Holding the slot *past* the command — across a
// delivery a caller can park forever — was the bug; giving it up *before* the
// command would leave process.max_concurrent bounding nothing at all, and an
// agent set to one would run as many commands at once as it was asked to.
// Nothing asserted that half: the cap's own test takes the slot by hand rather
// than by running something, so a handler that gave its slot away before
// starting its command passed every test in this file.
func TestExec_TheSlotIsHeldForAsLongAsTheCommandRuns(t *testing.T) {
	h := newHarness(t, withCaps(policy.Caps{
		DefaultTimeout: 30 * time.Second,
		MaxTimeout:     time.Minute,
		MaxOutputBytes: 1 << 20,
		MaxConcurrent:  1,
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The helper prints its child's pid before it settles down to sleep, so
	// the first thing on the stream is the recorded fact that the command is
	// running — not an interval anyone had to guess at.
	running := make(chan struct{})
	announce := sync.OnceFunc(func() { close(running) })
	stream := newFakeStream(ctx)
	stream.onSend = func(*sandboxdv1.ExecResponse) { announce() }

	pidFile := filepath.Join(t.TempDir(), "held.pid")
	returned := make(chan error, 1)
	go func() { returned <- h.svc.Exec(helperReq("spawn", pidFile), stream) }()

	select {
	case <-running:
	case err := <-returned:
		t.Fatalf("Exec returned %v before its command produced anything", err)
	case <-time.After(stallFailsafe):
		t.Fatalf("the command produced nothing in %s and Exec has not returned", stallFailsafe)
	}

	require.Equal(t, 1, h.svc.policy.InUse(),
		"the agent's only slot is taken by a command that is running")

	// So the next caller is refused, and refused because the agent is full
	// rather than because it gave up: this one bounds its own wait.
	refused := helperReq("echo", "queued")
	refused.Timeout = durationpb.New(300 * time.Millisecond)
	_, err := h.run(t, refused)
	require.Error(t, err)
	require.Equal(t, codes.ResourceExhausted, status.Code(err))

	// And the slot comes back when the command does, tree and all.
	cancel()
	select {
	case <-returned:
	case <-time.After(stallFailsafe):
		t.Fatalf("Exec did not return in %s after its caller went away", stallFailsafe)
	}
	require.Equal(t, 0, h.svc.policy.InUse())

	through, err := h.run(t, helperReq("echo", "through"))
	require.NoError(t, err)
	require.Equal(t, "through", through.output(sandboxdv1.Stream_STREAM_STDOUT))

	leader, child := readPIDs(t, pidFile)
	requireProcessGone(t, leader)
	requireProcessGone(t, child)
}

// A full agent refuses rather than queueing a caller indefinitely.
//
// The wait for a slot is bounded by the command's own timeout: a caller with no
// deadline of its own would otherwise wait forever behind a busy agent, which
// is a hung tool call rather than a cap.
func TestExec_ConcurrencyWaitIsBoundedByTheCommandsOwnTimeout(t *testing.T) {
	h := newHarness(t, withCaps(policy.Caps{
		DefaultTimeout: 300 * time.Millisecond,
		MaxTimeout:     time.Minute,
		MaxOutputBytes: 1 << 20,
		MaxConcurrent:  1,
	}))

	release, err := h.svc.policy.Acquire(context.Background())
	require.NoError(t, err)
	defer release()

	// No deadline on the call at all: the bound has to come from the request.
	_, err = h.run(t, helperReq("echo", "hi"))
	require.Error(t, err)
	require.Equal(t, codes.ResourceExhausted, status.Code(err))
}

// A caller that gives up while queued is recorded as cancelled, not as the
// agent running out of capacity.
func TestExec_CancelledWhileQueuedIsNotACapacityFailure(t *testing.T) {
	h := newHarness(t, withCaps(policy.Caps{
		DefaultTimeout: 30 * time.Second,
		MaxTimeout:     time.Minute,
		MaxOutputBytes: 1 << 20,
		MaxConcurrent:  1,
	}))

	release, err := h.svc.policy.Acquire(context.Background())
	require.NoError(t, err)
	defer release()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err = h.runCtx(ctx, t, helperReq("echo", "hi"))
	require.Error(t, err)
	require.Equal(t, codes.Canceled, status.Code(err))

	records := h.records(t)
	require.Len(t, records, 1)
	require.Equal(t, policy.OutcomeCancelled, records[0].Outcome,
		"the agent had capacity in reserve for this caller; it stopped waiting for it")
}

// --- policy ---------------------------------------------------------------

func TestExec_DeniedCommandIsRefusedAndStillAudited(t *testing.T) {
	self, err := os.Executable()
	require.NoError(t, err)
	h := newHarness(t, withDeny(filepath.Base(self)))

	_, err = h.run(t, helperReq("echo", "hi"))
	require.Error(t, err)
	require.Equal(t, codes.PermissionDenied, status.Code(err))

	records := h.records(t)
	require.Len(t, records, 1, "the refusal is exactly the thing worth recording")
	require.Equal(t, policy.OutcomeDenied, records[0].Outcome)
	require.Equal(t, filepath.Base(self), records[0].Rule)
	require.NotEmpty(t, records[0].Path, "the record names the resolved executable, which is what the rule matched")
}

func TestExec_DeniedCommandDoesNotRun(t *testing.T) {
	self, err := os.Executable()
	require.NoError(t, err)
	h := newHarness(t, withDeny(filepath.Base(self)))

	marker := filepath.Join(t.TempDir(), "ran")
	req := helperReq("spawn", marker)
	_, err = h.run(t, req)
	require.Error(t, err)

	_, statErr := os.Stat(marker)
	require.ErrorIs(t, statErr, os.ErrNotExist, "a denied command must not have started")
}

func TestExec_AllowListRefusesAnythingNotListed(t *testing.T) {
	h := newHarness(t, withAllow("something-else"))

	_, err := h.run(t, helperReq("echo", "hi"))
	require.Error(t, err)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "allow list")

	// And the same policy admits a command that is on the list.
	self, err := os.Executable()
	require.NoError(t, err)
	allowed := newHarness(t, withAllow(self))
	_, err = allowed.run(t, helperReq("echo", "hi"))
	require.NoError(t, err)
}

// --- audit ----------------------------------------------------------------

func TestExec_EveryExecProducesExactlyOneRecordWithThePrincipal(t *testing.T) {
	h := newHarness(t)

	ctx := contextWithPrincipal(t, "control-plane-1")
	for range 3 {
		_, err := h.runCtx(ctx, t, helperReq("echo", "hi"))
		require.NoError(t, err)
	}

	records := h.records(t)
	require.Len(t, records, 3)
	for _, rec := range records {
		require.Equal(t, "control-plane-1", rec.Principal)
		require.Equal(t, "sandboxd.v1.ExecService/Exec", rec.RPC)
		require.NotZero(t, rec.Time)
	}
}

func TestExec_AuditRecordsThePrincipal(t *testing.T) {
	h := newHarness(t)

	_, err := h.runCtx(contextWithPrincipal(t, "mcp-server"), t, helperReq("exit", "0"))
	require.NoError(t, err)

	records := h.records(t)
	require.Len(t, records, 1)
	require.Equal(t, "mcp-server", records[0].Principal,
		"the principal comes from the verified certificate chain, never from the request")
}

func TestExec_AuditNeverRecordsEnvironmentValues(t *testing.T) {
	const secret = "s3cr3t-token-do-not-log-4a9f"
	h := newHarness(t)

	// envdump rather than a request naming the variable, so that the variable
	// name reaches the command through the environment alone. A request that
	// put the name in argv would prove nothing: argv is recorded on purpose.
	req := helperReq("envdump")
	req.Env = append(req.Env, "FLEET_TEST_SECRET="+secret)

	stream, err := h.run(t, req)
	require.NoError(t, err)
	require.Contains(t, stream.output(sandboxdv1.Stream_STREAM_STDOUT), "FLEET_TEST_SECRET="+secret,
		"the command really did receive the secret, so its absence from the log is not an accident of it never existing")

	require.NoError(t, h.audit.Close())
	raw, err := os.ReadFile(h.auditPath)
	require.NoError(t, err)
	require.NotContains(t, string(raw), secret, "an audit log that captures secrets is a new place to steal them from")
	require.NotContains(t, string(raw), "FLEET_TEST_SECRET", "not even the name of an environment variable is recorded")

	// The command's output carried the secret too, and that is also absent:
	// there is no field for output in a record.
	records := parseRecords(t, h.auditPath)
	require.Len(t, records, 1)
	require.Equal(t, policy.OutcomeOK, records[0].Outcome)

	require.NotContains(t, h.logs.String(), secret, "nor does the daemon log carry it")
}

// The "no environment values" rule has to hold on the failure paths too.
//
// Record has no field that could carry one, which is what the test above
// checks — but an error string can, and it is written into a field. Two ways
// in, both reachable by any caller, because a caller chooses its own
// environment: the PATH a failed lookup searched, and a malformed entry quoted
// back at its sender. Either one puts a value the operator never chose into
// the file that gets shipped off-box.
//
// The caller still gets the whole story: it sent the value, and an exec caller
// can read the agent's environment with a command anyway.
func TestExec_AuditNeverRecordsEnvironmentValuesOnTheFailurePaths(t *testing.T) {
	const secret = "s3cr3t-token-do-not-log-4a9f"

	for name, req := range map[string]*sandboxdv1.ExecRequest{
		// A PATH the caller chose, echoed by "not in PATH (...)".
		"the PATH a failed lookup searched": {
			Argv: []string{"definitely-not-a-real-command"},
			Env:  []string{"PATH=/tmp/" + secret},
		},
		// An entry with an empty name is quoted whole, and "=VALUE" is a value
		// with nothing else in it.
		"a malformed entry quoted back": {
			Argv: selfArgv(),
			Env:  []string{helperEnvFor("echo"), "=" + secret},
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)

			_, err := h.run(t, req)
			require.Error(t, err)
			require.Contains(t, status.Convert(err).Message(), secret,
				"the caller is told what it sent; only the log is redacted")

			require.NoError(t, h.audit.Close())
			raw, readErr := os.ReadFile(h.auditPath)
			require.NoError(t, readErr)
			require.NotContains(t, string(raw), secret,
				"an environment value must not reach the audit log through an error string either")

			records := parseRecords(t, h.auditPath)
			require.Len(t, records, 1, "the refusal is still recorded, just without the value")
			require.Equal(t, policy.OutcomeError, records[0].Outcome)
			require.NotEmpty(t, records[0].Error, "and it still says why")
		})
	}
}

// Nothing a caller sends that has no field of its own reaches the record, by
// any route out of the handler.
//
// The test above is the enumerated version of this: it names the two paths a
// previous round found, and it would keep passing if a third were added
// tomorrow. That is how the first one was missed — the invariant was read off
// the field list, the field list was right, and an error string is a field
// too.
//
// So this one enumerates requests rather than paths. Every shape below leaves
// the handler somewhere different — before validation, at the lookup, at the
// policy, at the spawn, on the kill path, on the way out — and every one is
// run with the secret in each of the places a caller can put one that the
// record has nowhere to hold: an environment value, an environment name, and
// stdin. The property is asserted over the whole file rather than over a
// field, so a new path that writes caller data into any field of any record
// fails it without anyone having thought of that path first.
//
// Argv and working_dir are deliberately not poisoned. Both have fields, both
// are recorded on purpose, and docs/security.md says so.
func TestExec_NothingWithoutAFieldReachesTheRecord(t *testing.T) {
	const secret = "s3cr3t-token-do-not-log-4a9f"

	// Every way a caller can carry the secret into the request without putting
	// it somewhere the record is documented to keep.
	poisons := map[string][]string{
		"in the PATH that is searched":   {"PATH=/tmp/" + secret},
		"in PATHEXT":                     {"PATHEXT=." + secret},
		"in TMPDIR":                      {"TMPDIR=/tmp/" + secret, "TEMP=/tmp/" + secret, "TMP=/tmp/" + secret},
		"in HOME":                        {homeVar + "=/home/" + secret},
		"in COMSPEC":                     {"COMSPEC=/bin/" + secret},
		"in an ordinary value":           {"ORDINARY=" + secret},
		"in a variable name":             {secret + "=ordinary"},
		"in an entry with no separator":  {secret},
		"in an entry with an empty name": {"=" + secret},
		"in a name beside a NUL byte":    {secret + "=has-a\x00-nul"},
		"in a value beside a NUL byte":   {"ORDINARY=" + secret + "\x00"},
	}

	// Every shape leaves Exec by a different route.
	missingDir := filepath.Join(t.TempDir(), "no-such-directory")
	aDirectory := t.TempDir()
	shapes := func() map[string]*sandboxdv1.ExecRequest {
		overLimit := helperReq("echo", "hi")
		overLimit.Timeout = durationpb.New(time.Hour)

		badDir := helperReq("echo", "hi")
		badDir.WorkingDir = missingDir

		killed := helperReq("sleep", "30")
		killed.Timeout = durationpb.New(200 * time.Millisecond)

		capped := helperReq("spew", "65536")
		capped.MaxOutputBytes = 1024

		return map[string]*sandboxdv1.ExecRequest{
			"a command that runs":            helperReq("echo", "hi"),
			"a command that exits non-zero":  helperReq("exit", "3"),
			"a command that is killed":       killed,
			"a command over the output cap":  capped,
			"an empty argv":                  {},
			"no such executable":             {Argv: []string{"definitely-not-a-real-command"}},
			"an argv[0] that is a directory": {Argv: []string{aDirectory}},
			"a relative argv[0]":             {Argv: []string{"." + string(filepath.Separator) + "not-here"}},
			"a working_dir that is not one":  badDir,
			"a timeout over the maximum":     overLimit,
			"a command the policy refuses":   {Argv: []string{"denied-by-the-test"}},
			"shell mode":                     {Argv: []string{"echo", "hi"}, Shell: true},
		}
	}

	for poison, env := range poisons {
		t.Run(poison, func(t *testing.T) {
			// One deny rule, matching nothing any other shape names, so the
			// refusal path is reachable from the same harness as the rest.
			h := newHarness(t, withDeny("denied-by-the-test*"))

			requests := shapes()
			for _, req := range requests {
				req.Env = append(req.Env, env...)
				// Stdin has no field either, and a caller can put a file's
				// contents in it.
				req.Stdin = []byte(secret)
				// Errors are the point of most of these shapes; what matters
				// is what was written down, which is checked below.
				_, _ = h.run(t, req)
			}

			require.NoError(t, h.audit.Close())
			raw, err := os.ReadFile(h.auditPath)
			require.NoError(t, err)
			require.NotContainsf(t, string(raw), secret,
				"a caller put %s and it reached the audit log; the record has no field for it, "+
					"and an error message is a field", poison)
			require.NotContainsf(t, h.logs.String(), secret,
				"a caller put %s and it reached the daemon's own log", poison)

			// The redaction has to leave a record behind, or "nothing leaked"
			// is satisfied by recording nothing.
			records := parseRecords(t, h.auditPath)
			require.Len(t, records, len(requests), "one record per call, whatever the call did")
			for _, rec := range records {
				require.NotEmpty(t, rec.Outcome, "every record says how the call ended")
				require.Equal(t, execMethod, rec.RPC)
			}
		})
	}
}

func TestExec_ConcurrentCallsProduceWholeRecords(t *testing.T) {
	h := newHarness(t)

	const calls = 12
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	for i := range calls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stream := newFakeStream(context.Background())
			// Collected rather than asserted here: require.NoError calls
			// t.FailNow, which is only valid on the test's own goroutine.
			if err := h.svc.Exec(helperReq("echo", "call-"+strconv.Itoa(i)), stream); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	require.Empty(t, errs)

	records := h.records(t)
	require.Len(t, records, calls, "one record per exec, none lost and none interleaved into another")
	for _, rec := range records {
		require.Equal(t, policy.OutcomeOK, rec.Outcome)
		require.NotEmpty(t, rec.Path)
	}
}

func TestExec_AuditRequiredFailsTheRPCWhenTheRecordCannotBeWritten(t *testing.T) {
	unwritable := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(unwritable, []byte("this is a file"), 0o600))

	h := newHarness(t, withAudit(func(a *policy.AuditConfig) {
		// A path whose parent is a regular file cannot be created on any
		// platform, which is the portable way to spell "unwritable".
		a.Path = filepath.Join(unwritable, "audit.jsonl")
		a.Required = true
	}))

	stream, err := h.run(t, helperReq("echo", "hi"))
	require.Error(t, err)
	require.Equal(t, codes.Internal, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "audit.required")
	require.Nil(t, stream.result(), "the result is withheld when it could not be recorded")

	// What the caller does still have is the output, and that is the shape of
	// the failure rather than a wrinkle in it: chunks go out as the command
	// produces them, which is the point of a streaming RPC, so by the time the
	// record is written they cannot be recalled. "The call failed" here means
	// the caller never learns the exit status, not that it saw nothing — and a
	// consumer has to read it as "this may well have run".
	require.Equal(t, "hi", stream.output(sandboxdv1.Stream_STREAM_STDOUT),
		"output already on the wire is not withheld, and the error message is what says so")
	require.Contains(t, status.Convert(err).Message(), "its result is withheld",
		"the message distinguishes this from a handler that crashed, which is also Internal")
}

func TestExec_AuditNotRequiredLogsAndProceeds(t *testing.T) {
	unwritable := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(unwritable, []byte("this is a file"), 0o600))

	h := newHarness(t, withAudit(func(a *policy.AuditConfig) {
		a.Path = filepath.Join(unwritable, "audit.jsonl")
		a.Required = false
	}))

	stream, err := h.run(t, helperReq("echo", "hi"))
	require.NoError(t, err, "without audit.required the call proceeds unrecorded")
	require.NotNil(t, stream.result())
	require.Contains(t, h.logs.String(), "audit record was not written")
}

// --- environment ----------------------------------------------------------

func TestExec_DaemonEnvironmentIsNotInherited(t *testing.T) {
	const leaked = "GITHUB_TOKEN"
	t.Setenv(leaked, "ghp_pretend-this-is-real")

	h := newHarness(t)
	// Rebuild the base after Setenv, the way a daemon started with that
	// variable would have.
	h.svc.baseEnv = BaseEnv()

	stream, err := h.run(t, helperReq("env", leaked))
	require.NoError(t, err)
	require.Empty(t, stream.output(sandboxdv1.Stream_STREAM_STDOUT),
		"the daemon's environment may hold credentials from whatever installed it")
}

func TestExec_RequestEnvironmentIsAppliedOverTheBase(t *testing.T) {
	h := newHarness(t)

	req := helperReq("env", "PATH")
	req.Env = append(req.Env, "PATH=/a-path-of-my-own")

	stream, err := h.run(t, req)
	require.NoError(t, err)
	require.Equal(t, "/a-path-of-my-own", stream.output(sandboxdv1.Stream_STREAM_STDOUT),
		"a request entry replaces the base entry rather than sitting beside it")
}

func TestExec_BaseEnvironmentCarriesTheDocumentedVariables(t *testing.T) {
	h := newHarness(t)

	stream, err := h.run(t, helperReq("envdump"))
	require.NoError(t, err)

	names := map[string]bool{}
	for _, line := range strings.Split(stream.output(sandboxdv1.Stream_STREAM_STDOUT), "\n") {
		if name, _, ok := strings.Cut(line, "="); ok {
			names[strings.ToUpper(strings.TrimSpace(name))] = true
		}
	}
	require.True(t, names["PATH"], "nothing runs without PATH")
	require.True(t, names[strings.ToUpper(homeVar)], "toolchains cache under the home directory")
	// The helper mode variable is proof that the request's own entries arrive.
	require.True(t, names[helperEnv])
}

func TestExec_MalformedEnvironmentEntryIsRefused(t *testing.T) {
	h := newHarness(t)

	req := helperReq("echo", "hi")
	req.Env = append(req.Env, "NOT_A_PAIR")

	_, err := h.run(t, req)
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "KEY=VALUE")
}

// --- helpers --------------------------------------------------------------

// readPIDs waits for the spawn helper to record its own pid and its child's.
func readPIDs(t *testing.T, path string) (leader, child int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			fields := strings.Fields(string(data))
			if len(fields) == 2 {
				leader, leaderErr := strconv.Atoi(fields[0])
				child, childErr := strconv.Atoi(fields[1])
				if leaderErr == nil && childErr == nil && leader > 0 && child > 0 {
					return leader, child
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the helper never recorded its pids in %s", path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// requireProcessGone waits for a pid to disappear.
//
// It polls rather than checking once because reaping is asynchronous: the
// grandchild is reparented when its parent dies and it is init that collects
// it. What it never does is ask the agent whether the kill worked — a test
// that trusts the API it is testing would pass whether or not anything died.
func requireProcessGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if !platform.ProcessExists(pid) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pid %d survived: the process group was not killed", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// contextWithPrincipal returns a context carrying a verified client chain, the
// way the daemon's TLS handshake would.
func contextWithPrincipal(t *testing.T, cn string) context.Context {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{{cert}},
		}},
	})
}
