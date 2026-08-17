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

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/platform"
	"github.com/axelmierczuk/sandboxd-mcp/internal/security/policy"
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
}

func newFakeStream(ctx context.Context) *fakeStream { return &fakeStream{ctx: ctx} }

func (s *fakeStream) Context() context.Context { return s.ctx }

func (s *fakeStream) Send(msg *sandboxdv1.ExecResponse) error {
	s.mu.Lock()
	hook := s.onSend
	err := s.sendErr
	block := s.blockSend
	s.mu.Unlock()

	if hook != nil {
		hook(msg)
	}
	if block != nil {
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
// invisible from the outside: there is no runaway process to notice.
func TestExec_StalledOutputStreamDoesNotWedgeTheHandler(t *testing.T) {
	h := newHarness(t)

	block := make(chan struct{})
	// Released at the end so the parked copier can finish; the handler must
	// have returned long before this runs.
	defer close(block)

	stream := newFakeStream(context.Background())
	stream.blockSend = block

	req := helperReq("spew", "1048576")
	req.Timeout = durationpb.New(500 * time.Millisecond)

	returned := make(chan error, 1)
	go func() { returned <- h.svc.Exec(req, stream) }()

	var err error
	select {
	case err = <-returned:
	case <-time.After(30 * time.Second):
		t.Fatal("Exec did not return for a caller that stopped reading its stream")
	}

	require.Error(t, err)
	require.Equal(t, codes.Aborted, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "stopped reading")

	// The slot is back, so the next call is not queued behind a call that will
	// never end.
	require.Equal(t, 0, h.svc.policy.InUse())

	records := h.records(t)
	require.Len(t, records, 1, "a command that ran is recorded even when its result could not be delivered")
	require.Equal(t, policy.OutcomeTimedOut, records[0].Outcome)
	require.True(t, records[0].TimedOut)
	require.NotEmpty(t, records[0].Error)
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
	req.Env = append(req.Env, "SANDBOXD_TEST_SECRET="+secret)

	stream, err := h.run(t, req)
	require.NoError(t, err)
	require.Contains(t, stream.output(sandboxdv1.Stream_STREAM_STDOUT), "SANDBOXD_TEST_SECRET="+secret,
		"the command really did receive the secret, so its absence from the log is not an accident of it never existing")

	require.NoError(t, h.audit.Close())
	raw, err := os.ReadFile(h.auditPath)
	require.NoError(t, err)
	require.NotContains(t, string(raw), secret, "an audit log that captures secrets is a new place to steal them from")
	require.NotContains(t, string(raw), "SANDBOXD_TEST_SECRET", "not even the name of an environment variable is recorded")

	// The command's output carried the secret too, and that is also absent:
	// there is no field for output in a record.
	records := parseRecords(t, h.auditPath)
	require.Len(t, records, 1)
	require.Equal(t, policy.OutcomeOK, records[0].Outcome)

	require.NotContains(t, h.logs.String(), secret, "nor does the daemon log carry it")
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
