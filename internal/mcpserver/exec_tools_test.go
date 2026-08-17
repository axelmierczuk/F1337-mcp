package mcpserver_test

import (
	"context"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver/tools"
	"github.com/axelmierczuk/fleet-mcp/internal/platform"
	"github.com/axelmierczuk/fleet-mcp/internal/security/policy"
)

// execResult mirrors tools.ExecResult for decoding a tool result.
type execResult struct {
	Sandbox    string `json:"sandbox"`
	ExitCode   int32  `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	DurationMs int64  `json:"duration_ms"`
	TimedOut   bool   `json:"timed_out"`
	Signal     string `json:"signal"`
	Truncation *struct {
		Truncated    bool   `json:"truncated"`
		BytesOmitted uint64 `json:"bytes_omitted"`
		LinesOmitted uint64 `json:"lines_omitted"`
		Note         string `json:"note"`
	} `json:"truncation"`
	Note string `json:"note"`
}

func (f *agentFixture) exec(t *testing.T, mode string, args map[string]any) execResult {
	t.Helper()
	call := map[string]any{"argv": selfArgv(), "env": helperEnvFor(mode)}
	for k, v := range args {
		call[k] = v
	}
	return structured[execResult](t, f.ok("fleet_exec", call))
}

// TestExec_SuccessReturnsExitZeroAndItsOutput.
func TestExec_SuccessReturnsExitZeroAndItsOutput(t *testing.T) {
	f := newAgentFixture(t, backendOptions{})

	out := f.exec(t, "streams", nil)

	assert.Equal(t, int32(0), out.ExitCode)
	assert.Equal(t, "to stdout\n", out.Stdout)
	assert.Equal(t, "to stderr\n", out.Stderr, "stderr must stay distinguishable from stdout")
	assert.Equal(t, "build-box", out.Sandbox)
	assert.Nil(t, out.Truncation, "an uncapped result must carry no truncation field at all")
}

// TestExec_FailureIsASuccessfulCallCarryingTheDiagnosis. An error result would
// throw away the compiler output that is the only thing the model can act on.
func TestExec_FailureIsASuccessfulCallCarryingTheDiagnosis(t *testing.T) {
	f := newAgentFixture(t, backendOptions{})

	out := f.exec(t, "fail", nil)

	assert.Equal(t, int32(2), out.ExitCode)
	assert.Contains(t, out.Stderr, "undefined: doesNotExist", "the diagnosis must survive")
	assert.Contains(t, out.Stdout, "running 3 tests")
	assert.Contains(t, out.Note, "ran and failed", "and the result must say which kind of failure this is")
}

// TestExec_EmptyOutputSaysSo. A blank result is indistinguishable from a hung
// call, and the model's next move differs completely between the two.
func TestExec_EmptyOutputSaysSo(t *testing.T) {
	f := newAgentFixture(t, backendOptions{})

	out := f.exec(t, "quiet", nil)

	assert.Equal(t, int32(0), out.ExitCode)
	assert.Empty(t, out.Stdout)
	assert.Empty(t, out.Stderr)
	assert.Contains(t, out.Note, "no output on either stream")
}

// TestExec_TimeoutNamesTheLimitThatWasHit.
func TestExec_TimeoutNamesTheLimitThatWasHit(t *testing.T) {
	f := newAgentFixture(t, backendOptions{})

	out := f.exec(t, "sleep", map[string]any{"argv": selfArgv("30"), "timeout_seconds": 1})

	assert.True(t, out.TimedOut)
	assert.Contains(t, out.Note, "1s", "the note must name the limit that was hit")
	assert.Contains(t, out.Note, "timeout_seconds", "and the argument that raises it")
	assert.Contains(t, out.Note, "fleet_process_start", "and where long-running work belongs")
}

// TestExec_TruncatedOutputIsMarkedWithWhatWasDropped. The whole point of the
// cap is that the model can tell a capped result from a complete one.
func TestExec_TruncatedOutputIsMarkedWithWhatWasDropped(t *testing.T) {
	f := newAgentFixture(t, backendOptions{})

	out := f.exec(t, "spew", map[string]any{"argv": selfArgv("262144"), "max_output_bytes": 4096})

	assert.Equal(t, int32(0), out.ExitCode, "a command over the cap still runs to completion")
	require.NotNil(t, out.Truncation, "capped output must be marked")
	assert.True(t, out.Truncation.Truncated)
	assert.Positive(t, out.Truncation.BytesOmitted, "and must say how much was dropped")
	assert.Positive(t, out.Truncation.LinesOmitted)
	assert.Contains(t, out.Truncation.Note, "max_output_bytes", "and which argument raises the cap")
	assert.LessOrEqual(t, len(out.Stdout), 4096+64)
}

// TestExec_DefaultCapAppliesWithoutAnArgument covers the case the model will
// actually hit: it did not think about output size at all.
func TestExec_DefaultCapAppliesWithoutAnArgument(t *testing.T) {
	f := newAgentFixture(t, backendOptions{})

	out := f.exec(t, "spew", map[string]any{"argv": selfArgv("1048576")})

	require.NotNil(t, out.Truncation)
	assert.LessOrEqual(t, len(out.Stdout), tools.DefaultExecOutputBytes+64)
	assert.Positive(t, out.Truncation.BytesOmitted)
}

// TestExec_CancellingTheToolCallKillsTheRemoteProcess.
//
// It asserts on the process, not on the tool returning. A handler that gives
// up on its stream while leaving the command running has produced exactly the
// symptom this test exists to rule out: a sandbox slowly filling with
// abandoned work that nothing is watching.
func TestExec_CancellingTheToolCallKillsTheRemoteProcess(t *testing.T) {
	f := newAgentFixture(t, backendOptions{})

	pidFile := filepath.Join(t.TempDir(), "helper.pid")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = f.session.CallTool(ctx, &mcp.CallToolParams{Name: "fleet_exec", Arguments: map[string]any{
			"argv": selfArgv(pidFile, "120"),
			"env":  helperEnvFor("mark"),
		}})
	}()

	pid := readPID(t, pidFile)
	cancel()

	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("the tool call did not return after its caller cancelled")
	}
	requireProcessGone(t, pid)
}

// requireProcessGone waits for a pid to disappear. It polls rather than
// checking once because reaping is asynchronous, and it never asks the agent
// whether the kill worked — a test that trusts the API it is testing would
// pass whether or not anything died.
func requireProcessGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if !platform.ProcessExists(pid) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pid %d survived the cancelled call", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestExec_MissingBinaryIsAToolErrorNamingIt. The other half of the contract:
// a request the agent would not run at all is an error, not an exit code.
func TestExec_MissingBinaryIsAToolErrorNamingIt(t *testing.T) {
	f := newAgentFixture(t, backendOptions{})

	text := f.fails("fleet_exec", map[string]any{"argv": []any{"definitely-not-a-real-binary-xyz"}})

	assert.Contains(t, text, "definitely-not-a-real-binary-xyz")
	assert.Contains(t, text, "build-box", "and the sandbox it was refused on")
	assert.NotContains(t, text, "rpc error: code =", "no gRPC envelope reaches the model")
}

// TestExec_PolicyDenialIsAToolError covers the third failure the issue names
// alongside "unreachable" and "binary not found".
func TestExec_PolicyDenialIsAToolError(t *testing.T) {
	f := newAgentFixture(t, backendOptions{caps: policy.Caps{MaxTimeout: 2 * time.Second}})

	text := f.fails("fleet_exec", map[string]any{
		"argv": selfArgv(), "env": helperEnvFor("quiet"), "timeout_seconds": 600,
	})

	assert.Contains(t, text, "2s", "a refused request must name the maximum it exceeded")
	assert.Contains(t, text, "build-box")
}

// TestExec_ArgvIsRequired: an empty argv never reaches the agent.
func TestExec_ArgvIsRequired(t *testing.T) {
	f := newAgentFixture(t, backendOptions{})
	text := f.fails("fleet_exec", map[string]any{"argv": []any{}})
	assert.Contains(t, text, "argv")
}

// TestExec_AnAbsurdTimeoutIsRefusedRatherThanWrappedAround.
//
// The RPC deadline is twice the timeout, in nanoseconds, in an int64. Past
// about 146 years that multiplication wraps negative — the context is born
// expired, the call fails instantly, and the error tells the model its call
// timed out and to raise timeout_seconds.
func TestExec_AnAbsurdTimeoutIsRefusedRatherThanWrappedAround(t *testing.T) {
	f := newAgentFixture(t, backendOptions{})

	// 2^33 seconds: past the point where twice it, in nanoseconds, leaves the
	// range of a time.Duration.
	text := f.fails("fleet_exec", map[string]any{
		"argv": []any{"true"}, "timeout_seconds": 1 << 33,
	})

	assert.Contains(t, text, "timeout_seconds")
	assert.Contains(t, text, "fleet_process_start", "and where work that long belongs")
	assert.NotContains(t, text, "timed out", "it is a refusal, not a call that ran and expired")
}

// TestExec_StdinIsDelivered.
func TestExec_StdinIsDelivered(t *testing.T) {
	f := newAgentFixture(t, backendOptions{})

	out := f.exec(t, "cat", map[string]any{"stdin": "fed through stdin"})

	assert.Equal(t, int32(0), out.ExitCode)
	assert.Equal(t, "fed through stdin", out.Stdout)
}

// --------------------------------------------------------------- memory

// floodExec is an ExecServiceClient that ignores the cap it was given and
// streams until it has sent floodBytes.
//
// The real agent clamps output, so the memory question cannot be asked of it:
// it never sends more than the cap. This is the case the bound exists for —
// an agent that is misconfigured, older, or not the one this server believes
// it is talking to must not be able to size this process's heap by streaming
// at it.
type floodExec struct {
	total   int
	sampler *heapSampler
}

const floodChunk = 32 * 1024

func (f floodExec) Exec(_ context.Context, _ *sandboxdv1.ExecRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[sandboxdv1.ExecResponse], error) {
	return &floodStream{remaining: f.total, sampler: f.sampler}, nil
}

type floodStream struct {
	grpc.ClientStream
	remaining int
	done      bool
	sampler   *heapSampler
}

func (s *floodStream) Recv() (*sandboxdv1.ExecResponse, error) {
	if s.remaining > 0 {
		n := min(s.remaining, floodChunk)
		s.remaining -= n
		chunk := make([]byte, n)
		for i := range chunk {
			chunk[i] = 'y'
		}
		chunk[n-1] = '\n'
		s.sampler.tick()
		return &sandboxdv1.ExecResponse{Event: &sandboxdv1.ExecResponse_Output{
			Output: &sandboxdv1.OutputChunk{Stream: sandboxdv1.Stream_STREAM_STDOUT, Data: chunk},
		}}, nil
	}
	if !s.done {
		s.done = true
		return &sandboxdv1.ExecResponse{Event: &sandboxdv1.ExecResponse_Result{
			Result: &sandboxdv1.ExecResult{ExitCode: 0, Duration: durationpb.New(time.Second)},
		}}, nil
	}
	return nil, io.EOF
}

// TestExec_MegabytesOfOutputDoNotBlowUpTheServer asserts on the heap, not on
// the rendered string: a tool that accumulated everything and then trimmed
// would pass a length check and still be the bug. It is the peak *during* the
// stream, because a tool that buffered and then trimmed would also show
// nothing afterwards.
func TestExec_MegabytesOfOutputDoNotBlowUpTheServer(t *testing.T) {
	if testing.Short() {
		t.Skip("streams 256 MiB")
	}
	const streamed = 256 << 20 // 256 MiB, four times heapPayload: chunks here
	// are generated in memory rather than read from disk, so the bigger signal
	// is nearly free.

	f := newAgentFixture(t, backendOptions{})
	// Swap the exec client for one that ignores the cap. The file service and
	// everything else stays real.
	sampler := newHeapSampler(128)
	f.clients.execOverride = floodExec{total: streamed, sampler: sampler}

	out := structured[execResult](t, f.ok("fleet_exec", map[string]any{
		"argv": []any{"whatever"}, "max_output_bytes": 64 * 1024,
	}))

	assert.Equal(t, int32(0), out.ExitCode, "the call must complete rather than fail on size")
	require.NotNil(t, out.Truncation)
	assert.Greater(t, out.Truncation.BytesOmitted, uint64(200<<20), "and must report roughly what it dropped")
	assert.LessOrEqual(t, len(out.Stdout), 64*1024+floodChunk)
	require.Greater(t, sampler.ticks, 512, "the flood has to arrive as many chunks, not one")

	assertHeapBounded(t, sampler, streamed, "fleet_exec output accumulation")
}
