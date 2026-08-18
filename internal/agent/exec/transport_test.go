package exec

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/security/policy"
)

// streamWindow is the flow-control window this file pins its client to.
//
// 64 KiB is grpc-go's floor — WithInitialWindowSize ignores anything smaller —
// and pinning it also turns off the BDP estimator, which would otherwise raise
// the window mid-call and hand back the quota these tests exist to take away.
const streamWindow = 64 * 1024

// sendBudget is how much a server can hand to a client that never reads before
// a Send blocks.
//
// Two budgets in series, not one. The stream's outbound window is 64 KiB and
// only the client's own reads reopen it; behind that grpc-go keeps a per-stream
// write quota of another 64 KiB, which it replenishes as the wire drains. So
// 128 KiB goes out before anything waits, which is why a test that wants a Send
// to park has to spend twice the window rather than one of it.
//
// It is also exactly four maxChunkBytes chunks, and that is what makes this
// deterministic rather than lucky: see the cap in parksOnItsResult.
const sendBudget = 2 * streamWindow

// serveExecOverGRPC registers svc on a real gRPC server over bufconn and
// returns a client that never grows its stream window, plus a channel carrying
// what the server's *first* Exec handler returned.
//
// The rest of this package drives the handler directly through a stand-in
// stream, which is right for everything the handler decides. It is not right
// for a wedge whose cause is grpc-go's flow control: a stand-in that blocks
// because a test told it to proves the handler's reaction, not that there is
// anything to react to. Here the client is real, the window is real, and
// nothing is told to block.
//
// The interceptor is the only way to see a handler return from outside it,
// because the client this file uses never reads its stream and so never
// observes the RPC ending. It reports the first call and no other on purpose:
// the first is the wedged one, the calls after it are the ones sent to prove
// the agent still has capacity, and a channel that carried both would answer
// "has the wedged handler returned?" with whichever finished first — which is
// always the healthy call.
func serveExecOverGRPC(t *testing.T, svc *Service) (sandboxdv1.ExecServiceClient, <-chan error) {
	t.Helper()

	var calls atomic.Int64
	returned := make(chan error, 1)
	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer(grpc.StreamInterceptor(
		func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			first := calls.Add(1) == 1
			err := handler(srv, ss)
			if first {
				returned <- err
			}
			return err
		}))
	svc.Register(server)
	go func() { _ = server.Serve(lis) }()
	// Stop rather than GracefulStop: an attempt here ends with a handler parked
	// in Send, and graceful means waiting for it.
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithInitialWindowSize(streamWindow),
		grpc.WithInitialConnWindowSize(streamWindow),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return sandboxdv1.NewExecServiceClient(conn), returned
}

// parkedSend reports which of the sink's two Sends a goroutine is currently
// inside: "result" for the terminal ExecResult, "output" for an output chunk,
// "" for neither.
//
// The two are opposite answers. A copier parked in write is #72's case, which
// the watchdog already bounds; the terminal result is #81's, which it cannot
// reach. Reading it off the stacks is how the fixture tells them apart instead
// of assuming which one it produced.
func parkedSend() string {
	buf := make([]byte, 1<<16)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	switch stacks := string(buf); {
	case strings.Contains(stacks, "exec.(*sink).sendResult"):
		return "result"
	case strings.Contains(stacks, "exec.(*sink).write"):
		return "output"
	default:
		return ""
	}
}

// awaitParkedSend waits for a Send to park and reports which one did.
//
// A wait for a fact, not an assertion about one: nothing is asserted on how
// long it took, and the failsafe is there so a fixture that never gets there
// fails the test instead of hanging the suite.
func awaitParkedSend(failsafe time.Duration) string {
	deadline := time.Now().Add(failsafe)
	for {
		if kind := parkedSend(); kind != "" {
			return kind
		}
		if time.Now().After(deadline) {
			return ""
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// awaitFirstRecord waits for the handler to write its audit record, and reports
// whether it did so before the handler returned.
//
// This is the fixture's join point, and it is a fact rather than a delay: the
// record is written after run has come back — command waited for, group swept,
// copiers finished — and before the terminal result goes out. Past it there is
// no copier left to park, so a Send parked from here on can only be the
// terminal one, and a copier parked transiently waiting for its write quota to
// be replenished cannot be mistaken for the wedge.
//
// false means the handler returned first, which is the stalled-copier case
// rather than this one.
func awaitFirstRecord(t *testing.T, h *harness, returned <-chan error, failsafe time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(failsafe)
	for {
		if len(parseRecords(t, h.auditPath)) > 0 {
			return true
		}
		select {
		case err := <-returned:
			t.Logf("the handler returned %v before recording a command that finished", err)
			return false
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("no audit record and no handler return in %s: the command neither finished nor was given up on", failsafe)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A real client that stops reading really does park the handler on its terminal
// result — and the agent's capacity survives it.
//
// Everything else in this package stands a fixture in for the stream, which is
// right for what the handler decides and cannot show that grpc-go's Send parks
// at all: a stand-in that blocks because a test told it to proves the reaction,
// not that there is anything to react to. Here the client is connected, is not
// reading, and set no deadline, which is the whole of the reported behaviour,
// and the parking is grpc's own.
//
// # Spending the budget on exactly four chunks
//
// The caller can absorb sendBudget before a Send waits, and quota is taken
// whenever any is left — so the message that takes the last of it still goes
// and the *next* Send is the one with nowhere to go. This test needs that next
// Send to be the terminal result, which means the budget has to run out on the
// last chunk of output rather than an earlier one.
//
// Left to itself that is a coin toss, because where io.Copy cuts the output is
// the kernel's business: a line-at-a-time writer lets the copier keep up, which
// produces a couple of hundred chunks of a few hundred bytes, spends 2 KiB of
// the budget on per-message overhead, and ends on a tail chunk small enough
// that the crossing lands anywhere in the last few. Two things fix that. The
// helper writes in 32 KiB blocks, so the pipe is always full and every read
// fills io.Copy's buffer; and the request caps output at sendBudget, which is
// exactly four maxChunkBytes chunks — so the cap, not the tail of the pipe,
// decides where the last chunk ends. Four full chunks spend the budget with the
// fourth, the copiers finish, Wait returns, done is closed, and the watchdog
// that rescues a stalled output stream is gone. That is #81.
//
// The command keeps writing long past the cap, which the sink accepts and
// discards, so nothing here depends on the command's output ending anywhere in
// particular. And the fixture still reads back which Send parked: if a machine
// cuts the output some other way, the attempt says so and is repeated rather
// than reported as a wedge that did not happen.
func TestExec_ARealClientThatStopsReadingParksOnItsResultWithoutTakingCapacity(t *testing.T) {
	for attempt := 1; attempt <= 3; attempt++ {
		if parksOnItsResult(t, attempt) {
			return
		}
	}
	t.Fatal("no attempt parked on the terminal result: every one of them spent the stream's budget " +
		"before the last chunk of output, which parks a copier instead and is #72's case")
}

// transportFailsafe bounds a wait only a genuine hang can exceed. Nothing is
// asserted on it; it is here so a handler that never parks fails this test
// instead of hanging the suite.
const transportFailsafe = 60 * time.Second

// wedgedBudget is how long the wedged call's command is given.
//
// It bounds nothing this test asserts. It is what ends an attempt that parks a
// copier instead: that handler is inside Wait rather than inside the terminal
// Send, so only the watchdog gets it out, and the watchdog starts on this
// clock. Generous enough to start a helper and push 128 KiB through a pipe on
// any runner, short enough that a repeat is not the wall clock.
const wedgedBudget = 20 * time.Second

// parksOnItsResult runs the scenario once and reports whether it was the
// terminal result that parked. false means the fixture produced the stalled
// copier instead, which is a fact about how the output was cut and says nothing
// about the handler.
func parksOnItsResult(t *testing.T, attempt int) bool {
	t.Helper()

	h := newHarness(t, withCaps(policy.Caps{
		DefaultTimeout: wedgedBudget,
		MaxTimeout:     time.Minute,
		MaxOutputBytes: 8 << 20,
		// One slot, so "the slot came back" and "the next caller can run" are
		// the same statement.
		MaxConcurrent: 1,
	}))
	client, returned := serveExecOverGRPC(t, h.svc)

	// No deadline, which is half of what the report is about: nothing but this
	// cancel ever ends the wedged call, and it is deferred rather than used.
	wedgedCtx, hangUp := context.WithCancel(context.Background())
	defer hangUp()

	// Far more output than the cap, so the cap is what decides where the last
	// chunk ends. Started, and then never read.
	wedged := helperReq("blocks", strconv.Itoa(32*sendBudget))
	wedged.MaxOutputBytes = sendBudget
	_, err := client.Exec(wedgedCtx, wedged)
	require.NoError(t, err)

	if !awaitFirstRecord(t, h, returned, transportFailsafe) {
		t.Logf("attempt %d: the output was cut so that the budget ran out before the last chunk, "+
			"so a copier parked rather than the terminal result; that is #72's case, retrying", attempt)
		return false
	}

	// Past the record the copiers are finished, so this can only be the
	// terminal Send — parked in grpc's own flow control, with nothing left in
	// the handler that could free it.
	require.Equal(t, "result", awaitParkedSend(transportFailsafe),
		"attempt %d: the command finished and was recorded, but its result went out anyway, "+
			"so %d bytes of output did not spend a %d-byte budget", attempt, sendBudget, sendBudget)

	// The recorded fact, at the only moment it is worth anything: the handler
	// is inside the Send it is never coming back from, and the slot it was
	// holding is already back.
	require.Equal(t, 0, h.svc.policy.InUse(),
		"attempt %d: the command has finished and its result is on its way out; the slot stands for nothing running", attempt)

	// What the slot is worth. The agent has exactly one, and a second call runs
	// on it start to finish while the first caller sits on its result.
	second, err := client.Exec(context.Background(), helperReq("echo", "second"))
	require.NoError(t, err)
	require.Equal(t, int32(0), drain(t, second).GetExitCode(),
		"attempt %d: a caller parked on its own result must not cost the next caller its capacity", attempt)

	// And the first was parked for all of that rather than caught in passing.
	// Exec ends with `return sink.sendResult(...)`, so a handler that has not
	// returned is a handler still inside that Send — and a whole command has
	// started, run and been reported since it went in.
	select {
	case err := <-returned:
		t.Fatalf("attempt %d: the wedged Exec returned %v while its terminal Send was still parked", attempt, err)
	default:
	}

	// Hanging up is what ends it, because ending the RPC is what tears the
	// stream down and releases the Send. Nothing else was ever going to.
	hangUp()
	require.Error(t, awaitHandlerReturn(t, attempt, returned),
		"attempt %d: the caller hung up before it read its result, so the result was not delivered", attempt)

	records := h.records(t)
	require.Len(t, records, 2, "attempt %d: both commands ran and both are recorded", attempt)
	require.Equal(t, policy.OutcomeOK, records[0].Outcome,
		"attempt %d: the wedged call ran a command that succeeded, and the record says so before the result goes out", attempt)
	require.True(t, records[0].Truncated,
		"attempt %d: the cap is what cut the output, which is what put the last chunk where the budget runs out", attempt)
	require.Equal(t, policy.OutcomeOK, records[1].Outcome)
	return true
}

// awaitHandlerReturn waits for one Exec handler to come back and returns what
// it returned.
func awaitHandlerReturn(t *testing.T, attempt int, returned <-chan error) error {
	t.Helper()
	select {
	case err := <-returned:
		return err
	case <-time.After(transportFailsafe):
		t.Fatalf("attempt %d: the handler did not return in %s after its caller hung up, "+
			"so ending the RPC did not release the Send", attempt, transportFailsafe)
		return nil
	}
}

// drain reads a stream to its end and returns the terminal result.
func drain(t *testing.T, stream sandboxdv1.ExecService_ExecClient) *sandboxdv1.ExecResult {
	t.Helper()
	var result *sandboxdv1.ExecResult
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			require.NotNil(t, result, "a stream that ended without a result is not a completed call")
			return result
		}
		require.NoError(t, err)
		if res := msg.GetResult(); res != nil {
			result = res
		}
	}
}
