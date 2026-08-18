package shell

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gopty "github.com/aymanbagabas/go-pty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	"github.com/axelmierczuk/fleet-mcp/internal/platform"
	"github.com/axelmierczuk/fleet-mcp/internal/security/policy"
)

// requirePTY skips a test on a host that cannot allocate a pseudo-terminal.
//
// There is one in CI and on every developer machine. A host without one is a
// container built without /dev/pts, and the honest answer there is to skip
// rather than to fail a test about a capability the machine does not have.
func requirePTY(t *testing.T) {
	t.Helper()
	if !platform.PTYSupported() {
		t.Skip("no pseudo-terminal available on this host")
	}
}

// openOptions builds a ShellOpen for the helper binary in the named mode.
func openOptions(mode string, args ...string) *sandboxdv1.ShellOpen {
	return &sandboxdv1.ShellOpen{
		Argv: selfArgv(args...),
		Env:  []string{helperEnvFor(mode)},
		Size: &sandboxdv1.ShellSize{Columns: 100, Rows: 40},
	}
}

// ---------------------------------------------------------------- a session

// TestSession_RunsACommandAndReportsItsExitCode is the shape of every other
// test here: a session opens, something runs on a terminal, and the status
// comes back as the stream's last message.
func TestSession_RunsACommandAndReportsItsExitCode(t *testing.T) {
	requirePTY(t)

	svc := newService(t, options{})
	client := serve(t, svc)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sess, err := openSession(ctx, t, client, openOptions("exit", "7"))
	require.NoError(t, err)

	exit := sess.awaitEnd()
	require.NotNil(t, exit, "a session that ran has to report how it ended")
	assert.Equal(t, int32(7), exit.GetExitCode())
	assert.False(t, exit.GetSignaled())
	assert.False(t, exit.GetIdleTimeout())

	// The terminal the session was given is named back, which is what lets an
	// operator match a session against what the host reports about itself.
	assert.NotEmpty(t, sess.opened.GetTerminal())
	assert.Positive(t, sess.opened.GetPid())

	rec := onlyRecord(t, svc)
	assert.Equal(t, policy.OutcomeOK, rec.Outcome)
	require.NotNil(t, rec.ExitCode)
	assert.Equal(t, int32(7), *rec.ExitCode)
}

// TestSession_CarriesTypingToTheProgramAndItsOutputBack is the round trip the
// whole feature is: bytes in one direction, bytes back the other, over one
// terminal.
func TestSession_CarriesTypingToTheProgramAndItsOutputBack(t *testing.T) {
	requirePTY(t)

	client := serve(t, newService(t, options{}))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sess, err := openSession(ctx, t, client, openOptions("cat"))
	require.NoError(t, err)
	sess.awaitOutput(catReady)

	require.NoError(t, sess.typedLine("hello-from-the-operator"))
	sess.awaitOutput("read[hello-from-the-operator]")

	require.NoError(t, sess.typedLine("quit"))
	exit := sess.awaitEnd()
	require.NotNil(t, exit)
	assert.Equal(t, int32(0), exit.GetExitCode())
}

// TestSession_ResizeReachesTheProgram covers the criterion a shell fails
// silently and completely without: a program that believes the terminal is
// 80x24 when it is not draws garbage in every full-screen view.
//
// The size is read by the program *inside* the session, through the same
// platform call the client reads the local terminal with, so this asserts the
// ioctl landed rather than that a message was sent.
func TestSession_ResizeReachesTheProgram(t *testing.T) {
	requirePTY(t)

	client := serve(t, newService(t, options{}))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sess, err := openSession(ctx, t, client, openOptions("winsize"))
	require.NoError(t, err)

	// The size named in the open, applied before the command started. A shell
	// that only applied resizes would draw its first screen at 80x24.
	sess.awaitOutput("size 100x40")

	require.NoError(t, sess.resize(120, 50))
	sess.awaitOutput("size 120x50")
}

// TestSession_InterruptByteReachesTheProgramRatherThanTheStream is the other
// half of "Ctrl-C interrupts the remote foreground process": on this side, the
// byte is delivered to the terminal and the session survives it.
//
// What the client does with Ctrl-C — never letting it become a local signal —
// is asserted in internal/cli/fleetctl. What the agent does is this: the byte
// goes to the terminal, whose line discipline turns it into a SIGINT for the
// foreground process group, and the program running there dies of it while the
// session and its stream stay up.
func TestSession_InterruptByteReachesTheProgramRatherThanTheStream(t *testing.T) {
	requirePTY(t)
	if runtime.GOOS == "windows" {
		t.Skip("this asserts on a SIGINT delivered by a terminal's line discipline; the ConPTY equivalent is a console control event and needs its own scenario")
	}

	client := serve(t, newService(t, options{}))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// A shell, deliberately, rather than the helper alone: the assertion is
	// about what a terminal does to a *foreground process group*, and that
	// needs something that puts a program in one. The helper is what runs in
	// it.
	//
	// Every string asserted on below is one a program printed, never one this
	// test typed. A terminal echoes its input, so a session's output contains
	// everything sent to it, and an assertion matching typed text would hold
	// for a session in which nothing ran at all.
	sess, err := openSession(ctx, t, client, &sandboxdv1.ShellOpen{
		Argv: []string{"/bin/sh"},
		Env:  []string{helperEnvFor("announce")},
		Size: &sandboxdv1.ShellSize{Columns: 100, Rows: 40},
	})
	require.NoError(t, err)

	require.NoError(t, sess.typedLine(strings.Join(selfArgv(), " ")))
	// The interrupt is sent only once the helper is the terminal's foreground
	// process. A Ctrl-C arriving while the shell is still parsing the line
	// interrupts nothing.
	sess.awaitOutput("foreground-running")

	require.NoError(t, sess.typed("\x03"))

	// A fresh command, and its answer. One assertion covers both halves of the
	// criterion and neither is reachable without the other: the shell only
	// reads this line once the program in front of it has ended, so an
	// interrupt that never arrived leaves it unread forever.
	//
	// It is a separate line rather than the tail of the one above, because what
	// a shell does with the *rest of a command list* after an interrupt is the
	// shell's own business — dash abandons it and bash carries on, and this
	// test is about the agent rather than about /bin/sh. The marker is
	// arithmetic, so the answer is something the far end computed rather than
	// something the terminal echoed back.
	require.NoError(t, sess.typedLine("echo after=$((21+21))"))
	sess.awaitOutput("after=42")

	// And the session itself is still there — the half that fails if an
	// interrupt is treated as anything other than a byte on the wire.
	require.NoError(t, sess.typedLine("exit 4"))
	exit := sess.awaitEnd()
	require.NotNil(t, exit)
	assert.Equal(t, int32(4), exit.GetExitCode(), "the shell should have exited on its own, after the interrupt reached only the program it was running")
}

// TestSession_AnInterruptByteReachesAConsoleProgram is the Windows half of the
// criterion above, and the platform where nothing else asserts it.
//
// The mechanics are not the Unix ones and the difference is the whole reason
// this exists. There is no line discipline: the byte reaches the pseudo-console,
// the console host raises a control event for the processes attached to it, and
// a process started with CREATE_NEW_PROCESS_GROUP has Ctrl-C disabled and never
// sees it. That flag is what
// [platform.ProcessGroup.ConfigureInteractivePTYCommand] exists to leave off,
// and the two configurations are identical on Unix — so a session started
// through the supervised one instead is a change no Unix test can see and this
// is the only thing that fails when it happens.
func TestSession_AnInterruptByteReachesAConsoleProgram(t *testing.T) {
	requirePTY(t)
	if runtime.GOOS != "windows" {
		t.Skip("a Unix session's interrupt is a SIGINT from the terminal's line discipline; TestSession_InterruptByteReachesTheProgramRatherThanTheStream covers it")
	}

	client := serve(t, newService(t, options{}))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sess, err := openSession(ctx, t, client, openOptions("interrupt"))
	require.NoError(t, err)

	// Only once the program is listening. An interrupt that arrives first ends
	// it by default, and this test would then be asserting on a race.
	sess.awaitOutput(interruptReady)

	require.NoError(t, sess.typed("\x03"))
	sess.awaitOutput(interruptSeen)

	// And the session survived it: an interrupt is something that happens
	// inside a session rather than something that ends one.
	exit := sess.awaitEnd()
	require.NotNil(t, exit)
	assert.Equal(t, int32(0), exit.GetExitCode())
	assert.False(t, exit.GetIdleTimeout())
}

// ------------------------------------------------------------- reaping

// TestSession_IdleTimeoutReapsAnAbandonedSession covers the bound that stops a
// forgotten terminal holding a shell open on somebody's machine forever.
func TestSession_IdleTimeoutReapsAnAbandonedSession(t *testing.T) {
	requirePTY(t)

	svc := newService(t, options{shell: agent.ShellConfig{IdleTimeout: agent.Duration(300 * time.Millisecond)}})
	client := serve(t, svc)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sess, err := openSession(ctx, t, client, openOptions("sleep"))
	require.NoError(t, err)

	exit := sess.awaitEnd()
	require.NotNil(t, exit, "a reaped session still has to tell the client what happened to it")
	assert.True(t, exit.GetIdleTimeout(), "the client has to be able to tell a reaping from the shell exiting")

	rec := onlyRecord(t, svc)
	assert.Equal(t, policy.OutcomeTimedOut, rec.Outcome)
	assert.True(t, rec.TimedOut)
}

// TestSession_ActivityKeepsAnIdleTimeoutAtBay is the other half of the same
// setting, and the one that matters to an operator: a session doing something
// is not abandoned, whichever direction the something is going in.
//
// Without it the timeout would be a stopwatch on the session rather than on its
// idleness, and a shell watching a long build would be killed for the crime of
// nobody typing.
func TestSession_ActivityKeepsAnIdleTimeoutAtBay(t *testing.T) {
	requirePTY(t)

	// Generous, and deliberately so. The interval between one line and the next
	// is what this proves the timeout is measured from, and the assertion holds
	// for any interval shorter than the timeout — so the margin between them
	// only has to be wider than a round trip through a pty and a gRPC stream on
	// a loaded machine. A tight one turns a test about idleness into a test
	// about scheduling, and it fails under -race first.
	const (
		idle     = 2 * time.Second
		interval = idle / 8
		keepFor  = 2 * idle
	)
	svc := newService(t, options{shell: agent.ShellConfig{IdleTimeout: agent.Duration(idle)}})
	client := serve(t, svc)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	sess, err := openSession(ctx, t, client, openOptions("cat"))
	require.NoError(t, err)
	sess.awaitOutput(catReady)

	// Typing for twice the timeout. Each line is answered, so both directions
	// are carrying bytes throughout.
	deadline := time.Now().Add(keepFor)
	for i := 0; time.Now().Before(deadline); i++ {
		require.NoError(t, sess.typedLine("still-here-"+strconv.Itoa(i)))
		sess.awaitOutput("read[still-here-" + strconv.Itoa(i) + "]")
		time.Sleep(interval)
	}

	require.NoError(t, sess.typedLine("quit"))
	exit := sess.awaitEnd()
	require.NotNil(t, exit)
	assert.False(t, exit.GetIdleTimeout(), "a session that carried data throughout was reaped as idle")
	assert.Equal(t, int32(0), exit.GetExitCode())
}

// TestSession_OutputAloneKeepsAnIdleTimeoutAtBay is the half of that setting
// which the test above cannot see, and which is the one an operator loses a
// job to.
//
// "Either direction" is the promise — ShellConfig.IdleTimeout says so,
// docs/security.md says so, and session.activity says so — and the whole point
// of it is the session where only one direction is carrying anything: an
// operator watching a long build types nothing for an hour while the build
// prints continuously. The test above types *and* reads, so it holds with the
// output half of the clock deleted; this one does not, because nothing here
// ever types.
func TestSession_OutputAloneKeepsAnIdleTimeoutAtBay(t *testing.T) {
	requirePTY(t)

	// Same margins, and for the same reason, as the test above: the assertion
	// holds for any interval shorter than the timeout, so the gap between them
	// only has to be wider than a round trip through a pty and a gRPC stream on
	// a loaded machine.
	const (
		idle     = 2 * time.Second
		interval = idle / 8
		keepFor  = 2 * idle
	)
	svc := newService(t, options{shell: agent.ShellConfig{IdleTimeout: agent.Duration(idle)}})
	client := serve(t, svc)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	sess, err := openSession(ctx, t, client,
		openOptions("tick", strconv.FormatInt(interval.Milliseconds(), 10)))
	require.NoError(t, err)

	// A line the helper can only have printed after twice the idle timeout had
	// passed, so a session reaped on time never produces it. Nothing is typed
	// at the session between opening it and this arriving: the only thing
	// keeping it alive is what it is printing.
	sess.awaitOutput("tick " + strconv.Itoa(int(keepFor/interval)))

	select {
	case <-sess.done:
		t.Fatalf("the session ended while its program was still printing: %s", sess.state())
	default:
	}
}

// TestAwait_IdleIsMeasuredFromTheLastByteRatherThanFromTheStart is the same
// property without a terminal, and it is the one that cannot go flaky: it
// asserts a lower bound on when the reaping happened, and a lower bound can
// only fail if the code gave up too early — which is the bug.
func TestAwait_IdleIsMeasuredFromTheLastByteRatherThanFromTheStart(t *testing.T) {
	const (
		idle  = 200 * time.Millisecond
		busy  = 5 * idle
		touch = idle / 4
	)

	svc := &Service{idleTimeout: idle, log: slog.New(slog.DiscardHandler)}
	sess := &session{}
	sess.touch()

	// Nothing ever arrives on this channel: the session's command does not
	// exit, so idleness is the only thing that can end this wait.
	waited := make(chan error, 1)

	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(touch)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				sess.touch()
			}
		}
	}()
	time.AfterFunc(busy, func() { close(stop) })

	started := time.Now()
	reason, reaped := svc.await(context.Background(), sess, waited)
	elapsed := time.Since(started)

	assert.Equal(t, endIdle, reason)
	assert.False(t, reaped)
	assert.GreaterOrEqual(t, elapsed, busy,
		"the session was reaped %s in, while it was still carrying data; the timeout is being measured from the session's start rather than from its last byte", elapsed)
}

// pidLine matches the identity each level of the helper tree prints.
var pidLine = regexp.MustCompile(`(?m)pid (\d+)`)

// TestSession_ClosingTheStreamKillsTheWholeTree is the guarantee that keeps a
// disconnected session from leaving processes behind on somebody's machine.
//
// A shell is a process spawner by definition, so "the session ended" has to
// mean the tree ended. The assertion is on the pids the tree reported for
// itself, which is what makes it about the processes rather than about the
// agent's opinion of them.
func TestSession_ClosingTheStreamKillsTheWholeTree(t *testing.T) {
	requirePTY(t)

	svc := newService(t, options{})
	client := serve(t, svc)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sess, err := openSession(ctx, t, client, openOptions("tree"))
	require.NoError(t, err)

	// Both levels have to have announced themselves before the stream closes,
	// or the assertion below is about one process and the grandchild — the one
	// a group kill exists for — is never looked at.
	var pids []int
	waitFor(t, "both levels of the tree to announce themselves", func() (bool, string) {
		pids = parsePIDs(t, sess.printed())
		if len(pids) == 2 {
			return true, ""
		}
		return false, "so far: " + sess.printed()
	})

	// The client hanging up, which is what a closed terminal window or a killed
	// fleetctl looks like from here.
	cancel()

	for _, pid := range pids {
		waitFor(t, "pid "+strconv.Itoa(pid)+" to be gone", func() (bool, string) {
			if !processRunning(pid) {
				return true, ""
			}
			return false, "pid " + strconv.Itoa(pid) + " outlived the session that started it"
		})
	}

	rec := onlyRecord(t, svc)
	assert.Equal(t, policy.OutcomeCancelled, rec.Outcome)
}

// TestSession_AProgramThatIgnoresTheHangupIsStillKilled covers the second half
// of the teardown.
//
// Closing the terminal is the polite half and does most of the work, but it can
// be ignored — and a guarantee that can be declined is not one. This asserts
// the kill that follows it.
func TestSession_AProgramThatIgnoresTheHangupIsStillKilled(t *testing.T) {
	requirePTY(t)
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no deliverable hangup for a program to ignore; the job object is what ends a session there, and internal/platform tests it")
	}

	svc := newService(t, options{shell: agent.ShellConfig{IdleTimeout: agent.Duration(300 * time.Millisecond)}})
	client := serve(t, svc)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sess, err := openSession(ctx, t, client, openOptions("ignore-hup"))
	require.NoError(t, err)
	pid := int(sess.opened.GetPid())

	// Reaped for idleness, since nothing is typing at it.
	exit := sess.awaitEnd()
	require.NotNil(t, exit)
	assert.True(t, exit.GetIdleTimeout())

	waitFor(t, "the process that ignored its hangup to be killed", func() (bool, string) {
		if !processRunning(pid) {
			return true, ""
		}
		return false, "pid " + strconv.Itoa(pid) + " ignored the hangup and survived the kill that should have followed"
	})
}

// TestSession_TheTerminalIsClosedExactlyOnce pins the guard that keeps the
// agent's own heap intact.
//
// A reaped session hangs its terminal up and then releases it, so two paths
// reach the close. go-pty's Unix implementation makes the second one a no-op;
// its ConPTY implementation calls ClosePseudoConsole unconditionally, which
// destroys a console object that is already gone and corrupts the process heap.
// That reached CI as an 0xC0000374 with no stack and no failing assertion,
// which is the worst shape a bug can arrive in — so the guard gets a test that
// names it rather than a comment alone.
func TestSession_TheTerminalIsClosedExactlyOnce(t *testing.T) {
	fake := &countingPTY{}
	tty := newSessionTerminal(fake, slog.New(slog.DiscardHandler))

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = tty.Close()
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), fake.closes.Load(),
		"the terminal was closed more than once; on Windows the second one takes the agent's heap with it")
}

// TestSession_ATerminalIsNeverResizedAfterItIsClosed pins the other half of
// the same hazard, and the half a close guard alone does not cover.
//
// Closing a pseudo-console frees it; go-pty's ConPTY Resize then hands that
// freed handle to ResizePseudoConsole, which is the same use-after-free one
// call along — and worse, because Windows reissues handle values, so the
// number can by then name an object something else owns. The input pump is not
// joined before teardown, so a resize arriving while a session is being reaped
// is what a person dragging their window during a reconnect produces rather
// than a thought experiment.
func TestSession_ATerminalIsNeverResizedAfterItIsClosed(t *testing.T) {
	fake := &countingPTY{}
	tty := newSessionTerminal(fake, slog.New(slog.DiscardHandler))

	require.NoError(t, tty.Resize(100, 40))
	require.Equal(t, int32(1), fake.resizes.Load(), "a resize before the close has to reach the terminal")

	require.NoError(t, tty.Close())

	err := tty.Resize(120, 50)
	require.ErrorIs(t, err, errTerminalGone)
	assert.Equal(t, int32(1), fake.resizes.Load(),
		"a resize reached a terminal that had already been released; on Windows that is ResizePseudoConsole against a freed console")
}

// TestSession_AResizeRacingTheCloseNeverReachesAFreedTerminal is the same
// property under the concurrency it actually happens under: the input pump
// resizing while the reaper closes.
//
// The fake fails the test from inside the terminal rather than after it, which
// is the only way to catch an ordering that a counter read afterwards would
// have already lost.
func TestSession_AResizeRacingTheCloseNeverReachesAFreedTerminal(t *testing.T) {
	fake := &countingPTY{}
	tty := newSessionTerminal(fake, slog.New(slog.DiscardHandler))

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 200 {
			_ = tty.Resize(100, 40)
		}
	}()
	go func() {
		defer wg.Done()
		_ = tty.Close()
	}()
	wg.Wait()

	assert.Zero(t, fake.afterClose.Load(),
		"a resize reached the terminal after it had been closed")
}

// TestSession_TheInputPumpGoesThroughTheGuardedTerminal is the missing half of
// the two tests above, and the half this repository keeps leaving out.
//
// Those two assert what [sessionTerminal] does when it is asked. Nothing
// asserted that the code which does the asking asks *it*: replacing
// s.tty.Resize with s.tty.PTY.Resize in [session.pumpInput] — one embedded
// field, no compile error, no failing test — puts back round one's
// use-after-free in full, and the platform where it matters reports it as a
// corrupted heap with no stack rather than as a failure.
//
// The same line is the only caller of [sizeOf] on the resize path, so the clamp
// is asserted here too: an unclamped 70000 columns is not a wide terminal, it
// is a four-column one, arrived at silently inside the ioctl's 16-bit
// conversion.
func TestSession_TheInputPumpGoesThroughTheGuardedTerminal(t *testing.T) {
	fake := &countingPTY{}
	tty := newSessionTerminal(fake, slog.New(slog.DiscardHandler))
	sess := &session{svc: &Service{log: slog.New(slog.DiscardHandler)}, tty: tty}

	sess.pumpInput(scripted(resizeTo(70000, 1<<20)))
	require.Equal(t, int32(1), fake.resizes.Load(), "a resize from the client never reached the terminal at all")
	assert.Equal(t, windowSize{columns: maxDimension, rows: maxDimension}, fake.size(),
		"the client's exaggerated size reached the platform unclamped")

	// And once the terminal has gone, the pump's resize is refused rather than
	// handed to a freed pseudo-console.
	require.NoError(t, tty.Close())
	sess.pumpInput(scripted(resizeTo(120, 50)))

	assert.Equal(t, int32(1), fake.resizes.Load(),
		"a resize from the client reached a terminal that had already been released")
	assert.Zero(t, fake.afterClose.Load(),
		"the input pump resized the terminal after the teardown had released it")
}

// TestSession_TheOutputPumpGoesThroughTheSender is the same omission on the
// other pump.
//
// [sender] is what keeps a ShellExit the last message on the stream — the wire
// contract shell.proto states — and [TestSender_NothingFollowsTheSessionsExit]
// asserts that it does. Nothing asserted that the pump uses it: sending on the
// stream directly compiles, passes, and breaks the contract for every client,
// because the pump is deliberately not joined before the exit goes out and on
// Windows it is still reading by definition.
func TestSession_TheOutputPumpGoesThroughTheSender(t *testing.T) {
	stream := &recordingStream{}
	send := newSender(stream)
	require.NoError(t, send.within(time.Second, exit(&sessionAudit{}, false)))

	sess := &session{
		svc:  &Service{log: slog.New(slog.DiscardHandler)},
		tty:  newSessionTerminal(&sayingPTY{say: []byte("output after the exit")}, slog.New(slog.DiscardHandler)),
		send: send,
	}
	sess.pumpOutput()

	assert.Equal(t, []string{"exit"}, stream.kinds(),
		"the output pump reached the stream without going through the sender, so terminal output followed the session's exit")
}

// scripted is a stream that delivers reqs and then ends, which is what a client
// half-closing looks like to [session.pumpInput].
func scripted(reqs ...*sandboxdv1.ShellRequest) *scriptedStream {
	return &scriptedStream{reqs: reqs}
}

func resizeTo(columns, rows uint32) *sandboxdv1.ShellRequest {
	return &sandboxdv1.ShellRequest{
		Event: &sandboxdv1.ShellRequest_Resize{Resize: &sandboxdv1.ShellSize{Columns: columns, Rows: rows}},
	}
}

type scriptedStream struct {
	grpc.ServerStream

	reqs []*sandboxdv1.ShellRequest
	at   int
}

func (s *scriptedStream) Recv() (*sandboxdv1.ShellRequest, error) {
	if s.at >= len(s.reqs) {
		return nil, io.EOF
	}
	s.at++
	return s.reqs[s.at-1], nil
}

func (s *scriptedStream) Send(*sandboxdv1.ShellResponse) error { return nil }

// sayingPTY prints once and then reports the hangup, which is a terminal whose
// last process has gone.
type sayingPTY struct {
	countingPTY

	say  []byte
	said bool
}

func (p *sayingPTY) Read(b []byte) (int, error) {
	if p.said {
		return 0, io.EOF
	}
	p.said = true
	return copy(b, p.say), nil
}

// countingPTY is a pseudo-terminal that never allocates anything, and reports
// what was done to it after it was closed.
//
// A fake rather than a real pty, deliberately: what is being asserted is that
// a call does *not* reach the platform, and on the platform where that matters
// the consequence of it reaching is a corrupted heap rather than an error
// anything could observe.
type countingPTY struct {
	closes     atomic.Int32
	resizes    atomic.Int32
	afterClose atomic.Int32
	closed     atomic.Bool
	columns    atomic.Int32
	rows       atomic.Int32
}

func (p *countingPTY) Read([]byte) (int, error) { return 0, io.EOF }
func (p *countingPTY) Write(b []byte) (int, error) {
	return len(b), nil
}

func (p *countingPTY) Close() error {
	p.closes.Add(1)
	p.closed.Store(true)
	return nil
}

func (p *countingPTY) Resize(columns, rows int) error {
	if p.closed.Load() {
		p.afterClose.Add(1)
	}
	p.resizes.Add(1)
	p.columns.Store(int32(columns)) //nolint:gosec // a test's own bounded dimensions
	p.rows.Store(int32(rows))       //nolint:gosec // as above
	return nil
}

// size is the last window the terminal was given.
func (p *countingPTY) size() windowSize {
	return windowSize{columns: int(p.columns.Load()), rows: int(p.rows.Load())}
}

func (p *countingPTY) Name() string                         { return "counting-pty" }
func (p *countingPTY) Fd() uintptr                          { return 0 }
func (p *countingPTY) Command(string, ...string) *gopty.Cmd { return nil }
func (p *countingPTY) CommandContext(context.Context, string, ...string) *gopty.Cmd {
	return nil
}

// TestSession_AChildIsReapedEvenWhenTheOpenCannotBeDelivered covers the one
// path out of the handler that runs after a command exists and before anything
// is waiting for it.
//
// The ShellOpened send is the last thing between starting the session's process
// and the goroutine that waits on it. A handler that returns from there without
// ever calling Wait leaves the child killed by the teardown and unreaped by
// anyone — a zombie in the daemon's own process table, for the life of the
// daemon, one per session whose caller hung up at the wrong instant. A caller
// that opens streams and drops them is not an exotic client; it is a script
// with a loop in it.
//
// Unix only, because the zombie is. On Windows an unwaited child leaves a
// handle rather than a process-table entry, and go-pty leaks a handle of its
// own to every session's process regardless of what this agent does, so there
// is nothing there for an assertion to distinguish.
func TestSession_AChildIsReapedEvenWhenTheOpenCannotBeDelivered(t *testing.T) {
	requirePTY(t)
	if runtime.GOOS == "windows" {
		t.Skip("a child nobody waits on is a zombie on Unix; on Windows it is a leaked handle that go-pty leaks anyway")
	}

	svc := newService(t, options{})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var rec sessionAudit
	spec, err := svc.plan(openOptions("sleep"), &rec)
	require.NoError(t, err)

	stream := &refusingStream{ctx: ctx, sendFail: errors.New("the caller went away mid-handshake")}
	require.Error(t, svc.run(ctx, stream, spec, &rec))

	pid := stream.openedPID()
	require.Positive(t, pid, "the session never started a process, so this test would prove nothing")

	waitFor(t, "the session's own process to be reaped", func() (bool, string) {
		if !platform.ProcessExists(pid) {
			return true, ""
		}
		return false, "pid " + strconv.Itoa(pid) + " is still in the process table; the handler killed its child and never waited on it"
	})
}

// TestSession_TheTerminalIsDrainedEvenWhenTheClientHasStoppedReading is the
// fourth ConPTY lifetime hazard on this branch, and the one that does not
// announce itself as a memory bug.
//
// Closing a pseudo-console asks the console host to flush what it is still
// holding, and that flush needs a reader on the output pipe. The only reader is
// [session.pumpOutput], and a pump that stopped the instant a send failed — one
// dropped connection is all that takes — left [Service.reap] closing a terminal
// nobody was draining. Close is the *first* statement of the teardown, so a
// handler stuck there never reaches the group kill: the RPC never returns, its
// process slot is never released, its record is never written, and the tree the
// close was meant to end is still running.
//
// The assertion is platform-neutral and holds on every one of the three,
// because the same undrained terminal stops the session's own program on Unix
// too: a program whose writes block never exits, and the only way this session
// can end with the status the flood helper chose is if something kept reading.
func TestSession_TheTerminalIsDrainedEvenWhenTheClientHasStoppedReading(t *testing.T) {
	requirePTY(t)

	// Short, so that the failure is a session reaped for idleness within
	// seconds rather than one that hangs until the suite's own timeout.
	svc := newService(t, options{shell: agent.ShellConfig{IdleTimeout: agent.Duration(3 * time.Second)}})
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	var rec sessionAudit
	spec, err := svc.plan(openOptions("flood"), &rec)
	require.NoError(t, err)

	// A client that took the handshake and then stopped reading, which is what
	// a dropped connection looks like from inside the handler.
	stream := &refusingStream{
		ctx:       ctx,
		allowOpen: true,
		sendFail:  errors.New("the caller stopped reading its session stream"),
	}
	// The RPC ends in error either way — there is nobody left to deliver the
	// exit to — so it is the record that says how the session ended.
	_ = svc.run(ctx, stream, spec, &rec)

	require.NotNilf(t, rec.exitCode,
		"the session never reported an exit status; it ended as %q (idle=%v), which means its program was still blocked writing to a terminal nobody was draining",
		rec.outcome, rec.idle)
	assert.Equal(t, int32(floodExit), *rec.exitCode,
		"the session's program did not run to completion behind a client that had stopped reading")
	assert.False(t, rec.idle, "the session was reaped for idleness rather than ending when its program did")
	assert.Equal(t, policy.OutcomeOK, rec.outcome)
}

// TestSession_TheLastOutputArrivesBeforeTheExitStatus covers the wait between
// a session's command finishing and its status going out.
//
// A shell prints on its way out — "logout", a job-control warning, whatever the
// last command left in the buffer — and a terminal does not stop producing the
// moment the process behind it does. On Windows it emphatically does not: a
// ConPTY's output pipe stays open until the pseudo-console is closed, so the
// wait there is the only thing between the operator and a farewell they never
// see. [sender] refuses everything after the exit, so a farewell that arrives
// at all is one that arrived before it; there is nothing else to order.
//
// The terminal is one that still has something to say a moment after its
// command has gone, which is the Windows behaviour staged on a platform that
// does not have it — and staged as a delay rather than a race, so that a build
// without the wait fails every time rather than most times.
func TestSession_TheLastOutputArrivesBeforeTheExitStatus(t *testing.T) {
	requirePTY(t)

	const farewell = "logout-after-the-command-had-already-gone"
	svc := newService(t, options{openPTY: lingeringPTY([]byte(farewell))})
	client := serve(t, svc)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sess, err := openSession(ctx, t, client, openOptions("exit", "0"))
	require.NoError(t, err)

	exit := sess.awaitEnd()
	require.NotNil(t, exit, "the session never reported its status")
	assert.Equal(t, int32(0), exit.GetExitCode())
	assert.Contains(t, sess.printed(), farewell,
		"the session's last output was dropped: its exit status went out while the terminal still had something to give, "+
			"and nothing may follow a ShellExit")
}

// farewellDelay is how long the terminal below waits before its last words.
// Well inside drainAfterExit, so the wait is what decides this rather than the
// machine's load.
const farewellDelay = 25 * time.Millisecond

// lingeringPTY allocates a real terminal that still has something to say a
// moment after its command has ended.
func lingeringPTY(say []byte) func() (platform.PTY, error) {
	return func() (platform.PTY, error) {
		raw, err := platform.OpenPTY()
		if err != nil {
			return nil, err
		}
		return &lastWordPTY{PTY: raw, say: say}, nil
	}
}

// lastWordPTY reads as the real terminal does until that read ends, and then
// produces one more chunk before ending itself.
//
// Read is called only by the session's output pump, one goroutine, so the flag
// needs no lock.
type lastWordPTY struct {
	platform.PTY

	say  []byte
	said bool
}

func (p *lastWordPTY) Read(b []byte) (int, error) {
	n, err := p.PTY.Read(b)
	if err == nil || p.said {
		return n, err
	}
	p.said = true
	time.Sleep(farewellDelay)
	return copy(b, p.say), nil
}

// TestSession_ATeardownIsNotHeldUpByATerminalThatWillNotClose is the fifth
// ConPTY lifetime hazard on this branch, and the one the fourth's fix does not
// reach.
//
// Closing a pseudo-console does not return until the console host's remaining
// output has somewhere to go, and the only reader is [session.pumpOutput]. That
// pump keeps reading after a send *fails*, which is what a caller hanging up
// produces. It cannot help with a send that neither fails nor returns: a client
// that is still connected and has stopped reading parks the pump inside gRPC's
// flow control for as long as it stays that way, which is the state [sender]'s
// own deadline exists to survive. A teardown that waited for the close would
// then park at its first statement — no group kill, no released process slot,
// no audit record, no end to the RPC, and the process tree the close was
// supposed to end still running.
//
// So the close is started and not waited for, and this asserts the things below
// it in the teardown rather than the close itself. The terminal is one whose
// close never returns, which is the only way to stage on Unix what
// ClosePseudoConsole does on Windows — the same reasoning that makes the drain
// test above platform-neutral, approached from the other side.
func TestSession_ATeardownIsNotHeldUpByATerminalThatWillNotClose(t *testing.T) {
	requirePTY(t)

	// Released at the very end, so the session's own goroutines can finish
	// whichever way this test went. Registered after the service and the server
	// so that it is the first cleanup to run.
	stalled := make(chan struct{})

	svc := newService(t, options{
		shell:   agent.ShellConfig{IdleTimeout: agent.Duration(300 * time.Millisecond)},
		openPTY: stallingClosePTY(stalled),
	})
	client := serve(t, svc)
	t.Cleanup(func() { close(stalled) })

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sess, err := openSession(ctx, t, client, openOptions("sleep"))
	require.NoError(t, err)
	pid := int(sess.opened.GetPid())

	// The kill: the guarantee the teardown exists to make, and the first thing
	// below the close.
	waitFor(t, "the reaped session's process to be killed", func() (bool, string) {
		if !processRunning(pid) {
			return true, ""
		}
		return false, "pid " + strconv.Itoa(pid) + " is still running: the teardown never got past closing a terminal that would not close"
	})

	// And the RPC ended, which is what releases its process slot and is the
	// only reason there is a record to read at all.
	rec := onlyRecord(t, svc)
	assert.Equal(t, policy.OutcomeTimedOut, rec.Outcome)
	assert.True(t, rec.TimedOut)

	// The close really was still outstanding while all of that happened, rather
	// than the fake having quietly let it through.
	assert.False(t, closedNow(stalled),
		"the terminal's close finished on its own, so this proved nothing about a teardown that has to survive one that does not")
}

// closedNow reports whether ch has been closed, without blocking on it.
func closedNow(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// stallingClosePTY allocates a real terminal whose Close does not return until
// blocked is closed — a pseudo-console with nobody draining it, on platforms
// that have no such thing.
func stallingClosePTY(blocked <-chan struct{}) func() (platform.PTY, error) {
	return func() (platform.PTY, error) {
		raw, err := platform.OpenPTY()
		if err != nil {
			return nil, err
		}
		return &stallingPTY{PTY: raw, blocked: blocked}, nil
	}
}

// stallingPTY is that terminal. Everything except Close is the real one's, so
// the session it carries is a real session: a command runs on it, its output is
// read from it, and its process group is the platform's.
type stallingPTY struct {
	platform.PTY
	blocked <-chan struct{}
}

func (p *stallingPTY) Close() error {
	<-p.blocked
	return p.PTY.Close()
}

// TestSender_NothingFollowsTheSessionsExit pins the wire contract shell.proto
// states and serialisation alone does not keep: a ShellExit is the last message
// on the stream.
//
// The two senders take turns, which is what gRPC requires, and taking turns is
// not ordering: the output pump is not joined before the exit is sent, and on
// Windows it is still running by definition — a ConPTY's output pipe does not
// end when the session's command does, so the wait before the exit is a bounded
// drain rather than a join. Whatever the pump reads next would otherwise go out
// behind the terminal message, to a client the contract entitles to have
// stopped reading at it.
//
// Asserted against [sender] rather than through a session, and the reason is
// the same as the reason the hazard is Windows-shaped: on Unix the terminal
// stops producing when the session's command does, so the sequence cannot be
// staged from a test that has to pass on all three. This is the only path to
// Send in the package — [session.send] is one of these, built by
// [Service.run] — so there is no second route for a message to take.
func TestSender_NothingFollowsTheSessionsExit(t *testing.T) {
	stream := &recordingStream{}
	send := newSender(stream)

	require.NoError(t, send.within(time.Second, data([]byte("before"))))
	require.NoError(t, send.within(time.Second, exit(&sessionAudit{}, false)))

	err := send.within(time.Second, data([]byte("after")))
	require.ErrorIs(t, err, errAfterExit)

	assert.Equal(t, []string{"data", "exit"}, stream.kinds(),
		"a message reached the stream after the session had reported how it ended")
}

// recordingStream keeps the shape of everything sent on it, in order.
//
// Nothing receives on it: the sender is the send half and nothing else, and an
// embedded nil ServerStream means anything this fake does not implement panics
// with the method's name rather than standing in for more of gRPC than it is.
type recordingStream struct {
	grpc.ServerStream

	mu   sync.Mutex
	sent []string
}

func (s *recordingStream) Recv() (*sandboxdv1.ShellRequest, error) { return nil, io.EOF }

func (s *recordingStream) Send(resp *sandboxdv1.ShellResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case resp.GetOpened() != nil:
		s.sent = append(s.sent, "opened")
	case resp.GetExit() != nil:
		s.sent = append(s.sent, "exit")
	default:
		s.sent = append(s.sent, "data")
	}
	return nil
}

func (s *recordingStream) kinds() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.sent...)
}

// TestSender_SerialisesTheHandlerAndTheOutputPump pins the property [sender]
// exists for, and which nothing else in this package can observe.
//
// A session has two senders on one stream — the output pump continuously, and
// the handler for the opened and exit messages — and gRPC is explicit that one
// goroutine may send while another receives but that two may not send. The
// client half of this session has the same shape and the same fix; this is the
// agent's.
//
// The stream reports the overlap from inside Send rather than leaving it to be
// counted afterwards: a tally read at the end cannot tell an interleaving that
// happened from one that did not.
func TestSender_SerialisesTheHandlerAndTheOutputPump(t *testing.T) {
	stream := &overlappingStream{}
	send := newSender(stream)

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				_ = send.within(30*time.Second, data([]byte("output")))
			}
		}()
	}
	wg.Wait()

	assert.Zero(t, stream.overlaps.Load(),
		"two goroutines were inside Send on the same stream at once; gRPC does not permit that")
}

// TestSender_GivesUpOnAStreamNobodyIsReading is the liveness half, and it is
// the reason the lock is a channel with a deadline rather than a mutex.
//
// A client that is still connected but has stopped reading parks the output
// pump inside Send. A handler queued behind a plain mutex would then wait there
// forever with a session that has already ended — no exit message, no audit
// record, no released process slot, and an RPC that only ends when the process
// does.
func TestSender_GivesUpOnAStreamNobodyIsReading(t *testing.T) {
	stream := &stallingStream{blocked: make(chan struct{})}
	t.Cleanup(func() { close(stream.blocked) })
	send := newSender(stream)

	parked := make(chan struct{})
	go func() {
		close(parked)
		_ = send.within(30*time.Second, data([]byte("output")))
	}()
	<-parked

	waitFor(t, "the stalled send to be holding the stream", func() (bool, string) {
		if stream.inFlight.Load() > 0 {
			return true, ""
		}
		return false, "nothing is inside Send yet"
	})

	// In a goroutine with a bound of its own, so that the failure is a test
	// saying what went wrong rather than a suite hitting its timeout — which is
	// exactly the shape the bug has in production.
	result := make(chan error, 1)
	go func() { result <- send.within(250*time.Millisecond, exit(&sessionAudit{}, false)) }()

	select {
	case err := <-result:
		require.Error(t, err, "a send behind a parked one reported success on a stream it never reached")
		assert.Equal(t, codes.Aborted, status.Code(err),
			"a caller has to be able to tell a stream nobody is reading from a session that failed")
	case <-time.After(30 * time.Second):
		t.Fatal("a send queued behind a parked one never gave up; the handler's exit message would wait there " +
			"for as long as the client stayed connected and silent, holding the RPC and its process slot open")
	}
}

// overlappingStream notices two senders at once. Send holds the stream for a
// moment rather than returning immediately, which is what makes the overlap
// observable: a real gRPC send marshals, takes the transport's write path and
// can block on flow control, so an unserialised pair overlaps in production for
// far longer than this.
type overlappingStream struct {
	grpc.ServerStream

	inFlight atomic.Int32
	overlaps atomic.Int32
}

func (s *overlappingStream) Recv() (*sandboxdv1.ShellRequest, error) { return nil, io.EOF }

func (s *overlappingStream) Send(*sandboxdv1.ShellResponse) error {
	if s.inFlight.Add(1) > 1 {
		s.overlaps.Add(1)
	}
	time.Sleep(100 * time.Microsecond)
	s.inFlight.Add(-1)
	return nil
}

// stallingStream is a client that is still connected and has stopped reading:
// its Send never returns until the test lets it.
type stallingStream struct {
	grpc.ServerStream

	blocked  chan struct{}
	inFlight atomic.Int32
}

func (s *stallingStream) Recv() (*sandboxdv1.ShellRequest, error) { return nil, io.EOF }

func (s *stallingStream) Send(*sandboxdv1.ShellResponse) error {
	s.inFlight.Add(1)
	defer s.inFlight.Add(-1)
	<-s.blocked
	return nil
}

// ------------------------------------------------------------- the limit

// TestSession_WaitsForASlotInTheAgentWideProcessLimit covers the cap this
// service shares with every other way the agent starts a process.
//
// A session is one process by the agent's accounting and any number by the
// host's, and the slot is held for the whole session rather than for the moment
// it starts — a terminal that has been open for an hour is still a process this
// agent started. Without it a fleet of operators could start more shells than
// the agent's own limit allows and the cap would apply to everything except the
// service most able to exhaust the machine.
//
// The assertion is that the second session never opens, which is the fact an
// operator would notice: the first holds the only slot, and the second waits
// for it until its caller gives up.
func TestSession_WaitsForASlotInTheAgentWideProcessLimit(t *testing.T) {
	requirePTY(t)

	svc := newService(t, options{maxConcurrent: 1})
	client := serve(t, svc)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	held, err := openSession(ctx, t, client, openOptions("sleep"))
	require.NoError(t, err)
	require.NotNil(t, held.opened, "the session holding the slot never started")

	// The second caller waits rather than being refused: a slot may come free,
	// and acquireTimeout is what bounds the wait. This one gives up first,
	// which is the shape a person pressing Ctrl-C on a hung command produces.
	waitingCtx, giveUp := context.WithCancel(ctx)
	time.AfterFunc(time.Second, giveUp)
	defer giveUp()

	_, err = openSession(waitingCtx, t, client, openOptions("sleep"))
	require.Error(t, err, "a second session started while the agent's only process slot was held")

	// And the reason is recorded as what it was, rather than as a session that
	// ran and was cancelled.
	var waited *policy.Record
	waitFor(t, "the refused session to reach the audit log", func() (bool, string) {
		for _, rec := range records(t, svc) {
			if strings.Contains(rec.Error, "free process slot") {
				waited = &rec
				return true, ""
			}
		}
		return false, "no record of a session that waited for a slot yet"
	})
	assert.Equal(t, policy.OutcomeCancelled, waited.Outcome)
}

// -------------------------------------------------------------- the size

// TestSizeOf_FillsInTheDefaultAndClampsTheExaggerated covers both halves of a
// window size a client got wrong, neither of which is an error.
//
// The default matters because a terminal told it has no rows draws nothing at
// all, so a client that cannot read its own size is better served by 80x24 it
// can resize than by a refusal. The clamp matters because the ioctl underneath
// takes unsigned 16-bit fields: an unclamped 70000 columns is not a wide
// terminal, it is a four-column one, arrived at silently inside a conversion.
func TestSizeOf_FillsInTheDefaultAndClampsTheExaggerated(t *testing.T) {
	t.Parallel()

	assert.Equal(t, windowSize{columns: defaultColumns, rows: defaultRows}, sizeOf(nil),
		"a client that sent no size has to get a usable terminal rather than a zero-sized one")
	assert.Equal(t, windowSize{columns: defaultColumns, rows: 50},
		sizeOf(&sandboxdv1.ShellSize{Rows: 50}), "each dimension defaults on its own")
	assert.Equal(t, windowSize{columns: 120, rows: 40},
		sizeOf(&sandboxdv1.ShellSize{Columns: 120, Rows: 40}))

	huge := sizeOf(&sandboxdv1.ShellSize{Columns: 70000, Rows: 1 << 20})
	assert.Equal(t, windowSize{columns: maxDimension, rows: maxDimension}, huge,
		"an exaggerated size was passed through to an ioctl that takes 16 bits, where it wraps into a small one")
}

// TestPlan_AppliesTheSizeRulesToTheOpeningWindow is the caller of the above.
//
// Everything TestSizeOf asserts holds of a function; this asserts that the size
// a session opens with is the one that function returned. Reading the client's
// numbers straight off the ShellOpen instead compiles and passes, and is the
// same omission the input pump had on the resize path.
func TestPlan_AppliesTheSizeRulesToTheOpeningWindow(t *testing.T) {
	t.Parallel()

	svc := newService(t, options{})

	var rec sessionAudit
	spec, err := svc.plan(&sandboxdv1.ShellOpen{
		Argv: selfArgv(),
		Env:  []string{helperEnvFor("exit")},
		Size: &sandboxdv1.ShellSize{Columns: 70000},
	}, &rec)
	require.NoError(t, err)
	assert.Equal(t, windowSize{columns: maxDimension, rows: defaultRows}, spec.size,
		"a session opened at the size the client asked for rather than at the one the rules allow")
}

// ---------------------------------------------------------------- leaks

// TestSession_NoGoroutineLeakAcrossManySessions is the counterpart of
// ForwardService's, for a service with the same shape and one more goroutine
// per stream.
//
// A session is three goroutines and a pseudo-terminal: the input pump, the
// output pump, and the wait. None of the three is joined by the handler, on
// purpose — the input pump is parked in Recv and only the handler returning
// unblocks it — so "they end" is an argument rather than something the code
// makes obvious, and an argument about goroutine lifetimes is exactly the kind
// that stays true right up until it does not. The failure it guards against is
// an agent that slowly stops working on a host nobody is watching.
//
// Both endings are driven, because they end the pumps differently: a session
// whose command exits, and a caller that hangs up on a session that is still
// running.
func TestSession_NoGoroutineLeakAcrossManySessions(t *testing.T) {
	requirePTY(t)

	const (
		exited    = 5
		cancelled = 5
	)

	svc := newService(t, options{})
	client := serve(t, svc)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// One first, so gRPC's own long-lived goroutines are in the baseline.
	runOne := func() {
		sess, err := openSession(ctx, t, client, openOptions("exit", "0"))
		require.NoError(t, err)
		require.NotNil(t, sess.awaitEnd())
	}
	runOne()
	baseline := goleak.IgnoreCurrent()

	for range exited {
		runOne()
	}

	// And the ending that has to tear a running session down rather than
	// collect one that finished: the caller goes away mid-session.
	for range cancelled {
		streamCtx, streamCancel := context.WithCancel(ctx)
		sess, err := openSession(streamCtx, t, client, openOptions("sleep"))
		require.NoError(t, err)
		require.NotNil(t, sess.opened)
		streamCancel()
		<-sess.done
	}

	// The agent's own record of each session, not the client's stream ending:
	// a cancelled caller is gone long before the agent has hung the terminal
	// up and killed the tree, and counting goroutines in that window would
	// measure the teardown rather than what it leaves behind.
	awaitRecords(t, svc, 1+exited+cancelled)

	goleak.VerifyNone(t, baseline)
}

// -------------------------------------------------------------- refusals

func TestShell_RefusedWhenDisabled(t *testing.T) {
	svc := newService(t, options{shell: agent.ShellConfig{Enabled: enabled(false)}})
	client := serve(t, svc)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := openSession(ctx, t, client, openOptions("exit", "0"))
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "shell.enabled")

	rec := onlyRecord(t, svc)
	assert.Equal(t, policy.OutcomeDenied, rec.Outcome)
	assert.Equal(t, "shell.enabled: false", rec.Rule)
}

// TestShell_RefusedOnAnAgentWithExecDisabled is the one refusal that is a
// security boundary rather than a convenience.
//
// exec.enabled: false is the only configuration in which allowed_roots confines
// anything, and it is that only because an agent that runs commands reaches
// every path anyway. A shell service that ignored the setting would hand an
// operator a configured jail, report itself confined through GetHostInfo, and
// then let a caller type their way past it.
func TestShell_RefusedOnAnAgentWithExecDisabled(t *testing.T) {
	svc := newService(t, options{exec: agent.ExecConfig{Enabled: enabled(false)}})
	client := serve(t, svc)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := openSession(ctx, t, client, openOptions("exit", "0"))
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "exec.enabled")

	rec := onlyRecord(t, svc)
	assert.Equal(t, policy.OutcomeDenied, rec.Outcome)
	assert.Equal(t, "exec.enabled: false", rec.Rule)
}

// TestShell_RefusedByTheCommandPolicy checks that the deny list reaches this
// service too. A guardrail that stopped `fleet_exec` from running something and
// let a session run it would be worse than no guardrail: it is what an operator
// plans around.
func TestShell_RefusedByTheCommandPolicy(t *testing.T) {
	svc := newService(t, options{deny: []string{filepath.Base(selfArgv()[0])}})
	client := serve(t, svc)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := openSession(ctx, t, client, openOptions("exit", "0"))
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	rec := onlyRecord(t, svc)
	assert.Equal(t, policy.OutcomeDenied, rec.Outcome)
	assert.NotEmpty(t, rec.Rule)
}

func TestShell_RefusesAStreamThatNamesNoCommand(t *testing.T) {
	client := serve(t, newService(t, options{}))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stream, err := client.Shell(ctx)
	require.NoError(t, err)
	require.NoError(t, stream.Send(&sandboxdv1.ShellRequest{
		Event: &sandboxdv1.ShellRequest_Data{Data: []byte("hello")},
	}))
	_, err = stream.Recv()
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestShell_RefusesAWorkingDirectoryThatIsNotOne(t *testing.T) {
	client := serve(t, newService(t, options{}))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	open := openOptions("exit", "0")
	open.WorkingDir = filepath.Join(t.TempDir(), "no-such-directory")
	_, err := openSession(ctx, t, client, open)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestShell_DefaultsToTheLoginShell checks the case an operator actually uses:
// `fleetctl shell` with no command at all.
func TestShell_DefaultsToTheLoginShell(t *testing.T) {
	requirePTY(t)

	svc := newService(t, options{loginTo: selfArgv("3")})
	client := serve(t, svc)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sess, err := openSession(ctx, t, client, &sandboxdv1.ShellOpen{
		Env:  []string{helperEnvFor("exit")},
		Size: &sandboxdv1.ShellSize{Columns: 80, Rows: 24},
	})
	require.NoError(t, err)

	// The command actually started is reported back, because "which shell did I
	// get" is a question with a different answer on every host.
	assert.Equal(t, selfArgv("3"), sess.opened.GetArgv())

	exit := sess.awaitEnd()
	require.NotNil(t, exit)
	assert.Equal(t, int32(3), exit.GetExitCode())
}

// TestLoginShell_PrefersTheEnvironmentAndFallsBackToAShellThatWorks pins the
// resolution order, including the entry it deliberately does not consult: the
// account's passwd shell, which on a daemon's service account is routinely
// /usr/sbin/nologin.
func TestLoginShell_PrefersTheEnvironmentAndFallsBackToAShellThatWorks(t *testing.T) {
	named := loginShellFor(func(key string) string {
		if key == loginShellVar {
			return "/usr/bin/fictional-shell"
		}
		return ""
	})
	assert.Equal(t, []string{"/usr/bin/fictional-shell"}, named)

	fallback := loginShellFor(func(string) string { return "" })
	assert.Equal(t, []string{fallbackShell}, fallback)
}

func parsePIDs(t *testing.T, out string) []int {
	t.Helper()

	var pids []int
	for _, m := range pidLine.FindAllStringSubmatch(out, -1) {
		pid, err := strconv.Atoi(m[1])
		require.NoErrorf(t, err, "unparseable pid %q", m[1])
		pids = append(pids, pid)
	}
	return pids
}
