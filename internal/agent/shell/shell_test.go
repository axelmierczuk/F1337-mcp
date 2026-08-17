package shell

import (
	"context"
	"log/slog"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	require.NoError(t, sess.typed("hello-from-the-operator\n"))
	sess.awaitOutput("read[hello-from-the-operator]")

	require.NoError(t, sess.typed("quit\n"))
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

	require.NoError(t, sess.typed(strings.Join(selfArgv(), " ")+"\n"))
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
	require.NoError(t, sess.typed("echo after=$((21+21))\n"))
	sess.awaitOutput("after=42")

	// And the session itself is still there — the half that fails if an
	// interrupt is treated as anything other than a byte on the wire.
	require.NoError(t, sess.typed("exit 4\n"))
	exit := sess.awaitEnd()
	require.NotNil(t, exit)
	assert.Equal(t, int32(4), exit.GetExitCode(), "the shell should have exited on its own, after the interrupt reached only the program it was running")
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
		require.NoError(t, sess.typed("still-here-"+strconv.Itoa(i)+"\n"))
		sess.awaitOutput("read[still-here-" + strconv.Itoa(i) + "]")
		time.Sleep(interval)
	}

	require.NoError(t, sess.typed("quit\n"))
	exit := sess.awaitEnd()
	require.NotNil(t, exit)
	assert.False(t, exit.GetIdleTimeout(), "a session that carried data throughout was reaped as idle")
	assert.Equal(t, int32(0), exit.GetExitCode())
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
			if !platform.ProcessExists(pid) {
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
		if !platform.ProcessExists(pid) {
			return true, ""
		}
		return false, "pid " + strconv.Itoa(pid) + " ignored the hangup and survived the kill that should have followed"
	})
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
