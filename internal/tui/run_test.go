package tui

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"
)

// fakeRunner stands in for *tea.Program so the lifecycle can be driven down
// every path, including the one a real program cannot be asked for on demand.
type fakeRunner struct {
	err   error
	panic any
}

func (f *fakeRunner) Run() (tea.Model, error) {
	if f.panic != nil {
		panic(f.panic)
	}
	return nil, f.err
}

// TestTheTerminalIsRestoredOnEveryPathOut.
//
// The brief for this is "every exit path, including panic and SIGTERM", and the
// only way to make that checkable rather than a claim is to make the lifecycle
// an ordinary function over an ordinary interface. What is left outside this
// test — that the restore function really does put a real terminal back — is
// covered end to end by TestTUIRestoresTheTerminal in test/e2e.
func TestTheTerminalIsRestoredOnEveryPathOut(t *testing.T) {
	t.Parallel()

	t.Run("clean exit", func(t *testing.T) {
		t.Parallel()
		var restored int
		var panicked bool
		err := runGuarded(&fakeRunner{}, func(p bool) { restored++; panicked = p })
		require.NoError(t, err)
		require.Equal(t, 1, restored)
		require.False(t, panicked, "a clean exit is not a panic")
	})

	t.Run("program error", func(t *testing.T) {
		t.Parallel()
		var restored int
		var panicked bool
		boom := errors.New("the renderer gave up")
		err := runGuarded(&fakeRunner{err: boom}, func(p bool) { restored++; panicked = p })
		require.ErrorIs(t, err, boom, "the failure must still reach the caller")
		require.Equal(t, 1, restored)
		require.False(t, panicked)
	})

	t.Run("killed by a cancelled context", func(t *testing.T) {
		t.Parallel()
		// This is the shape SIGTERM arrives in: the context is cancelled, and
		// bubbletea returns ErrProgramKilled.
		var restored int
		var panicked bool
		err := runGuarded(&fakeRunner{err: tea.ErrProgramKilled}, func(p bool) { restored++; panicked = p })
		require.ErrorIs(t, err, tea.ErrProgramKilled)
		require.Equal(t, 1, restored)
		require.False(t, panicked, "a cancelled context is not a panic")
	})

	t.Run("panic", func(t *testing.T) {
		t.Parallel()
		var restored int
		var panicked bool
		var order []string
		require.PanicsWithValue(t, "nil map write", func() {
			_ = runGuarded(&fakeRunner{panic: "nil map write"}, func(p bool) {
				restored++
				panicked = p
				order = append(order, "restored")
			})
		})
		require.Equal(t, 1, restored)
		require.True(t, panicked, "the guard must know it is the panic path: it is the only one bubbletea has not already covered")
		// Restored *before* the panic continues, so the stack trace lands on a
		// terminal that can display it. And the panic is re-raised rather than
		// swallowed: a bug that produced a tidy error message would be a bug
		// nobody finds.
		require.Equal(t, []string{"restored"}, order)
	})

	t.Run("restore happens once", func(t *testing.T) {
		t.Parallel()
		var restored int
		require.NoError(t, runGuarded(&fakeRunner{}, func(bool) { restored++ }))
		require.Equal(t, 1, restored)
	})
}

// TestGuardTerminalIsSafeOnSomethingThatIsNotATerminal, which is what a test,
// a pipe and a CI runner all are.
func TestGuardTerminalIsSafeOnSomethingThatIsNotATerminal(t *testing.T) {
	t.Parallel()

	f, err := os.CreateTemp(t.TempDir(), "not-a-tty")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	for _, panicked := range []bool{false, true} {
		require.NotPanics(t, func() { guardTerminal(f)(panicked) })
		require.NotPanics(t, func() { guardTerminal(nil)(panicked) })
	}

	// And nothing was written to it, because there was nothing to put back.
	info, err := f.Stat()
	require.NoError(t, err)
	require.Zero(t, info.Size())
}

// TestOnlyThePanicPathSendsTheResetSequence.
//
// The mode restore is idempotent and invisible; the escape sequences are only
// bytes, so a terminal not interpreting them prints them. bubbletea's own
// shutdown shows the cursor and leaves the alternate screen on every path
// where Run returns, and it puts the console mode back afterwards — so on
// Windows, where a console keeps ENABLE_VIRTUAL_TERMINAL_PROCESSING off unless
// something turns it on, sending them again left "<ESC>[?1049l<ESC>[?25h" on
// the operator's screen after every clean exit. The panic path is the one
// bubbletea has not already covered, and the one where they are worth it.
func TestOnlyThePanicPathSendsTheResetSequence(t *testing.T) {
	t.Parallel()

	var buf strings.Builder
	writeReset(&buf)
	require.Equal(t, resetSequence, buf.String())
	require.Contains(t, resetSequence, "?1049l", "the sequence does not leave the alternate screen")
	require.Contains(t, resetSequence, "?25h", "the sequence does not show the cursor")

	// And the lifecycle only reaches it one way.
	var sent []bool
	guard := func(panicked bool) { sent = append(sent, panicked) }
	require.NoError(t, runGuarded(&fakeRunner{}, guard))
	require.NoError(t, runGuarded(&fakeRunner{err: nil}, guard))
	require.PanicsWithValue(t, "boom", func() { _ = runGuarded(&fakeRunner{panic: "boom"}, guard) })
	require.Equal(t, []bool{false, false, true}, sent)
}

// TestRunRefusesWithoutATerminal. A full-screen program whose output is a pipe
// produces escape sequences and no frames, which reads as a hang.
func TestRunRefusesWithoutATerminal(t *testing.T) {
	t.Parallel()

	f, err := os.CreateTemp(t.TempDir(), "not-a-tty")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	err = RequireTerminal(f)
	require.ErrorIs(t, err, ErrNotATerminal)
	require.Contains(t, err.Error(), "fleetctl list --json", "the refusal must name what to use instead")

	require.ErrorIs(t, RequireTerminal(nil), ErrNotATerminal)
}

func TestRunWithoutASourceIsRefused(t *testing.T) {
	t.Parallel()
	require.Error(t, Run(context.Background(), Options{}))
}

// ------------------------------------------------------------- dispatch

// recordingSource records what was asked of it and answers with fixtures.
type recordingSource struct {
	mu    sync.Mutex
	calls []string

	logOpts  LogOptions
	sigName  string
	graceful bool
	err      error
}

func (r *recordingSource) record(what string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, what)
}

func (r *recordingSource) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func (r *recordingSource) Sandboxes(context.Context) ([]Sandbox, error) {
	r.record("sandboxes")
	return demoFleet(), r.err
}

func (r *recordingSource) Processes(_ context.Context, sandbox, _ string) ([]Process, error) {
	r.record("processes:" + sandbox)
	return demoProcesses(), r.err
}

func (r *recordingSource) Logs(_ context.Context, sandbox, _, processID string, opts LogOptions) (Logs, error) {
	r.mu.Lock()
	r.logOpts = opts
	r.mu.Unlock()
	r.record("logs:" + sandbox + "/" + processID)
	return demoLogs(), r.err
}

func (r *recordingSource) Detail(_ context.Context, sandbox, _ string, toolchains bool) (Detail, error) {
	if toolchains {
		r.record("detail+toolchains:" + sandbox)
	} else {
		r.record("detail:" + sandbox)
	}
	return demoDetail(), r.err
}

func (r *recordingSource) Signal(_ context.Context, sandbox, _, processID, sig string, graceful bool) error {
	r.mu.Lock()
	r.sigName, r.graceful = sig, graceful
	r.mu.Unlock()
	r.record("signal:" + sandbox + "/" + processID)
	return r.err
}

func (r *recordingSource) Restart(_ context.Context, sandbox, _, processID string) error {
	r.record("restart:" + sandbox + "/" + processID)
	return r.err
}

var _ Source = (*recordingSource)(nil)

// TestEachEffectCallsExactlyOneThing. The dispatcher is the only place in this
// package that calls a [Source], and it must not do more than it was asked.
func TestEachEffectCallsExactlyOneThing(t *testing.T) {
	t.Parallel()

	cases := []struct {
		effect Effect
		want   string
	}{
		{Effect{Kind: EffectSandboxes}, "sandboxes"},
		{Effect{Kind: EffectProcesses, Sandbox: "alpha"}, "processes:alpha"},
		{Effect{Kind: EffectLogs, Sandbox: "alpha", ProcessID: "p-web"}, "logs:alpha/p-web"},
		{Effect{Kind: EffectDetail, Sandbox: "alpha"}, "detail:alpha"},
		{Effect{Kind: EffectDetail, Sandbox: "alpha", Toolchains: true}, "detail+toolchains:alpha"},
		{Effect{Kind: EffectSignal, Sandbox: "alpha", ProcessID: "p-web", Signal: "TERM"}, "signal:alpha/p-web"},
		{Effect{Kind: EffectRestart, Sandbox: "alpha", ProcessID: "p-web"}, "restart:alpha/p-web"},
	}
	for _, tc := range cases {
		src := &recordingSource{}
		p := &program{model: demoModel(80, 24), src: src, schedule: DefaultSchedule}
		cmd := p.command(tc.effect)
		require.NotNilf(t, cmd, "%s produced no command", tc.effect.Kind)
		require.NotNil(t, cmd())
		require.Equal(t, []string{tc.want}, src.seen())
	}
}

// TestAMutatingEffectCarriesTheSignalItWasConfirmedWith, all the way from the
// keystroke to the source.
func TestAMutatingEffectCarriesTheSignalItWasConfirmedWith(t *testing.T) {
	t.Parallel()

	src := &recordingSource{}
	p := &program{model: demoModel(80, 24), src: src, schedule: DefaultSchedule}

	// S, pick SIGKILL by number, confirm.
	for _, k := range []string{"S", "4", "y"} {
		_, cmd := p.Update(key(k))
		if cmd != nil {
			cmd()
		}
	}
	require.Equal(t, []string{"signal:alpha/p-web"}, src.seen())
	require.Equal(t, "KILL", src.sigName)
	require.False(t, src.graceful, "an explicit signal is not a graceful stop")

	// And "x" is the graceful one.
	src2 := &recordingSource{}
	p2 := &program{model: demoModel(80, 24), src: src2, schedule: DefaultSchedule}
	for _, k := range []string{"x", "y"} {
		_, cmd := p2.Update(key(k))
		if cmd != nil {
			cmd()
		}
	}
	require.Equal(t, "TERM", src2.sigName)
	require.True(t, src2.graceful)
}

// TestNothingIsCalledUntilItIsConfirmed, at the dispatcher level rather than
// the model's: this is the seam an untested wiring change could bypass.
func TestNothingIsCalledUntilItIsConfirmed(t *testing.T) {
	t.Parallel()

	for _, keys := range [][]string{{"x"}, {"r"}, {"S", "enter"}, {"S", "1"}} {
		src := &recordingSource{}
		p := &program{model: demoModel(80, 24), src: src, schedule: DefaultSchedule}
		for _, k := range keys {
			_, cmd := p.Update(key(k))
			if cmd != nil {
				cmd()
			}
		}
		require.Emptyf(t, src.seen(), "keys %v reached the fleet with no confirmation", keys)
	}
}

// TestTheShellSeamIsOneHook. #43 supplies it; until then the key reports that
// this build has no shell. Both branches are covered because the wiring is what
// #43 will change, and a seam nothing exercises is a seam that has rotted by
// the time someone reaches for it.
func TestTheShellSeamIsOneHook(t *testing.T) {
	t.Parallel()

	var gotSandbox, gotAddress string
	p := &program{
		model:    demoModel(80, 24),
		src:      &recordingSource{},
		schedule: DefaultSchedule,
		shell: func(sandbox, address string) tea.Cmd {
			gotSandbox, gotAddress = sandbox, address
			return func() tea.Msg { return statusMsg{text: "shell closed"} }
		},
	}
	p.model.shellWired = true

	_, cmd := p.Update(key("s"))
	require.NotNil(t, cmd)
	require.Equal(t, "alpha", gotSandbox)
	require.Equal(t, "10.0.0.11:9443", gotAddress)

	unwired := &program{model: demoModel(80, 24), src: &recordingSource{}, schedule: DefaultSchedule}
	msg := unwired.command(Effect{Kind: EffectOpenShell, Sandbox: "alpha"})()
	require.Contains(t, msg.(statusMsg).text, "#43")
}

// TestADispatchedCallCarriesTheRunsContext.
//
// A tea.Cmd is a func with no arguments, so the only way a call started by the
// view can be cancelled by the same SIGTERM that stops it is for the closure to
// have captured the run's context. Every one of them used context.Background(),
// which meant a log follow kept reading a stream for the best part of a minute
// after the program had gone, against a pool the caller was about to close —
// and made [Source]'s own documented contract false.
func TestADispatchedCallCarriesTheRunsContext(t *testing.T) {
	t.Parallel()

	effects := []Effect{
		{Kind: EffectSandboxes},
		{Kind: EffectProcesses, Sandbox: "alpha"},
		{Kind: EffectLogs, Sandbox: "alpha", ProcessID: "p-web"},
		{Kind: EffectDetail, Sandbox: "alpha"},
		{Kind: EffectSignal, Sandbox: "alpha", ProcessID: "p-web", Signal: "TERM"},
		{Kind: EffectRestart, Sandbox: "alpha", ProcessID: "p-web"},
	}
	for _, e := range effects {
		ctx, cancel := context.WithCancel(context.Background())
		src := &ctxSource{}
		p := &program{ctx: ctx, model: demoModel(80, 24), src: src, schedule: DefaultSchedule}
		cancel()

		cmd := p.command(e)
		require.NotNil(t, cmd)
		cmd()
		require.ErrorIsf(t, src.seenErr, context.Canceled,
			"%s was dispatched under a context the run cannot cancel", e.Kind)
	}

	// And a program built without one still works, because a test builds them
	// that way and a nil context passed to a gRPC call panics.
	p := &program{model: demoModel(80, 24), src: &ctxSource{}, schedule: DefaultSchedule}
	require.NotNil(t, p.callContext())
	require.NoError(t, p.callContext().Err())
}

// ctxSource answers nothing and remembers the context it was called under.
type ctxSource struct{ seenErr error }

func (c *ctxSource) note(ctx context.Context) { c.seenErr = ctx.Err() }

func (c *ctxSource) Sandboxes(ctx context.Context) ([]Sandbox, error) { c.note(ctx); return nil, nil }
func (c *ctxSource) Processes(ctx context.Context, _, _ string) ([]Process, error) {
	c.note(ctx)
	return nil, nil
}

func (c *ctxSource) Logs(ctx context.Context, _, _, _ string, _ LogOptions) (Logs, error) {
	c.note(ctx)
	return Logs{}, nil
}

func (c *ctxSource) Detail(ctx context.Context, _, _ string, _ bool) (Detail, error) {
	c.note(ctx)
	return Detail{}, nil
}
func (c *ctxSource) Signal(ctx context.Context, _, _, _, _ string, _ bool) error {
	c.note(ctx)
	return nil
}
func (c *ctxSource) Restart(ctx context.Context, _, _, _ string) error { c.note(ctx); return nil }

var _ Source = (*ctxSource)(nil)

// flatten runs a message that may be a batch of commands, the way bubbletea's
// event loop does.
func flatten(msg tea.Msg) []tea.Msg {
	batch, ok := msg.(tea.BatchMsg)
	if !ok {
		return []tea.Msg{msg}
	}
	out := make([]tea.Msg, 0, len(batch))
	for _, cmd := range batch {
		out = append(out, flatten(cmd())...)
	}
	return out
}

// TestAHookCanReportBack.
//
// [Options.OpenShell] is the one thing this package hands to a caller outside
// it, and a hook returns a tea.Cmd, whose only power is to produce a message.
// Every message this package understands is unexported, so without [Status] a
// wired #43 could open a shell and have no way to say that it exited 3 — the
// seam would carry an action out and nothing back.
func TestAHookCanReportBack(t *testing.T) {
	t.Parallel()

	p := &program{
		model:    demoModel(80, 24),
		src:      &recordingSource{},
		schedule: DefaultSchedule,
		shell: func(string, string) tea.Cmd {
			return func() tea.Msg { return Status("shell on alpha exited 3") }
		},
	}
	p.model.shellWired = true

	_, cmd := p.Update(key("s"))
	require.NotNil(t, cmd)
	// The message the hook produced goes back in the way bubbletea would
	// deliver it, and the footer says so. Unwrapped rather than assumed to be
	// the only one: `s` emits one effect today, and a batch is what a second
	// would arrive as.
	for _, msg := range flatten(cmd()) {
		p.model, _ = p.model.Step(msg)
	}
	require.Contains(t, p.View(), "shell on alpha exited 3")
}

// TestTheProgramTicksOnItsOwnSchedule, and stops when it quits: a ticker that
// ran independently of the model would keep firing into a program that had
// already gone.
func TestTheProgramTicksOnItsOwnSchedule(t *testing.T) {
	t.Parallel()

	p := &program{
		model:    demoModel(80, 24),
		src:      &recordingSource{},
		schedule: Schedule{Tick: 10 * time.Millisecond, Sandboxes: time.Hour, Processes: time.Hour, LogWindow: time.Hour, Detail: time.Hour},
	}
	p.model.schedule = p.schedule

	_, cmd := p.Update(tickMsg{now: fixedNow})
	require.NotNil(t, cmd, "a tick must arm the next one")

	p.model.quitting = true
	_, cmd = p.Update(tickMsg{now: fixedNow})
	require.Nil(t, cmd, "a quitting program must not arm another tick")
}

// TestTheViewIsTheRenderer, so nothing can grow a second rendering path.
func TestTheViewIsTheRenderer(t *testing.T) {
	t.Parallel()

	p := &program{model: demoModel(80, 24), theme: NewTheme(ProfileNone), glyphs: unicodeGlyphs, src: &recordingSource{}}
	require.Equal(t, Render(p.model, p.theme, p.glyphs), p.View())
}
