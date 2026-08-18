package tui

import (
	"context"
	"errors"
	"os"
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
		err := runGuarded(&fakeRunner{}, func() { restored++ })
		require.NoError(t, err)
		require.Equal(t, 1, restored)
	})

	t.Run("program error", func(t *testing.T) {
		t.Parallel()
		var restored int
		boom := errors.New("the renderer gave up")
		err := runGuarded(&fakeRunner{err: boom}, func() { restored++ })
		require.ErrorIs(t, err, boom, "the failure must still reach the caller")
		require.Equal(t, 1, restored)
	})

	t.Run("killed by a cancelled context", func(t *testing.T) {
		t.Parallel()
		// This is the shape SIGTERM arrives in: the context is cancelled, and
		// bubbletea returns ErrProgramKilled.
		var restored int
		err := runGuarded(&fakeRunner{err: tea.ErrProgramKilled}, func() { restored++ })
		require.ErrorIs(t, err, tea.ErrProgramKilled)
		require.Equal(t, 1, restored)
	})

	t.Run("panic", func(t *testing.T) {
		t.Parallel()
		var restored int
		var order []string
		require.PanicsWithValue(t, "nil map write", func() {
			_ = runGuarded(&fakeRunner{panic: "nil map write"}, func() {
				restored++
				order = append(order, "restored")
			})
		})
		require.Equal(t, 1, restored)
		// Restored *before* the panic continues, so the stack trace lands on a
		// terminal that can display it. And the panic is re-raised rather than
		// swallowed: a bug that produced a tidy error message would be a bug
		// nobody finds.
		require.Equal(t, []string{"restored"}, order)
	})

	t.Run("restore happens once", func(t *testing.T) {
		t.Parallel()
		var restored int
		require.NoError(t, runGuarded(&fakeRunner{}, func() { restored++ }))
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

	require.NotPanics(t, func() { guardTerminal(f)() })
	require.NotPanics(t, func() { guardTerminal(nil)() })

	// And nothing was written to it, because there was nothing to put back.
	info, err := f.Stat()
	require.NoError(t, err)
	require.Zero(t, info.Size())
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
