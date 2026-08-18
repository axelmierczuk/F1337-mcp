package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/term"
)

// The parts that touch the outside world: the bubbletea adapter, the
// dispatcher that turns [Effect]s into calls, and the terminal lifecycle.
//
// Nothing here decides anything a pane shows. That is the point of the split —
// see the package doc — and it is what lets everything above this file be
// tested without a terminal.

// renderFPS is how often bubbletea's renderer wakes to see whether the frame
// changed.
//
// Its default is 60, which is a frame rate for animation. This program's fastest
// legitimate change is a keystroke, so a third of that is imperceptible to the
// operator and a third of the idle wakeups. That is where an idle TUI's cost
// is: the model schedules nothing faster than one tick a second, and a renderer
// tick with an unchanged buffer is a mutex and a length check, but sixty of
// anything a second is not "no busy-wait".
//
// Measured on macOS/arm64, from the process's own rusage over a two-minute
// window on a pseudo-terminal, with the short run subtracted so start-up does
// not count: an idle empty fleet costs 0.42% of one core at 60 and 0.19% at
// 20, and twenty registered-and-unreachable sandboxes cost 0.38% at 20. That
// difference is the only thing this constant buys, and it is why it is not
// simply left at the default.
//
// The method is written down because the figure is not: three places in this
// branch quoted three different pairs of numbers for it, which is what a
// measurement nobody can repeat turns into.
const renderFPS = 20

// Options configures a run.
type Options struct {
	// Source is where every pane's data comes from. Required.
	Source Source
	// Schedule is how often each pane refreshes. Zero uses DefaultSchedule.
	Schedule Schedule

	// Out and In are the terminal. Zero uses os.Stdout and os.Stdin.
	Out io.Writer
	In  io.Reader
	// TTY is the file the terminal mode is guarded on. Zero uses os.Stdout.
	// It is separate from Out because a test writes to a buffer and guards
	// nothing.
	TTY *os.File

	// Env reads the environment, for the colour and glyph decisions. Zero uses
	// os.Getenv.
	Env func(string) string

	// OpenShell is the seam #43 attaches to.
	//
	// It is a hook rather than a call because opening a shell means handing the
	// terminal to another program and taking it back: bubbletea's tea.Exec is
	// what does that, and it belongs to whoever owns the shell command, not to
	// this package. Nil — which is what ships until #43 lands — makes the key
	// say so rather than do nothing.
	OpenShell func(sandbox, address string) tea.Cmd
}

func (o Options) env() func(string) string {
	if o.Env != nil {
		return o.Env
	}
	return os.Getenv
}

// Run draws the fleet until the operator quits or ctx is cancelled.
//
// The terminal is restored on every path out of here: a normal quit, an error,
// a cancelled context (which is how SIGTERM arrives), and a panic. bubbletea
// restores it on the first three and catches panics inside its own loop; the
// guard below is what covers a panic that escapes it, and what makes the
// promise checkable — [runGuarded] is an ordinary function over an ordinary
// interface, and its test drives all four paths.
func Run(ctx context.Context, opts Options) error {
	if opts.Source == nil {
		return errors.New("tui: no source configured")
	}
	out := io.Writer(os.Stdout)
	if opts.Out != nil {
		out = opts.Out
	}
	tty := opts.TTY
	if tty == nil && opts.Out == nil {
		tty = os.Stdout
	}

	restore := guardTerminal(tty)

	env := opts.env()
	m := NewModel(opts.Schedule, opts.OpenShell != nil)
	p := &program{
		ctx:      ctx,
		model:    m,
		theme:    NewTheme(DetectProfile(env)),
		glyphs:   DetectGlyphs(env),
		src:      opts.Source,
		shell:    opts.OpenShell,
		schedule: m.schedule,
	}

	err := runGuarded(tea.NewProgram(p, programOptions(ctx, out, opts.In)...), restore)
	// A cancelled context is how SIGTERM and SIGINT arrive here, and it is a
	// clean exit rather than a failure: the operator asked to leave, and
	// `fleetctl tui` exiting non-zero because it was asked to stop would make
	// every wrapper script that runs it look like it failed. The two
	// conditions together are what distinguish it from a program bubbletea
	// killed for its own reasons, which is still an error.
	if errors.Is(err, tea.ErrProgramKilled) && ctx.Err() != nil {
		return nil //nolint:nilerr // see above: a requested shutdown is not a failure
	}
	return err
}

// programOptions is what bubbletea is configured with.
//
// Split out of [Run] because the two decisions here are invisible from outside
// a running program — a *tea.Program tells nobody its frame rate or who owns
// its signals — and both are load-bearing: one is the whole of "no busy-wait",
// and the other is a deadlock. Their test applies these to a program and reads
// back what they set, so deleting either goes red rather than silently costing
// a third of a core or hanging a shutdown with the terminal in raw mode.
func programOptions(ctx context.Context, out io.Writer, in io.Reader) []tea.ProgramOption {
	opts := []tea.ProgramOption{
		tea.WithContext(ctx),
		tea.WithAltScreen(),
		tea.WithOutput(out),
		tea.WithFPS(renderFPS),
		// One signal path, not two.
		//
		// bubbletea installs its own SIGINT/SIGTERM handler, and it races a
		// cancelled context: on a signal its handler goroutine does a blocking
		// send of QuitMsg onto the program's unbuffered message channel, with
		// no ctx.Done() case to escape through, while the same signal has
		// already cancelled ctx and given the event loop a second reason to
		// return. Whichever of the two the event loop's select picks decides
		// it: pick the context, and shutdown waits on that goroutine forever,
		// with the terminal in raw mode. Which way the race falls is a
		// scheduling accident, which is why it must not be left to run.
		//
		// So the signal handling is the caller's, through ctx, which is also
		// what `fleetctl serve` and `fleet-agent serve` already do. ^C still
		// works: the terminal is in raw mode, so it arrives as a keystroke.
		tea.WithoutSignalHandler(),
		// Nothing here uses the mouse, and leaving reporting off means a
		// terminal that does not support it is not sent sequences it will
		// print as text.
	}
	if in != nil {
		opts = append(opts, tea.WithInput(in))
	}
	return opts
}

// runner is the half of *tea.Program the lifecycle needs. Narrowing it is what
// lets the test drive a program that returns, fails, or panics.
type runner interface {
	Run() (tea.Model, error)
}

// runGuarded runs the program and restores the terminal on every way out,
// including a panic, which it re-raises once the terminal is usable again.
//
// Re-raising rather than swallowing: a panic is a bug, and a program that
// turned one into a tidy error message would hide it. What the guard buys is
// that the stack trace lands on a terminal that can display it, rather than
// down the right-hand side of a screen still in raw mode.
//
// restore is told which way it was reached, because the two are not the same
// job. See [guardTerminal].
func runGuarded(p runner, restore func(panicked bool)) (err error) {
	restored := false
	putBack := func(panicked bool) {
		if !restored {
			restored = true
			restore(panicked)
		}
	}
	defer func() {
		if r := recover(); r != nil {
			putBack(true)
			panic(r)
		}
		putBack(false)
	}()
	_, err = p.Run()
	return err
}

// guardTerminal captures the terminal's mode now and gives back a function
// that puts it back.
//
// bubbletea does this too, and on every path where Run returns it gets there
// first: its shutdown shows the cursor, leaves the alternate screen and only
// then restores the console mode. So this exists for the one path it cannot
// cover, a panic that escapes its own recovery — and the argument says which
// path this is.
//
// The mode is restored either way, because term.Restore to the state it is
// already in is a no-op that costs a syscall. The escape sequences are not,
// and that is the difference: they are only bytes, so a terminal that is not
// interpreting them prints them. Windows is where that happens — a console
// keeps ENABLE_VIRTUAL_TERMINAL_PROCESSING off unless something turns it on,
// bubbletea turns it on for the run and puts it back on the way out, and
// writing them after that leaves "<ESC>[?1049l<ESC>[?25h" on the operator's
// screen on every clean exit. On the panic path they are worth it: nothing
// else is going to leave the alternate screen, and a stack trace painted over
// a frame nobody can scroll back past is the failure this file exists to
// prevent.
func guardTerminal(f *os.File) func(panicked bool) {
	if f == nil || !term.IsTerminal(f.Fd()) {
		return func(bool) {}
	}
	state, err := term.GetState(f.Fd())
	if err != nil {
		return func(bool) {}
	}
	return restoreTerminal(func() error { return term.Restore(f.Fd(), state) }, f)
}

// restoreTerminal is the decision [guardTerminal] makes once there is a
// terminal to put back: the mode goes back whichever way this was reached, the
// escape sequences go out on the panic path only, and a restore that did not
// work is said out loud.
//
// It is its own function because guardTerminal returns a no-op for anything
// that is not a terminal — which is every unit test, every pipe and every CI
// runner — so the decisions inside it were reachable from no test at all.
// Sending the escapes on every path is the defect the last audit round found
// and fixed; putting it back left the whole tree green, end-to-end suite
// included.
//
// The failure is reported rather than discarded because of what it costs. On a
// clean exit bubbletea has already put the mode back and this call is a no-op,
// so an error here means the restore that mattered — the panic path, or a
// bubbletea shutdown that did not finish — did not happen, and the operator is
// holding a shell that no longer echoes. `reset` is the fix and a program that
// has exited cannot tell them so. It is the same sentence `fleetctl shell`
// prints for the same failure; the two commands own raw mode differently, but
// this part of the job is one job.
//
// The order is deliberate: leave the alternate screen first when there is one
// to leave, or the sentence is written on a screen that is about to be
// discarded. CRLF rather than LF because a terminal whose mode could not be
// restored is still in raw mode, where a bare newline moves down a line
// without returning to column one.
func restoreTerminal(restoreMode func() error, out io.Writer) func(panicked bool) {
	return func(panicked bool) {
		err := restoreMode()
		if panicked {
			writeReset(out)
		}
		if err != nil {
			_, _ = fmt.Fprintf(out, "\r\nfleetctl: could not restore the terminal (%v); run `reset` to fix it\r\n", err)
		}
	}
}

// resetSequence leaves the alternate screen and shows the cursor, in that
// order. A terminal already on the primary screen ignores the first, and one
// whose cursor is already visible ignores the second.
const resetSequence = "\x1b[?1049l\x1b[?25h"

// writeReset sends resetSequence. It is a function so that "only the panic
// path sends it" is something a test can watch happen; see [guardTerminal] for
// why only that path may.
func writeReset(w io.Writer) { _, _ = io.WriteString(w, resetSequence) }

// ------------------------------------------------------- bubbletea adapter

// program adapts the pure [Model] to bubbletea and dispatches its effects.
type program struct {
	// ctx is the run's context, and it is what every [Source] call is made
	// under. Holding it on the struct rather than taking it per call is
	// bubbletea's shape, not a choice: a tea.Cmd is a func with no arguments,
	// so the only way a dispatched call can be cancelled by the same SIGTERM
	// that stops the program is for the closure to have captured it. The zero
	// value is treated as context.Background so a test can build a program
	// without one.
	ctx      context.Context
	model    Model
	theme    Theme
	glyphs   Glyphs
	src      Source
	shell    func(sandbox, address string) tea.Cmd
	schedule Schedule
}

// callContext is the context a dispatched effect runs under.
//
// Cancelled with the run, so a shutdown does not leave a log follow reading a
// stream for the best part of a minute against a pool the caller is about to
// close. The deadline is still the [Source]'s: only it knows what one call to
// one sandbox is worth waiting for, and a graceful stop is worth thirteen
// seconds where a process listing is worth three.
func (p *program) callContext() context.Context {
	if p.ctx == nil {
		return context.Background()
	}
	return p.ctx
}

var _ tea.Model = (*program)(nil)

func (p *program) Init() tea.Cmd {
	next, effects := p.model.Init()
	p.model = next
	return tea.Batch(append(p.dispatch(effects), p.tick())...)
}

func (p *program) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	next, effects := p.model.Step(msg)
	p.model = next

	cmds := p.dispatch(effects)
	if _, ok := msg.(tickMsg); ok && !next.quitting {
		// One timer, re-armed from the tick it delivered. A ticker that ran
		// independently of the model would keep firing into a program that had
		// quit, and would be a second thing to stop.
		cmds = append(cmds, p.tick())
	}
	return p, tea.Batch(cmds...)
}

func (p *program) View() string { return Render(p.model, p.theme, p.glyphs) }

// tick is the model's clock. tea.Tick sleeps; it does not spin.
func (p *program) tick() tea.Cmd {
	every := p.schedule.Tick
	if every <= 0 {
		every = DefaultSchedule.Tick
	}
	return tea.Tick(every, func(t time.Time) tea.Msg { return tickMsg{now: t} })
}

// dispatch turns effects into commands. It is the only place in this package
// that calls a [Source].
func (p *program) dispatch(effects []Effect) []tea.Cmd {
	cmds := make([]tea.Cmd, 0, len(effects))
	for _, e := range effects {
		if cmd := p.command(e); cmd != nil {
			cmds = append(cmds, cmd)
		}
	}
	return cmds
}

func (p *program) command(e Effect) tea.Cmd {
	src, ctx := p.src, p.callContext()
	switch e.Kind {
	case EffectQuit:
		return tea.Quit

	case EffectSandboxes:
		return func() tea.Msg {
			sandboxes, err := src.Sandboxes(ctx)
			return sandboxesMsg{sandboxes: sandboxes, err: err, at: time.Now()}
		}

	case EffectProcesses:
		return func() tea.Msg {
			procs, err := src.Processes(ctx, e.Sandbox, e.Address)
			return processesMsg{sandbox: e.Sandbox, processes: procs, err: err}
		}

	case EffectLogs:
		return func() tea.Msg {
			logs, err := src.Logs(ctx, e.Sandbox, e.Address, e.ProcessID, e.Logs)
			return logsMsg{sandbox: e.Sandbox, processID: e.ProcessID, logs: logs, err: err}
		}

	case EffectDetail:
		return func() tea.Msg {
			detail, err := src.Detail(ctx, e.Sandbox, e.Address, e.Toolchains)
			return detailMsg{sandbox: e.Sandbox, detail: detail, toolchains: e.Toolchains, err: err}
		}

	case EffectSignal:
		return func() tea.Msg {
			err := src.Signal(ctx, e.Sandbox, e.Address, e.ProcessID, e.Signal, e.Graceful)
			done, attempted := signalReport(e)
			return actionMsg{done: done, attempted: attempted, err: err}
		}

	case EffectRestart:
		return func() tea.Msg {
			err := src.Restart(ctx, e.Sandbox, e.Address, e.ProcessID)
			return actionMsg{
				done:      fmt.Sprintf("restarted %s on %s", e.ProcessName, e.Sandbox),
				attempted: fmt.Sprintf("restart %s on %s", e.ProcessName, e.Sandbox),
				err:       err,
			}
		}

	case EffectOpenShell:
		if p.shell == nil {
			return func() tea.Msg {
				return Status("opening a shell needs `fleetctl shell` (#43), which this build does not have")
			}
		}
		return p.shell(e.Sandbox, e.Address)
	}
	return nil
}

// signalReport is what to say about a signal that worked, and about one that
// did not.
func signalReport(e Effect) (done, attempted string) {
	if e.Graceful {
		return fmt.Sprintf("stopped %s on %s", e.ProcessName, e.Sandbox),
			fmt.Sprintf("stop %s on %s", e.ProcessName, e.Sandbox)
	}
	return fmt.Sprintf("sent SIG%s to %s on %s", e.Signal, e.ProcessName, e.Sandbox),
		fmt.Sprintf("send SIG%s to %s on %s", e.Signal, e.ProcessName, e.Sandbox)
}
