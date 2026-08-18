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
// Measured, on an idle empty fleet over a two-minute window: 0.52% of one core
// at 60, 0.23% at 20. The difference is the only thing this constant buys, and
// it is why it is not simply left at the default.
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

// ErrNotATerminal is what a run without a terminal fails with.
var ErrNotATerminal = errors.New("fleetctl tui needs a terminal")

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
		model:    m,
		theme:    NewTheme(DetectProfile(env)),
		glyphs:   DetectGlyphs(env),
		src:      opts.Source,
		shell:    opts.OpenShell,
		schedule: m.schedule,
	}

	teaOpts := []tea.ProgramOption{
		tea.WithContext(ctx),
		tea.WithAltScreen(),
		tea.WithOutput(out),
		tea.WithFPS(renderFPS),
		// One signal path, not two.
		//
		// bubbletea installs its own SIGINT/SIGTERM handler, and it deadlocks
		// against a cancelled context: on a signal its handler goroutine does a
		// blocking send of QuitMsg onto the program's message channel, while the
		// same signal has already cancelled ctx and stopped the event loop that
		// would have received it. Shutdown then waits for that goroutine and
		// never returns — the terminal is left in raw mode, which is the exact
		// failure this whole file exists to prevent. It reproduced every time
		// under test/e2e's TestTUIGivesTheTerminalBackOnSIGTERM.
		//
		// So the signal handling is the caller's, through ctx, which is also
		// what `fleetctl serve` and `fleet-agent serve` already do. ^C still
		// works: the terminal is in raw mode, so it arrives as a keystroke.
		tea.WithoutSignalHandler(),
		// Nothing here uses the mouse, and leaving reporting off means a
		// terminal that does not support it is not sent sequences it will
		// print as text.
	}
	if opts.In != nil {
		teaOpts = append(teaOpts, tea.WithInput(opts.In))
	}

	err := runGuarded(tea.NewProgram(p, teaOpts...), restore)
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
func runGuarded(p runner, restore func()) (err error) {
	restored := false
	putBack := func() {
		if !restored {
			restored = true
			restore()
		}
	}
	defer func() {
		if r := recover(); r != nil {
			putBack()
			panic(r)
		}
		putBack()
	}()
	_, err = p.Run()
	return err
}

// guardTerminal captures the terminal's mode now and gives back a function
// that puts it back.
//
// bubbletea does this too, and normally gets there first. This exists for the
// path where it does not: a panic that escapes its recovery, or a shutdown that
// does not complete. Restoring twice is harmless — the saved state is the same
// state, and the sequences below are no-ops on a terminal already in that
// state — and restoring once too often is a much better failure than not
// restoring at all.
func guardTerminal(f *os.File) func() {
	if f == nil || !term.IsTerminal(f.Fd()) {
		return func() {}
	}
	state, err := term.GetState(f.Fd())
	if err != nil {
		return func() {}
	}
	return func() {
		_ = term.Restore(f.Fd(), state)
		// Leave the alternate screen and show the cursor, in that order. A
		// terminal that is already on the primary screen ignores the first,
		// and one whose cursor is already visible ignores the second.
		_, _ = io.WriteString(f, "\x1b[?1049l\x1b[?25h")
	}
}

// RequireTerminal refuses a run that has no terminal to draw on.
//
// A full-screen program whose output is a pipe produces escape sequences and no
// frames, which reads as a hang. Saying so, and naming the command that does
// have machine-readable output, is the difference between a bug report and a
// second try.
func RequireTerminal(f *os.File) error {
	if f == nil || !term.IsTerminal(f.Fd()) {
		return fmt.Errorf("%w: stdout is not one. `fleetctl list --json` is the scriptable view of the same data", ErrNotATerminal)
	}
	return nil
}

// ------------------------------------------------------- bubbletea adapter

// program adapts the pure [Model] to bubbletea and dispatches its effects.
type program struct {
	model    Model
	theme    Theme
	glyphs   Glyphs
	src      Source
	shell    func(sandbox, address string) tea.Cmd
	schedule Schedule
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
	src := p.src
	switch e.Kind {
	case EffectQuit:
		return tea.Quit

	case EffectSandboxes:
		return func() tea.Msg {
			sandboxes, err := src.Sandboxes(context.Background())
			return sandboxesMsg{sandboxes: sandboxes, err: err, at: time.Now()}
		}

	case EffectProcesses:
		return func() tea.Msg {
			procs, err := src.Processes(context.Background(), e.Sandbox, e.Address)
			return processesMsg{sandbox: e.Sandbox, processes: procs, err: err}
		}

	case EffectLogs:
		return func() tea.Msg {
			logs, err := src.Logs(context.Background(), e.Sandbox, e.Address, e.ProcessID, e.Logs)
			return logsMsg{sandbox: e.Sandbox, processID: e.ProcessID, logs: logs, err: err}
		}

	case EffectDetail:
		return func() tea.Msg {
			detail, err := src.Detail(context.Background(), e.Sandbox, e.Address, e.Toolchains)
			return detailMsg{sandbox: e.Sandbox, detail: detail, toolchains: e.Toolchains, err: err}
		}

	case EffectSignal:
		return func() tea.Msg {
			err := src.Signal(context.Background(), e.Sandbox, e.Address, e.ProcessID, e.Signal, e.Graceful)
			done, attempted := signalReport(e)
			return actionMsg{done: done, attempted: attempted, err: err}
		}

	case EffectRestart:
		return func() tea.Msg {
			err := src.Restart(context.Background(), e.Sandbox, e.Address, e.ProcessID)
			return actionMsg{
				done:      fmt.Sprintf("restarted %s on %s", e.ProcessName, e.Sandbox),
				attempted: fmt.Sprintf("restart %s on %s", e.ProcessName, e.Sandbox),
				err:       err,
			}
		}

	case EffectOpenShell:
		if p.shell == nil {
			return func() tea.Msg {
				return statusMsg{text: "opening a shell needs `fleetctl shell` (#43), which this build does not have"}
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
