package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/axelmierczuk/fleet-mcp/internal/client"
)

// Pane is one of the four views.
type Pane int

// The four panes, in tab order: the fleet, the focused sandbox's processes,
// the focused process's output, and the focused sandbox's host.
const (
	PaneFleet Pane = iota
	PaneProcesses
	PaneLogs
	PaneDetail
)

// panes is the tab order, and the only list of panes in this package.
var panes = []Pane{PaneFleet, PaneProcesses, PaneLogs, PaneDetail}

// Title is the pane's name, as it appears on its border.
func (p Pane) Title() string {
	switch p {
	case PaneFleet:
		return "fleet"
	case PaneProcesses:
		return "processes"
	case PaneLogs:
		return "logs"
	case PaneDetail:
		return "detail"
	default:
		return "?"
	}
}

// mode is what the model is doing instead of navigating.
type mode int

const (
	modeNormal mode = iota
	// modeConfirm is showing a confirmation prompt. Nothing mutating leaves
	// the model in any other mode.
	modeConfirm
	// modeSignal is choosing which signal to send, which then confirms.
	modeSignal
	modeHelp
)

// Schedule is how often each pane's data is refreshed.
//
// Only two of these are agent traffic at all, and both are scoped to the
// focused sandbox. Health is not here: it is refreshed by the pool's own
// background loop, and [EffectSandboxes] only reads the cache that loop fills.
type Schedule struct {
	// Tick is how often the model re-evaluates the schedule and the clock. It
	// is not itself I/O.
	Tick time.Duration
	// Sandboxes is how often the registry and the health cache are re-read.
	// Local, but not free — the registry is a file — so it is not every tick.
	Sandboxes time.Duration
	// Processes is how often the focused sandbox's process list is fetched.
	Processes time.Duration
	// LogWindow is how long one bounded log follow runs for. The pane
	// re-arms when a window closes, so this doubles as the log refresh period
	// and is the reason no stream here is unbounded.
	LogWindow time.Duration
	// Detail is how often the focused sandbox's host info is fetched. Host
	// facts are nearly static, so this is much slower than the rest.
	Detail time.Duration
}

// DefaultSchedule is what `fleetctl tui` runs with.
var DefaultSchedule = Schedule{
	Tick:      time.Second,
	Sandboxes: 2 * time.Second,
	Processes: 3 * time.Second,
	LogWindow: 2 * time.Second,
	Detail:    30 * time.Second,
}

// Bounds on what the view holds and shows. Everything below arrives from a
// machine running someone else's code, so none of these lengths are this side's
// to assume.
const (
	// maxLogLines is how much output the logs pane keeps. A process that
	// outruns the pane costs this much memory and no more.
	maxLogLines = 2000
	// logTailLines is how much history each window replays before following.
	// It covers the seam between one window closing and the next opening, so
	// re-arming does not lose the lines emitted in between.
	logTailLines = 200
	// statusLife is how long a status line stays before the footer goes back
	// to the key hints.
	statusLife = 6 * time.Second
)

// signals the picker offers, in the order it offers them. TERM first because
// it is the one an operator wants nine times in ten, KILL last of the two
// stopping signals because it is the one that loses work.
var signals = []string{"TERM", "INT", "HUP", "KILL", "USR1", "USR2"}

// Confirmation is a mutating action waiting for a yes.
//
// It holds the whole effect, already decided, so that confirming is not a
// second decision: whatever the prompt names is exactly what runs. A gate that
// re-derived the action from the model at confirmation time could act on a
// different process from the one it asked about, if anything moved in between.
type Confirmation struct {
	// Prompt names the sandbox and the process. It is built once, when the
	// action is proposed, from the row the operator was looking at.
	Prompt string
	Effect Effect
}

// paneState is the part of a pane that refreshing has to be careful with.
type paneState struct {
	// inFlight stops a tick starting a second fetch on top of the first, which
	// on a slow sandbox is how a view ends up with a queue of stale answers.
	// Every path that asks for data sets it and every path that answers clears
	// it, including the paths that drop an answer for somewhere else.
	inFlight bool
	// last is when a fetch most recently returned.
	last time.Time
	// err is the most recent failure. Data from before it is kept and still
	// shown: a sandbox that stopped answering has not stopped having had
	// processes, and blanking the pane loses the last thing an operator saw
	// before it went away.
	err error
	// stale records that what is shown predates the most recent failure.
	stale bool
}

// Model is the whole view, as a value.
//
// It holds no clients, no channels and no clock: every input arrives as a
// message and every output leaves as an [Effect]. See the package doc.
type Model struct {
	width, height int
	// now is the clock the frame is rendered against, advanced by tickMsg.
	// Holding it rather than calling time.Now in the renderer is what makes a
	// frame reproducible, and therefore golden-fileable.
	now time.Time

	schedule Schedule

	focus Pane
	mode  mode

	sandboxes []Sandbox
	sbCursor  int
	sbState   paneState
	sbLoaded  bool

	processes  []Process
	procCursor int
	procFor    string
	procState  paneState

	logs      Logs
	logFor    logTarget
	logState  paneState
	logScroll int
	// logFollow pins the pane to the newest output. Scrolling up releases it,
	// which is what stops new output yanking the view away from the line an
	// operator is reading.
	logFollow bool

	detail       Detail
	detailFor    string
	detailState  paneState
	detailScroll int
	toolchains   bool

	confirm Confirmation
	sigIdx  int

	status   string
	statusAt time.Time

	// shellWired records whether an "open a shell" action exists in this
	// build. See [Options.OpenShell]; #43 is what supplies it.
	shellWired bool

	quitting bool
}

// NewModel returns the model a program starts with.
func NewModel(schedule Schedule, shellWired bool) Model {
	if schedule.Tick <= 0 {
		schedule = DefaultSchedule
	}
	return Model{
		// 80x24 until the terminal says otherwise. bubbletea sends a size
		// before the first frame on a real terminal, but a program whose first
		// frame depends on that message renders nothing at all when it does
		// not arrive — over a pipe, or on a terminal that answers slowly.
		width:  80,
		height: 24,
		// The clock starts now rather than at the zero time. Relative times are
		// rendered against it, and a model that started at the zero time would
		// draw its first second's worth of frames reporting every sandbox as
		// last seen "0s ago" — including the ones nothing has heard from in a
		// day, which is the reading an operator opens this to check.
		now:        time.Now(),
		schedule:   schedule,
		logFollow:  true,
		shellWired: shellWired,
	}
}

// Init is the first work the model wants: read the fleet once, immediately,
// rather than showing an empty frame until the first tick. It marks the fetch
// in flight for the same reason every other path does — the first tick arrives
// a second later and would otherwise ask again.
func (m Model) Init() (Model, []Effect) {
	return m.markInFlight(EffectSandboxes), []Effect{{Kind: EffectSandboxes}}
}

// Step advances the model. It is pure: same model, same message, same result.
func (m Model) Step(msg tea.Msg) (Model, []Effect) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.clampScroll()
		return m, nil

	case tea.KeyMsg:
		return m.key(msg.String())

	case tickMsg:
		return m.tick(msg.now)

	case sandboxesMsg:
		return m.applySandboxes(msg), nil

	case processesMsg:
		return m.applyProcesses(msg), nil

	case logsMsg:
		return m.applyLogs(msg), nil

	case detailMsg:
		return m.applyDetail(msg), nil

	case actionMsg:
		return m.applyAction(msg)

	case statusMsg:
		m.status, m.statusAt = msg.text, m.now
		return m, nil
	}
	return m, nil
}

// ---------------------------------------------------------------- keys

func (m Model) key(k string) (Model, []Effect) {
	// Quitting is answerable from every mode, including from inside a
	// confirmation. An operator who has second thoughts at a destructive
	// prompt must not have to answer it to leave.
	if k == "ctrl+c" {
		m.quitting = true
		return m, []Effect{{Kind: EffectQuit}}
	}

	switch m.mode {
	case modeConfirm:
		return m.confirmKey(k)
	case modeSignal:
		return m.signalKey(k)
	case modeHelp:
		m.mode = modeNormal
		return m, nil
	}

	switch k {
	case "q":
		m.quitting = true
		return m, []Effect{{Kind: EffectQuit}}

	case "?":
		m.mode = modeHelp
		return m, nil

	case "tab":
		m.focus = panes[(int(m.focus)+1)%len(panes)]
		return m, nil
	case "shift+tab":
		m.focus = panes[(int(m.focus)+len(panes)-1)%len(panes)]
		return m, nil

	case "up", "k":
		return m.move(-1), nil
	case "down", "j":
		return m.move(1), nil
	case "pgup":
		return m.move(-m.pageSize()), nil
	case "pgdown":
		return m.move(m.pageSize()), nil
	case "g", "home":
		return m.jump(true), nil
	case "G", "end":
		return m.jump(false), nil

	case "enter":
		// Drilling in from the fleet pane is the one navigation that means
		// something beyond moving a cursor, so it gets the key that reads that
		// way and refreshes the panes it just changed the subject of.
		if m.focus == PaneFleet {
			m.focus = PaneProcesses
			return m.focusEffects()
		}
		return m, nil

	case "f":
		m.logFollow = !m.logFollow
		if m.logFollow {
			m.logScroll = 0
			m.status = "following the newest output"
		} else {
			m.status = "log following paused; f resumes"
		}
		m.statusAt = m.now
		return m, nil

	case "t":
		m.toolchains = !m.toolchains
		m.detailState.inFlight = false
		if !m.toolchains {
			m.detail.Toolchains, m.detail.ToolchainsAsked = nil, false
			m.status = "toolchain probing off"
			m.statusAt = m.now
			return m, nil
		}
		m.status = "probing for toolchains; this is measurably slower"
		m.statusAt = m.now
		return m.request(EffectDetail)

	case "ctrl+r":
		m.status, m.statusAt = "refreshing", m.now
		return m.refreshAll()

	case "s":
		return m.openShell()

	case "x":
		return m.propose(m.stopEffect())
	case "r":
		return m.propose(m.restartEffect())
	case "S":
		if _, ok := m.selectedProcess(); !ok {
			return m.note("no process selected")
		}
		m.mode, m.sigIdx = modeSignal, 0
		return m, nil
	}
	return m, nil
}

// confirmKey answers a confirmation. Only "y" proceeds; everything else
// cancels, including keys that mean something in normal mode. A prompt that
// let an unrelated keystroke fall through to the action underneath would be
// worse than no prompt, because the operator believes they are protected.
func (m Model) confirmKey(k string) (Model, []Effect) {
	c := m.confirm
	m.confirm = Confirmation{}
	m.mode = modeNormal
	if k != "y" && k != "Y" {
		return m.note("cancelled")
	}
	m.status, m.statusAt = c.Effect.describe()+"…", m.now
	return m, []Effect{c.Effect}
}

func (m Model) signalKey(k string) (Model, []Effect) {
	switch k {
	case "esc", "q":
		m.mode = modeNormal
		return m.note("cancelled")
	case "up", "k":
		m.sigIdx = clamp(m.sigIdx-1, 0, len(signals)-1)
		return m, nil
	case "down", "j":
		m.sigIdx = clamp(m.sigIdx+1, 0, len(signals)-1)
		return m, nil
	case "enter":
		m.mode = modeNormal
		return m.propose(m.signalEffect(signals[m.sigIdx]))
	}
	// A digit picks a signal directly, which is faster than arrowing to it and
	// is the only other thing a keystroke here could sensibly mean.
	if n := strings.IndexByte("123456", k[0]); len(k) == 1 && n >= 0 && n < len(signals) {
		m.mode = modeNormal
		return m.propose(m.signalEffect(signals[n]))
	}
	return m, nil
}

// note sets the footer line and returns no effects.
func (m Model) note(text string) (Model, []Effect) {
	m.status, m.statusAt = text, m.now
	return m, nil
}

// ------------------------------------------------------- mutating actions

// propose puts an effect behind a confirmation, or reports why there is
// nothing to confirm.
//
// This is the only path to a mutating effect. [Model.Step] never emits one
// directly, and the test that pins that walks every key rather than trusting
// this comment.
func (m Model) propose(e Effect, problem string) (Model, []Effect) {
	if problem != "" {
		return m.note(problem)
	}
	m.confirm = Confirmation{Prompt: e.confirmPrompt(), Effect: e}
	m.mode = modeConfirm
	return m, nil
}

// stopEffect is a graceful stop of the selected process.
func (m Model) stopEffect() (Effect, string) {
	sb, ok := m.selectedSandbox()
	if !ok {
		return Effect{}, "no sandbox selected"
	}
	p, ok := m.selectedProcess()
	if !ok {
		return Effect{}, "no process selected"
	}
	if !isLive(p.State) {
		return Effect{}, fmt.Sprintf("%s is already %s", p.Name, p.State)
	}
	return Effect{
		Kind: EffectSignal, Sandbox: sb.Name, Address: sb.Address,
		ProcessID: p.ID, ProcessName: p.Name, Signal: "TERM", Graceful: true,
	}, ""
}

// restartEffect restarts the selected process — or starts it, if it has
// already exited. The agent's RestartProcess runs it again from the same spec
// either way, and calling that "start" when the process is not there is what
// the operator means by the key.
func (m Model) restartEffect() (Effect, string) {
	sb, ok := m.selectedSandbox()
	if !ok {
		return Effect{}, "no sandbox selected"
	}
	p, ok := m.selectedProcess()
	if !ok {
		return Effect{}, "no process selected"
	}
	return Effect{
		Kind: EffectRestart, Sandbox: sb.Name, Address: sb.Address,
		ProcessID: p.ID, ProcessName: p.Name,
	}, ""
}

func (m Model) signalEffect(sig string) (Effect, string) {
	sb, ok := m.selectedSandbox()
	if !ok {
		return Effect{}, "no sandbox selected"
	}
	p, ok := m.selectedProcess()
	if !ok {
		return Effect{}, "no process selected"
	}
	return Effect{
		Kind: EffectSignal, Sandbox: sb.Name, Address: sb.Address,
		ProcessID: p.ID, ProcessName: p.Name, Signal: sig,
	}, ""
}

// describe is what the status line says while an action runs.
func (e Effect) describe() string {
	switch e.Kind {
	case EffectRestart:
		return fmt.Sprintf("restarting %s on %s", e.ProcessName, e.Sandbox)
	case EffectSignal:
		if e.Graceful {
			return fmt.Sprintf("stopping %s on %s", e.ProcessName, e.Sandbox)
		}
		return fmt.Sprintf("sending SIG%s to %s on %s", e.Signal, e.ProcessName, e.Sandbox)
	default:
		return e.Kind.String()
	}
}

// confirmPrompt names the sandbox and the process, always, and says what will
// happen to them.
//
// Naming both is the whole point of the prompt. A keystroke away from
// "signal every process on prod-db" is a different risk from typing that as a
// command, and the difference is that the operator typing it had to write the
// name down.
func (e Effect) confirmPrompt() string {
	switch e.Kind {
	case EffectRestart:
		return fmt.Sprintf("Restart %q on %q?", e.ProcessName, e.Sandbox)
	case EffectSignal:
		if e.Graceful {
			return fmt.Sprintf("Stop %q on %q? SIGTERM, then SIGKILL after %s", e.ProcessName, e.Sandbox, gracePeriod)
		}
		return fmt.Sprintf("Send SIG%s to %q on %q?", e.Signal, e.ProcessName, e.Sandbox)
	default:
		return fmt.Sprintf("%s on %q?", e.Kind, e.Sandbox)
	}
}

// openShell is the #43 seam. Without it, the key says so rather than doing
// nothing, which is the difference between an unfinished feature and a broken
// one.
func (m Model) openShell() (Model, []Effect) {
	sb, ok := m.selectedSandbox()
	if !ok {
		return m.note("no sandbox selected")
	}
	if !m.shellWired {
		return m.note("opening a shell needs `fleetctl shell` (#43), which this build does not have")
	}
	return m, []Effect{{Kind: EffectOpenShell, Sandbox: sb.Name, Address: sb.Address}}
}

// ------------------------------------------------------------ scheduling

// tick advances the clock and asks for whatever is due.
//
// Every refresh decision in the program is here, and it is a pure function of
// the model and the time, which is what makes "a slow sandbox does not queue up
// fetches" and "nothing is fetched for a sandbox nobody is looking at"
// assertions rather than hopes.
func (m Model) tick(now time.Time) (Model, []Effect) {
	m.now = now
	if m.status != "" && now.Sub(m.statusAt) > statusLife {
		m.status = ""
	}

	var out []Effect
	if due(m.sbState, now, m.schedule.Sandboxes) {
		m.sbState.inFlight = true
		out = append(out, Effect{Kind: EffectSandboxes})
	}

	sb, ok := m.selectedSandbox()
	if !ok {
		// Nothing is focused, so nothing is fetched. An empty fleet costs one
		// registry read every couple of seconds and no agent traffic at all.
		return m, out
	}

	if due(m.procState, now, m.schedule.Processes) {
		m.procState.inFlight = true
		out = append(out, m.effect(EffectProcesses, sb))
	}
	if due(m.detailState, now, m.schedule.Detail) {
		m.detailState.inFlight = true
		out = append(out, m.effect(EffectDetail, sb))
	}
	// The log window is re-armed the moment the previous one closes rather
	// than on a period of its own: the window *is* the period, and waiting out
	// a second timer after it would leave a gap in what the pane can see.
	if p, ok := m.selectedProcess(); ok && !m.logState.inFlight && m.logDue(now) {
		m.logState.inFlight = true
		e := m.effect(EffectLogs, sb)
		e.ProcessID, e.ProcessName = p.ID, p.Name
		out = append(out, e)
	}
	return m, out
}

// logDue decides when to open the next log window.
//
// Immediately, when the last one ran to its deadline: that is a follow that
// kept the stream open for its whole bound, and re-arming is what makes the
// pane continuous. Not immediately for anything else — a window that ended
// early because the process is gone, or that failed because the sandbox is
// not answering, would otherwise be retried on every tick, which is a request
// per second at a machine that has already said no.
func (m Model) logDue(now time.Time) bool {
	switch {
	case m.logState.last.IsZero():
		return true
	case m.logState.err == nil && m.logs.DeadlineReached && m.logFor == m.logTarget():
		return true
	default:
		return now.Sub(m.logState.last) >= m.schedule.LogWindow
	}
}

// due reports whether a pane's next fetch is owed. A fetch already in flight is
// never owed a second one.
func due(s paneState, now time.Time, every time.Duration) bool {
	if s.inFlight {
		return false
	}
	return s.last.IsZero() || now.Sub(s.last) >= every
}

// effect builds a target-carrying effect for the focused sandbox.
func (m Model) effect(kind EffectKind, sb Sandbox) Effect {
	e := Effect{Kind: kind, Sandbox: sb.Name, Address: sb.Address}
	switch kind {
	case EffectDetail:
		e.Toolchains = m.toolchains
	case EffectLogs:
		e.Logs = LogOptions{
			TailLines: logTailLines,
			Follow:    true,
			FollowFor: m.schedule.LogWindow,
			MaxLines:  maxLogLines,
		}
	}
	return e
}

// request asks for one pane's data now, regardless of when it last arrived,
// and marks it in flight.
//
// Marking matters: an on-demand fetch that left the flag alone would be joined
// by the scheduled one on the next tick, and the pane an operator just asked to
// refresh would be the one place two answers race.
func (m Model) request(kind EffectKind) (Model, []Effect) {
	sb, ok := m.selectedSandbox()
	if !ok {
		return m, nil
	}
	e := m.effect(kind, sb)
	if kind == EffectLogs {
		p, ok := m.selectedProcess()
		if !ok {
			return m, nil
		}
		e.ProcessID, e.ProcessName = p.ID, p.Name
	}
	m = m.markInFlight(kind)
	return m, []Effect{e}
}

// markInFlight records that a fetch of this kind has been asked for.
func (m Model) markInFlight(kind EffectKind) Model {
	switch kind {
	case EffectSandboxes:
		m.sbState.inFlight = true
	case EffectProcesses:
		m.procState.inFlight = true
	case EffectLogs:
		m.logState.inFlight = true
	case EffectDetail:
		m.detailState.inFlight = true
	}
	return m
}

// focusEffects is what a change of focused sandbox owes: everything scoped to
// it, at once, so the panes are not showing the previous machine's data while
// three separate timers come due.
func (m Model) focusEffects() (Model, []Effect) {
	sb, ok := m.selectedSandbox()
	if !ok {
		return m, nil
	}
	out := []Effect{m.effect(EffectProcesses, sb), m.effect(EffectDetail, sb)}
	m = m.markInFlight(EffectProcesses).markInFlight(EffectDetail)
	if p, ok := m.selectedProcess(); ok {
		e := m.effect(EffectLogs, sb)
		e.ProcessID, e.ProcessName = p.ID, p.Name
		out = append(out, e)
		m = m.markInFlight(EffectLogs)
	}
	return m, out
}

func (m Model) refreshAll() (Model, []Effect) {
	m, out := m.focusEffects()
	m = m.markInFlight(EffectSandboxes)
	return m, append([]Effect{{Kind: EffectSandboxes}}, out...)
}

// ------------------------------------------------------------- results

func (m Model) applySandboxes(msg sandboxesMsg) Model {
	m.sbState.inFlight = false
	m.sbState.last = msg.at
	if msg.err != nil {
		m.sbState.err, m.sbState.stale = msg.err, true
		return m
	}
	m.sbState.err, m.sbState.stale = nil, false

	// Keep the cursor on the sandbox it was on. A listing that re-sorts or
	// gains a member must not move the selection under an operator who is one
	// keystroke from a confirmation prompt about it.
	var selected string
	if sb, ok := m.selectedSandbox(); ok {
		selected = sb.Name
	}
	m.sandboxes = msg.sandboxes
	m.sbLoaded = true
	m.sbCursor = indexOf(m.sandboxes, selected, m.sbCursor)
	return m
}

func (m Model) applyProcesses(msg processesMsg) Model {
	m.procState.inFlight = false
	if msg.sandbox != m.focusedName() {
		// The operator moved on while this was in flight. Dropping it is the
		// whole reason the target travels with the effect; clearing the flag
		// anyway is what lets the pane ask about the sandbox that *is* focused
		// on the next tick rather than waiting out an answer it threw away.
		return m
	}
	m.procState.last = m.now
	if msg.err != nil {
		m.procState.err, m.procState.stale = msg.err, true
		return m
	}
	m.procState.err, m.procState.stale = nil, false

	var selected string
	if p, ok := m.selectedProcess(); ok {
		selected = p.ID
	}
	m.processes = msg.processes
	m.procFor = msg.sandbox
	m.procCursor = indexOfProcess(m.processes, selected, m.procCursor)
	return m
}

func (m Model) applyLogs(msg logsMsg) Model {
	want := m.logTarget()
	if msg.sandbox != want.sandbox || msg.processID != want.processID {
		// A window for a process nobody is watching any more. Clearing the
		// in-flight flag anyway is what lets the pane re-arm for the process
		// that *is* focused on the next tick.
		m.logState.inFlight = false
		return m
	}
	m.logState.inFlight = false
	m.logState.last = m.now
	if msg.err != nil {
		m.logState.err, m.logState.stale = msg.err, true
		return m
	}
	m.logState.err, m.logState.stale = nil, false
	m.logs = msg.logs
	m.logFor = want
	if m.logFollow {
		m.logScroll = 0
	}
	m.clampScroll()
	return m
}

func (m Model) applyDetail(msg detailMsg) Model {
	if msg.sandbox != m.focusedName() {
		m.detailState.inFlight = false
		return m
	}
	m.detailState.inFlight = false
	m.detailState.last = m.now
	if msg.err != nil {
		m.detailState.err, m.detailState.stale = msg.err, true
		return m
	}
	m.detailState.err, m.detailState.stale = nil, false
	m.detail = msg.detail
	m.detailFor = msg.sandbox
	return m
}

// applyAction reports what a mutating effect did and immediately re-reads the
// panes it could have changed, so the operator sees the result rather than
// waiting out a refresh period wondering whether the keystroke landed.
func (m Model) applyAction(msg actionMsg) (Model, []Effect) {
	if msg.err != nil {
		m.status, m.statusAt = msg.what+": "+msg.err.Error(), m.now
		return m, nil
	}
	m.status, m.statusAt = msg.what, m.now
	// An action's result is the one thing worth interrupting an in-flight
	// fetch for: whatever it is about to report was read before the change.
	m.procState.inFlight = false
	return m.request(EffectProcesses)
}

// ------------------------------------------------------------ selection

func (m Model) selectedSandbox() (Sandbox, bool) {
	if len(m.sandboxes) == 0 {
		return Sandbox{}, false
	}
	i := clamp(m.sbCursor, 0, len(m.sandboxes)-1)
	return m.sandboxes[i], true
}

// selectedProcess is the highlighted process, and false when the pane holds
// another sandbox's list. Guarding on procFor is what stops a mutating action
// aimed at a process on the machine the operator was looking at a moment ago.
func (m Model) selectedProcess() (Process, bool) {
	if len(m.processes) == 0 || m.procFor != m.focusedName() {
		return Process{}, false
	}
	i := clamp(m.procCursor, 0, len(m.processes)-1)
	return m.processes[i], true
}

func (m Model) focusedName() string {
	sb, ok := m.selectedSandbox()
	if !ok {
		return ""
	}
	return sb.Name
}

// logTarget is the sandbox and process the logs pane should be showing.
type logTarget struct{ sandbox, processID string }

func (m Model) logTarget() logTarget {
	p, ok := m.selectedProcess()
	if !ok {
		return logTarget{}
	}
	return logTarget{sandbox: m.focusedName(), processID: p.ID}
}

// move steps the cursor of the focused pane.
func (m Model) move(delta int) Model {
	switch m.focus {
	case PaneFleet:
		before := m.sbCursor
		m.sbCursor = clamp(m.sbCursor+delta, 0, maxIndex(len(m.sandboxes)))
		if m.sbCursor != before {
			// Changing machine invalidates everything scoped to the old one.
			// Clearing rather than keeping is right here and wrong on a
			// refresh failure: this is a different question, not a stale
			// answer to the same one.
			m = m.clearFocused()
		}
	case PaneProcesses:
		before := m.procCursor
		m.procCursor = clamp(m.procCursor+delta, 0, maxIndex(len(m.processes)))
		if m.procCursor != before {
			m.logs, m.logFor, m.logScroll = Logs{}, logTarget{}, 0
			m.logState.err, m.logState.stale = nil, false
		}
	case PaneLogs:
		// The logs pane holds history above the newest line, so "up" moves
		// back through it — the opposite sign to a list — and moving off the
		// newest line releases the follow.
		m.logScroll = clamp(m.logScroll-delta, 0, maxIndex(len(m.logs.Lines)))
		m.logFollow = m.logScroll == 0
	case PaneDetail:
		// Detail is a list of fields taller than its pane on an 80x24
		// terminal, and toolchains — which the operator has to ask for — are at
		// the bottom of it. A pane that clipped them and offered no way down
		// would make that key do nothing visible.
		m.detailScroll = clamp(m.detailScroll+delta, 0, m.detailOverflow())
	}
	return m
}

func (m Model) jump(top bool) Model {
	switch m.focus {
	case PaneFleet:
		return m.move(pick(top, -len(m.sandboxes), len(m.sandboxes)))
	case PaneProcesses:
		return m.move(pick(top, -len(m.processes), len(m.processes)))
	case PaneLogs:
		// "top" in a log means the oldest line this window holds.
		m.logScroll = pick(top, maxIndex(len(m.logs.Lines)), 0)
		m.logFollow = m.logScroll == 0
	case PaneDetail:
		m.detailScroll = pick(top, 0, m.detailOverflow())
	}
	return m
}

// detailOverflow is how far the detail pane can scroll: the number of lines it
// holds beyond the ones it can show.
func (m Model) detailOverflow() int {
	l := computeLayout(m.width, m.height, m.focus)
	b, ok := l.Boxes[PaneDetail]
	if !ok {
		return 0
	}
	w, h := b.interior()
	return atLeast(len(detailLines(m, NewTheme(ProfileNone), unicodeGlyphs, w))-h, 0)
}

// clearFocused drops everything scoped to the previously focused sandbox.
func (m Model) clearFocused() Model {
	m.processes, m.procFor, m.procCursor = nil, "", 0
	m.logs, m.logFor, m.logScroll = Logs{}, logTarget{}, 0
	m.detail, m.detailFor, m.detailScroll = Detail{}, "", 0
	m.procState = paneState{}
	m.logState = paneState{}
	m.detailState = paneState{}
	return m
}

func (m Model) pageSize() int {
	l := computeLayout(m.width, m.height, m.focus)
	b, ok := l.Boxes[m.focus]
	if !ok {
		return 1
	}
	_, h := b.interior()
	// One line of title inside the box, and one line of overlap so a page turn
	// keeps a line of context.
	if n := h - 2; n > 1 {
		return n
	}
	return 1
}

func (m *Model) clampScroll() {
	m.logScroll = clamp(m.logScroll, 0, maxIndex(len(m.logs.Lines)))
	m.detailScroll = clamp(m.detailScroll, 0, m.detailOverflow())
}

// ---------------------------------------------------------------- misc

func isLive(state string) bool {
	switch state {
	case client.ProcessStarting, client.ProcessReady, client.ProcessRunning,
		client.ProcessRestarting, client.ProcessOrphaned:
		return true
	default:
		return false
	}
}

func indexOf(list []Sandbox, name string, fallback int) int {
	for i, sb := range list {
		if sb.Name == name {
			return i
		}
	}
	return clamp(fallback, 0, maxIndex(len(list)))
}

func indexOfProcess(list []Process, id string, fallback int) int {
	for i, p := range list {
		if p.ID == id {
			return i
		}
	}
	return clamp(fallback, 0, maxIndex(len(list)))
}

func maxIndex(n int) int {
	if n <= 0 {
		return 0
	}
	return n - 1
}

func pick(cond bool, a, b int) int {
	if cond {
		return a
	}
	return b
}
