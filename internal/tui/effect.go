package tui

import "time"

// What the model wants done, as a value.
//
// [Model.Step] returns effects rather than bubbletea commands, and the reason
// is testability of the two things this program is most likely to get wrong.
// A tea.Cmd is an opaque func; a test that has one can tell you nothing about
// what it will do. An [Effect] is a struct, so "a mutating keystroke emits
// nothing until it is confirmed" and "a tick does not start a second fetch
// while the first is in flight" are assertions about returned values rather
// than about a terminal someone has to watch.

// EffectKind is what an effect asks for.
type EffectKind int

const (
	// EffectSandboxes reads the fleet and the pool's health cache. It performs
	// no agent I/O and is therefore the one effect that is safe on every tick.
	EffectSandboxes EffectKind = iota + 1
	// EffectProcesses lists processes on the focused sandbox.
	EffectProcesses
	// EffectLogs fetches one bounded window of the focused process's output.
	EffectLogs
	// EffectDetail describes the focused sandbox's host.
	EffectDetail
	// EffectSignal signals a process. Mutating: only ever emitted from a
	// confirmed [Confirmation].
	EffectSignal
	// EffectRestart restarts a process. Mutating, as above.
	EffectRestart
	// EffectOpenShell opens an interactive shell on the focused sandbox. This
	// is the seam #43 attaches to; see [Options.OpenShell].
	EffectOpenShell
	// EffectQuit ends the program.
	EffectQuit
)

// Mutating reports whether an effect changes something on a sandbox.
//
// This is the predicate the confirmation gate is written against, so a mutating
// effect added later is refused by the gate until someone lists it here —
// rather than quietly becoming the one action that needs no confirmation.
func (k EffectKind) Mutating() bool {
	switch k {
	case EffectSignal, EffectRestart:
		return true
	default:
		return false
	}
}

// String names an effect kind, for status lines and test failures.
func (k EffectKind) String() string {
	switch k {
	case EffectSandboxes:
		return "sandboxes"
	case EffectProcesses:
		return "processes"
	case EffectLogs:
		return "logs"
	case EffectDetail:
		return "detail"
	case EffectSignal:
		return "signal"
	case EffectRestart:
		return "restart"
	case EffectOpenShell:
		return "shell"
	case EffectQuit:
		return "quit"
	default:
		return "none"
	}
}

// Effect is one unit of work for the dispatcher.
//
// Sandbox and Address travel with the effect rather than being read from the
// model when it runs, because by then the operator may have moved: an effect
// carries the target it was decided for, and its result carries it back so a
// result for a sandbox nobody is looking at any more can be dropped instead of
// painted over the one that is.
type Effect struct {
	Kind    EffectKind
	Sandbox string
	Address string

	// ProcessID and ProcessName name the process for the process-scoped
	// effects. The name is carried only so a message about the effect can use
	// the operator's word for it rather than an opaque id.
	ProcessID   string
	ProcessName string

	// Signal is a SignalProcessRequest_Signal name — "TERM", "KILL" — for
	// EffectSignal.
	Signal string
	// Graceful asks for a graceful stop (TERM, grace period, then KILL) rather
	// than a bare signal.
	Graceful bool

	// Toolchains asks EffectDetail to probe for installed toolchains, which is
	// measurably slower and therefore never done unless the operator asks.
	Toolchains bool

	// Logs bounds an EffectLogs window.
	Logs LogOptions
}

// results, as they come back. Each carries the target it was fetched for.

type sandboxesMsg struct {
	sandboxes []Sandbox
	err       error
	at        time.Time
}

type processesMsg struct {
	sandbox   string
	processes []Process
	err       error
}

type logsMsg struct {
	sandbox   string
	processID string
	logs      Logs
	err       error
}

type detailMsg struct {
	sandbox    string
	detail     Detail
	toolchains bool
	err        error
}

// actionMsg reports what a mutating effect did. Failure is a status line rather
// than an exit: an operator whose stop was refused needs to keep looking at the
// fleet.
type actionMsg struct {
	// done is what to say when it worked, in the past tense; attempted is what
	// to put in front of the reason when it did not.
	//
	// Two strings rather than one, because one produced "stopped
	// web-dev-server on alpha: permission denied" — a sentence that claims the
	// stop happened and then denies it.
	done      string
	attempted string
	err       error
}

// tickMsg drives every refresh decision and the relative clock. One timer, not
// four: the model decides on each tick whether anything is due, which is what
// makes the schedule a pure function of the model rather than a property of
// however many timers happen to be running.
type tickMsg struct{ now time.Time }

// statusMsg puts one line in the footer.
type statusMsg struct{ text string }
