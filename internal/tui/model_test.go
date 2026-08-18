package tui

import (
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/axelmierczuk/fleet-mcp/internal/client"
)

// TestNoKeyMutatesWithoutConfirmation sweeps every key the program can be sent,
// in every mode it has, and asserts that exactly one combination produces an
// effect that changes a sandbox: "y" at a confirmation prompt.
//
// It is a sweep rather than three tests about the three mutating keys, because
// the failure it guards against is a key bound later that skips the gate — and
// a sweep over a hand-written list of keys cannot see that either, which is
// what this used to be. Every printable ASCII rune and every named key, in
// every mode, is the smallest space that contains any key a future edit could
// bind without also editing this test.
func TestNoKeyMutatesWithoutConfirmation(t *testing.T) {
	t.Parallel()

	every := []string{
		"tab", "shift+tab", "up", "down", "pgup", "pgdown", "home", "end",
		"enter", "esc", "ctrl+c", "ctrl+r",
	}
	for r := ' '; r <= '~'; r++ {
		every = append(every, string(r))
	}

	modes := map[string]struct {
		want  mode
		start func() Model
	}{
		"normal":  {modeNormal, func() Model { return demoModel(80, 24) }},
		"confirm": {modeConfirm, func() Model { m, _ := press(demoModel(80, 24), "x"); return m }},
		"signal":  {modeSignal, func() Model { m, _ := press(demoModel(80, 24), "S"); return m }},
		"help":    {modeHelp, func() Model { m, _ := press(demoModel(80, 24), "?"); return m }},
	}
	for name, tc := range modes {
		require.Equalf(t, tc.want, tc.start().mode, "the %s fixture is not in %s mode", name, name)
		for _, k := range every {
			m := tc.start()
			next, effects := m.Step(key(k))

			// The one combination that may: an operator who has read the
			// prompt and said yes.
			if tc.want == modeConfirm && (k == "y" || k == "Y") {
				require.Lenf(t, mutating(effects), 1, "%q did not confirm the prompt it was answering", k)
				continue
			}
			require.Emptyf(t, mutating(effects),
				"%s mode: key %q emitted a mutating effect with no confirmation", name, k)

			// And a key that proposes something must have left a prompt
			// behind, so that "no effect" cannot be achieved by silently doing
			// nothing.
			if next.mode == modeConfirm && m.mode != modeConfirm {
				require.NotEmptyf(t, next.confirm.Prompt, "%s mode: key %q opened a confirmation with no prompt", name, k)
				require.Truef(t, next.confirm.Effect.Kind.Mutating(), "%s mode: key %q confirmed a non-mutating effect", name, k)
				require.Containsf(t, next.confirm.Prompt, `"alpha"`, "%s mode: key %q did not name the sandbox", name, k)
			}
		}
	}
}

// TestConfirmationNamesTheSandboxAndTheProcess pins the one thing the prompt
// exists for. A prompt that said "Stop this process?" would be a keystroke's
// worth of protection and none of the information that makes the answer
// possible.
func TestConfirmationNamesTheSandboxAndTheProcess(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		keys   []string
		verb   string
		signal string
	}{
		{name: "stop", keys: []string{"x"}, verb: "Stop"},
		{name: "restart", keys: []string{"r"}, verb: "Restart"},
		{name: "signal", keys: []string{"S", "enter"}, verb: "SIGTERM"},
		{name: "signal by number", keys: []string{"S", "4"}, verb: "SIGKILL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := demoModel(80, 24)
			m, effects := press(m, tc.keys...)
			require.Empty(t, mutating(effects))
			require.Equal(t, modeConfirm, m.mode)
			require.Contains(t, m.confirm.Prompt, `"alpha"`, "prompt must name the sandbox")
			require.Contains(t, m.confirm.Prompt, `"web-dev-server"`, "prompt must name the process")
			require.Contains(t, m.confirm.Prompt, tc.verb)

			// And the prompt is on screen, not merely in the model.
			frame := Render(m, NewTheme(ProfileNone), unicodeGlyphs)
			require.Contains(t, frame, "[y/N]")
			require.Contains(t, frame, "alpha")
		})
	}
}

// TestOnlyYesConfirms checks that every other key cancels, including the keys
// that mean something in normal mode. A prompt that let "j" fall through to the
// action underneath would be worse than no prompt, because the operator
// believes they are protected.
func TestOnlyYesConfirms(t *testing.T) {
	t.Parallel()

	for _, k := range []string{"y", "Y"} {
		m, _ := press(demoModel(80, 24), "x")
		_, effects := m.Step(key(k))
		require.Len(t, mutating(effects), 1, "%q should confirm", k)
	}
	for _, k := range []string{"n", "N", "esc", "enter", "j", "x", "r", "tab", " ", "?"} {
		m, _ := press(demoModel(80, 24), "x")
		next, effects := m.Step(key(k))
		require.Emptyf(t, mutating(effects), "%q should not confirm", k)
		require.Equalf(t, modeNormal, next.mode, "%q should close the prompt", k)
		require.Equal(t, "cancelled", next.status)
	}
}

// TestConfirmationActsOnWhatItNamed feeds a refreshed process list in while a
// confirmation is open, reordering the table under it, and checks that "y"
// still stops the process the prompt named.
//
// This is why [Confirmation] holds the whole effect rather than re-deriving it
// from the model at confirmation time.
func TestConfirmationActsOnWhatItNamed(t *testing.T) {
	t.Parallel()

	m, _ := press(demoModel(80, 24), "x")
	require.Contains(t, m.confirm.Prompt, `"web-dev-server"`)

	reordered := demoProcesses()
	reordered[0], reordered[3] = reordered[3], reordered[0]
	m, _ = m.Step(processesMsg{sandbox: "alpha", processes: reordered})

	_, effects := m.Step(key("y"))
	acts := mutating(effects)
	require.Len(t, acts, 1)
	require.Equal(t, "p-web", acts[0].ProcessID)
	require.Equal(t, "alpha", acts[0].Sandbox)
	require.True(t, acts[0].Graceful)
}

// TestQuitIsAnswerableFromAConfirmation covers the operator who has second
// thoughts at a destructive prompt: leaving must not require answering it.
func TestQuitIsAnswerableFromAConfirmation(t *testing.T) {
	t.Parallel()

	m, _ := press(demoModel(80, 24), "x")
	require.Equal(t, modeConfirm, m.mode)
	next, effects := m.Step(key("ctrl+c"))
	require.Empty(t, mutating(effects))
	require.Len(t, effects, 1)
	require.Equal(t, EffectQuit, effects[0].Kind)
	require.True(t, next.quitting)
}

// TestStopRefusesAProcessThatIsAlreadyGone. Offering to stop a crashed process
// would be a confirmation prompt for a call that cannot do anything.
func TestStopRefusesAProcessThatIsAlreadyGone(t *testing.T) {
	t.Parallel()

	m := demoModel(80, 24)
	m.focus, m.procCursor = PaneProcesses, 2 // the crashed one
	next, effects := m.Step(key("x"))
	require.Empty(t, effects)
	require.Equal(t, modeNormal, next.mode)
	require.Contains(t, next.status, "already crashed")
}

// TestRestartOfAnExitedProcessReadsAsStart. The agent runs it again from the
// same spec either way; the word an operator wants for that when the process is
// not there is "start".
func TestRestartOfAnExitedProcessReadsAsStart(t *testing.T) {
	t.Parallel()

	m := demoModel(80, 24)
	m.focus, m.procCursor = PaneProcesses, 2
	frame := Render(m, NewTheme(ProfileNone), unicodeGlyphs)
	require.Contains(t, frame, "r start")
	require.NotContains(t, frame, "r restart")

	m.procCursor = 0
	frame = Render(m, NewTheme(ProfileNone), unicodeGlyphs)
	require.Contains(t, frame, "r restart")
}

// ------------------------------------------------------------- scheduling

// TestTickFetchesOnlyWhatIsDue is the core of the refresh policy: a tick is
// cheap, and only the panes whose period has elapsed cost anything.
func TestTickFetchesOnlyWhatIsDue(t *testing.T) {
	t.Parallel()

	base := demoModel(80, 24)
	base.now = fixedNow

	// A second after everything arrived, the only thing owed is the next log
	// window: the last one ran to its deadline, so following means opening
	// another. See TestAFailedLogWindowBacksOff for the case where it does not.
	_, effects := base.tick(fixedNow.Add(time.Second))
	require.Equal(t, []EffectKind{EffectLogs}, kinds(effects))

	// The sandbox listing is due at its period, and it is local: it is the one
	// effect that costs no agent traffic.
	_, effects = base.tick(fixedNow.Add(DefaultSchedule.Sandboxes))
	require.Contains(t, kinds(effects), EffectSandboxes)
	require.NotContains(t, kinds(effects), EffectProcesses, "the process list is slower than the listing")

	// The process list at its own, longer, period.
	_, effects = base.tick(fixedNow.Add(DefaultSchedule.Processes))
	require.Contains(t, kinds(effects), EffectProcesses)
	require.NotContains(t, kinds(effects), EffectDetail, "host detail is much slower than the process list")

	_, effects = base.tick(fixedNow.Add(DefaultSchedule.Detail))
	require.Contains(t, kinds(effects), EffectDetail)
}

// TestTickNeverStartsASecondFetchOnTopOfTheFirst. On a slow sandbox this is
// the difference between a view that is behind and a view with a queue of
// answers to questions nobody is asking any more.
func TestTickNeverStartsASecondFetchOnTopOfTheFirst(t *testing.T) {
	t.Parallel()

	m := demoModel(80, 24)
	m.now = fixedNow
	m, effects := m.tick(fixedNow.Add(time.Minute))
	require.NotEmpty(t, effects)

	for i := range 10 {
		var more []Effect
		m, more = m.tick(fixedNow.Add(time.Minute + time.Duration(i+1)*time.Second))
		require.Emptyf(t, more, "tick %d started a fetch while one was in flight", i)
	}
}

// TestNothingIsFetchedForASandboxNobodyIsLookingAt is the whole reason a fleet
// of any size is watchable: the per-sandbox cost is health, which the pool
// already pays in the background, and nothing else.
func TestNothingIsFetchedForASandboxNobodyIsLookingAt(t *testing.T) {
	t.Parallel()

	m := demoModel(80, 24)
	m.sandboxes = bigFleet()
	m.sbCursor = 3
	m.now = fixedNow
	m.procState, m.detailState, m.logState = paneState{}, paneState{}, paneState{}

	_, effects := m.tick(fixedNow.Add(time.Minute))
	for _, e := range effects {
		if e.Kind == EffectSandboxes {
			continue
		}
		require.Equalf(t, "node-04", e.Sandbox,
			"%s was fetched for %s, which is not the focused sandbox", e.Kind, e.Sandbox)
	}
}

// TestAnEmptyFleetCostsNoAgentTraffic.
func TestAnEmptyFleetCostsNoAgentTraffic(t *testing.T) {
	t.Parallel()

	m := NewModel(DefaultSchedule, false)
	m.sbLoaded = true
	_, effects := m.tick(fixedNow.Add(time.Hour))
	require.Equal(t, []EffectKind{EffectSandboxes}, kinds(effects))
}

// TestLogsRearmAsSoonAsAWindowCloses. The bound on a log follow is the window,
// and the window is also the period: waiting out a second timer after one
// closed would leave a gap in what the pane can see.
func TestLogsRearmAsSoonAsAWindowCloses(t *testing.T) {
	t.Parallel()

	m := demoModel(80, 24)
	m.now = fixedNow

	// A window is open, so nothing asks for a second one.
	m.logState.inFlight = true
	_, effects := m.tick(fixedNow.Add(time.Second))
	require.NotContains(t, kinds(effects), EffectLogs)

	// It closes at its deadline, and the next tick opens the next one.
	m, _ = m.Step(logsMsg{sandbox: "alpha", processID: "p-web", logs: demoLogs()})
	require.False(t, m.logState.inFlight)

	_, effects = m.tick(fixedNow.Add(2 * time.Second))
	require.Contains(t, kinds(effects), EffectLogs)

	// And every window is bounded, both in time and in lines retained.
	for _, e := range effects {
		if e.Kind == EffectLogs {
			require.True(t, e.Logs.Follows())
			require.Greater(t, e.Logs.FollowFor, time.Duration(0), "a follow with no bound is an unbounded stream")
			require.LessOrEqual(t, e.Logs.FollowFor, time.Minute)
			require.Greater(t, e.Logs.MaxLines, 0)
		}
	}
}

// -------------------------------------------------------------- results

// TestAnswersForSomewhereElseAreDropped. An answer that arrives after the
// operator has moved on must not be painted over the machine they moved to.
func TestAnswersForSomewhereElseAreDropped(t *testing.T) {
	t.Parallel()

	m := demoModel(80, 24)
	before := m.processes

	m, _ = m.Step(processesMsg{sandbox: "gamma", processes: []Process{{ID: "x", Name: "wrong"}}})
	require.Equal(t, before, m.processes)
	require.Equal(t, "alpha", m.procFor)

	m, _ = m.Step(detailMsg{sandbox: "gamma", detail: Detail{Hostname: "wrong"}})
	require.Equal(t, "alpha", m.detailFor)

	m, _ = m.Step(logsMsg{sandbox: "alpha", processID: "p-other", logs: Logs{Lines: []LogLine{{Text: "wrong"}}}})
	require.Equal(t, demoLogs().Lines, m.logs.Lines)
}

// TestAFailedRefreshKeepsTheLastThingSeen. Blanking a pane when a sandbox stops
// answering loses the last thing an operator saw before it went away, which is
// usually the reason it went away.
func TestAFailedRefreshKeepsTheLastThingSeen(t *testing.T) {
	t.Parallel()

	m := demoModel(80, 24)
	m, _ = m.Step(processesMsg{sandbox: "alpha", err: errors.New("no answer within the timeout")})
	require.Len(t, m.processes, 4, "the process list was blanked by a failed refresh")
	require.True(t, m.procState.stale)

	frame := Render(m, NewTheme(ProfileNone), unicodeGlyphs)
	require.Contains(t, frame, "web-dev-server")
	require.Contains(t, frame, "(stale)", "a pane holding old data must say so")
}

// TestTheCursorStaysOnWhatItWasOn. A listing that re-sorts or gains a member
// must not move the selection under an operator who is one keystroke from a
// confirmation prompt about it.
func TestTheCursorStaysOnWhatItWasOn(t *testing.T) {
	t.Parallel()

	m := demoModel(80, 24)
	m.sbCursor = 2 // gamma
	grown := append([]Sandbox{{Name: "aaa-new", Health: client.HealthUnknown}}, demoFleet()...)
	m, _ = m.Step(sandboxesMsg{sandboxes: grown, at: fixedNow})
	sb, ok := m.selectedSandbox()
	require.True(t, ok)
	require.Equal(t, "gamma", sb.Name)

	// And the same for the process table, which refreshes far more often.
	m = demoModel(80, 24)
	m.focus, m.procCursor = PaneProcesses, 1 // queue-worker
	reordered := demoProcesses()
	reordered[0], reordered[1] = reordered[1], reordered[0]
	m, _ = m.Step(processesMsg{sandbox: "alpha", processes: reordered})
	p, ok := m.selectedProcess()
	require.True(t, ok)
	require.Equal(t, "queue-worker", p.Name)
}

// TestChangingSandboxClearsWhatBelongedToTheLastOne. This is the one case where
// blanking is right: a different machine is a different question, not a stale
// answer to the same one.
func TestChangingSandboxClearsWhatBelongedToTheLastOne(t *testing.T) {
	t.Parallel()

	m := demoModel(80, 24)
	require.NotEmpty(t, m.processes)
	m, _ = press(m, "down")

	require.Empty(t, m.processes)
	require.Empty(t, m.logs.Lines)
	require.Equal(t, "", m.detailFor)

	frame := Render(m, NewTheme(ProfileNone), unicodeGlyphs)
	require.NotContains(t, frame, "web-dev-server",
		"the previous sandbox's processes are still on screen")
}

// TestSelectingAProcessOnAnotherSandboxIsImpossible. procFor is what stops a
// mutating action aimed at a process on the machine the operator was looking at
// a moment ago.
func TestSelectingAProcessOnAnotherSandboxIsImpossible(t *testing.T) {
	t.Parallel()

	m := demoModel(80, 24)
	m.sbCursor = 1 // beta-builder, while procFor is still alpha
	_, ok := m.selectedProcess()
	require.False(t, ok)

	next, effects := m.Step(key("x"))
	require.Empty(t, effects)
	require.Equal(t, modeNormal, next.mode)
}

// TestActionsRefreshWhatTheyChanged, so the operator sees the result rather
// than waiting out a period wondering whether the keystroke landed.
func TestActionsRefreshWhatTheyChanged(t *testing.T) {
	t.Parallel()

	m := demoModel(80, 24)
	m, effects := m.Step(actionMsg{done: "stopped web-dev-server on alpha", attempted: "stop web-dev-server on alpha"})
	require.Equal(t, []EffectKind{EffectProcesses}, kinds(effects))
	require.Equal(t, "stopped web-dev-server on alpha", m.status)

	// And a failure says what was attempted rather than what was done: "stopped
	// … : permission denied" claims the stop happened and then denies it.
	m, effects = m.Step(actionMsg{
		done:      "stopped web-dev-server on alpha",
		attempted: "stop web-dev-server on alpha",
		err:       status.Error(codes.PermissionDenied, "the agent said no"),
	})
	require.Empty(t, effects, "a failed action must not be retried by itself")
	require.True(t, strings.HasPrefix(m.status, "stop web-dev-server on alpha: "), m.status)
	require.NotContains(t, m.status, "stopped", "the status claims the stop happened and then denies it")
	// And the reason is in the shared vocabulary, the same as `fleetctl list`
	// gives for the same refusal.
	require.Contains(t, m.status, "permission denied by sandbox policy")
}

// TestToolchainsAreProbedOnlyWhenAskedFor: the probe is measurably slower, and
// a view that ran it on a timer would pay for it on every refresh.
func TestToolchainsAreProbedOnlyWhenAskedFor(t *testing.T) {
	t.Parallel()

	m := demoModel(80, 24)
	m.now = fixedNow
	_, effects := m.tick(fixedNow.Add(time.Hour))
	for _, e := range effects {
		require.Falsef(t, e.Toolchains, "%s asked for toolchains without being told to", e.Kind)
	}

	m, effects = m.Step(key("t"))
	require.Equal(t, []EffectKind{EffectDetail}, kinds(effects))
	require.True(t, effects[0].Toolchains)

	m, _ = m.Step(key("t"))
	require.False(t, m.toolchains)
}

// TestTheShellKeySaysWhatItCannotDo. #43 is not merged, so the action is not
// wired; a key that silently did nothing would read as a broken program rather
// than an unfinished one.
func TestTheShellKeySaysWhatItCannotDo(t *testing.T) {
	t.Parallel()

	m := demoModel(80, 24)
	next, effects := m.Step(key("s"))
	require.Empty(t, effects)
	require.Contains(t, next.status, "#43")

	wired := demoModel(80, 24)
	wired.shellWired = true
	next, effects = wired.Step(key("s"))
	require.Equal(t, []EffectKind{EffectOpenShell}, kinds(effects))
	require.Equal(t, "alpha", effects[0].Sandbox)
	require.Equal(t, "10.0.0.11:9443", effects[0].Address)
	require.Empty(t, next.status)
}

// TestLogFollowReleasesOnScrollAndResumesOnF, so new output does not yank the
// view away from the line an operator is reading.
func TestLogFollowReleasesOnScrollAndResumesOnF(t *testing.T) {
	t.Parallel()

	m := demoModel(80, 24)
	m.focus = PaneLogs
	require.True(t, m.logFollow)

	m, _ = press(m, "up")
	require.False(t, m.logFollow)
	require.Equal(t, 1, m.logScroll)

	// A window arriving while scrolled back must not move the view.
	m, _ = m.Step(logsMsg{sandbox: "alpha", processID: "p-web", logs: demoLogs()})
	require.Equal(t, 1, m.logScroll)

	m, _ = press(m, "f")
	require.True(t, m.logFollow)
	require.Equal(t, 0, m.logScroll)
}

// TestResizeNeverLeavesTheScrollPastTheEnd.
func TestResizeNeverLeavesTheScrollPastTheEnd(t *testing.T) {
	t.Parallel()

	m := demoModel(200, 60)
	m.focus = PaneLogs
	m, _ = press(m, "g")
	require.Positive(t, m.logScroll)

	m.logs = Logs{Lines: []LogLine{{Text: "one"}}}
	m, _ = m.Step(sizeMsg(40, 12))
	require.LessOrEqual(t, m.logScroll, 0)
}

// TestAFailedLogWindowBacksOff. Re-arming on every tick against a machine that
// has already refused would be a request a second at a sandbox that is down.
func TestAFailedLogWindowBacksOff(t *testing.T) {
	t.Parallel()

	m := demoModel(80, 24)
	m.now = fixedNow
	m.logState.inFlight = true
	m, _ = m.Step(logsMsg{sandbox: "alpha", processID: "p-web", err: errors.New("no answer within the timeout")})

	_, effects := m.tick(fixedNow.Add(500 * time.Millisecond))
	require.NotContains(t, kinds(effects), EffectLogs)

	_, effects = m.tick(fixedNow.Add(DefaultSchedule.LogWindow))
	require.Contains(t, kinds(effects), EffectLogs)
}

func kinds(effects []Effect) []EffectKind {
	if len(effects) == 0 {
		return nil
	}
	out := make([]EffectKind, 0, len(effects))
	for _, e := range effects {
		out = append(out, e.Kind)
	}
	return out
}

// TestAKeyWithNoNameIsIgnoredRatherThanFatal.
//
// bubbletea's Key.String() returns "" for a key type it has no name for, and
// the signal picker read the first byte of it. An if-statement's initialiser
// runs before the condition it sits beside, so the length check next to the
// index was not guarding it: the whole full-screen program went down with an
// index-out-of-range where an unbound key should have done nothing.
func TestAKeyWithNoNameIsIgnoredRatherThanFatal(t *testing.T) {
	t.Parallel()

	nameless := tea.KeyMsg(tea.Key{Type: tea.KeyRunes}) // String() == ""
	require.Empty(t, nameless.String())

	for _, md := range []mode{modeNormal, modeConfirm, modeSignal, modeHelp} {
		m := demoModel(80, 24)
		m.mode = md
		require.NotPanicsf(t, func() {
			next, effects := m.Step(nameless)
			require.Emptyf(t, mutating(effects), "a nameless key mutated something in mode %d", md)
			_ = next
		}, "mode %d", md)
	}

	// And a key whose first byte is a digit but which is not one — a bracketed
	// paste arrives as "[1]" — does not pick a signal either.
	m := demoModel(80, 24)
	m.mode = modeSignal
	next, effects := m.Step(tea.KeyMsg(tea.Key{Type: tea.KeyRunes, Runes: []rune("1"), Paste: true}))
	require.Empty(t, effects)
	require.Equal(t, modeSignal, next.mode, "a pasted digit picked a signal")
}

// TestAnAnswerToTheOtherToolchainQuestionIsDropped.
//
// Pressing `t` asks again, and the reply already in flight describes a host
// nobody probed for toolchains. Applying it blanks the pane back to "probing"
// for as long as the second answer takes.
func TestAnAnswerToTheOtherToolchainQuestionIsDropped(t *testing.T) {
	t.Parallel()

	m := demoModel(80, 24)
	m.now = fixedNow
	m, _ = m.Step(key("t"))
	require.True(t, m.toolchains)

	// The pre-`t` answer lands.
	stale := demoDetail()
	stale.Hostname = "answered-before-t"
	m, _ = m.Step(detailMsg{sandbox: "alpha", detail: stale, toolchains: false})
	require.NotEqual(t, "answered-before-t", m.detail.Hostname, "an answer to the previous question was applied")
	require.False(t, m.detailState.inFlight, "the pane cannot ask again")

	// The one that answers the question asked is.
	fresh := demoDetail()
	fresh.Hostname = "answered-after-t"
	fresh.ToolchainsAsked = true
	m, _ = m.Step(detailMsg{sandbox: "alpha", detail: fresh, toolchains: true})
	require.Equal(t, "answered-after-t", m.detail.Hostname)
	require.True(t, m.detail.ToolchainsAsked)
}

// TestEveryKeyIsInTheHelp. A keymap and a help screen that disagree is how an
// operator concludes a key does not exist.
func TestEveryKeyIsInTheHelp(t *testing.T) {
	t.Parallel()

	documented := map[string]bool{}
	for _, k := range helpKeys {
		for _, part := range strings.Fields(strings.ReplaceAll(k[0], "/", " ")) {
			documented[part] = true
		}
	}
	for _, k := range []string{"tab", "shift+tab", "enter", "r", "x", "S", "s", "f", "t", "ctrl+r", "?", "q", "j", "k", "g", "G"} {
		require.Truef(t, documented[k], "key %q is bound but not in the help", k)
	}
}

// TestAnOnDemandFetchIsNotJoinedByTheScheduledOne.
//
// Every key that asks for data now has to mark the pane in flight, or the next
// tick sends a second request for the same thing — and the pane an operator
// just asked to refresh becomes the one place two answers race.
func TestAnOnDemandFetchIsNotJoinedByTheScheduledOne(t *testing.T) {
	t.Parallel()

	cases := []struct {
		key  string
		kind EffectKind
	}{
		{"t", EffectDetail},
		{"ctrl+r", EffectSandboxes},
	}
	for _, tc := range cases {
		m := demoModel(80, 24)
		m.now = fixedNow
		m, asked := m.Step(key(tc.key))
		require.Containsf(t, kinds(asked), tc.kind, "%q did not ask for %s", tc.key, tc.kind)

		_, again := m.tick(fixedNow.Add(time.Hour))
		require.NotContainsf(t, kinds(again), tc.kind,
			"%q asked for %s and the next tick asked again while it was still in flight", tc.key, tc.kind)
	}

	// Same for enter, which asks for everything scoped to the sandbox at once.
	m := demoModel(80, 24)
	m.now = fixedNow
	m, asked := m.Step(key("enter"))
	require.ElementsMatch(t, []EffectKind{EffectProcesses, EffectDetail, EffectLogs}, kinds(asked))
	_, again := m.tick(fixedNow.Add(time.Hour))
	require.Equal(t, []EffectKind{EffectSandboxes}, kinds(again),
		"a tick after enter re-asked for what enter had already asked for")
}

// TestAnActionInterruptsTheFetchItInvalidates. Whatever an in-flight process
// list is about to report was read before the stop landed, so the answer that
// matters is the one asked for after it.
func TestAnActionInterruptsTheFetchItInvalidates(t *testing.T) {
	t.Parallel()

	m := demoModel(80, 24)
	m.now = fixedNow
	m.procState.inFlight = true
	m, effects := m.Step(actionMsg{done: "stopped web-dev-server on alpha"})
	require.Equal(t, []EffectKind{EffectProcesses}, kinds(effects))
	require.True(t, m.procState.inFlight, "the replacement fetch is not marked in flight")
}

// TestTheFirstFrameDoesNotLieAboutTheClock. The relative times a fleet pane
// shows are measured against the model's clock, and a model that started at the
// zero time would report every sandbox as last seen "0s ago" — including the
// ones nothing has heard from in a day, which is the reading an operator opens
// this to check.
func TestTheFirstFrameDoesNotLieAboutTheClock(t *testing.T) {
	t.Parallel()

	m := NewModel(DefaultSchedule, false)
	require.WithinDuration(t, time.Now(), m.now, time.Minute)

	// Relative to the model's own clock, so the assertion is about the clock
	// being set rather than about how RelativeTime rounds.
	m, _ = m.Step(sandboxesMsg{sandboxes: []Sandbox{
		{Name: "alpha", Health: client.HealthServing, LastSeen: m.now.Add(-2 * time.Hour)},
	}, at: m.now})
	require.Contains(t, Render(m, NewTheme(ProfileNone), unicodeGlyphs), "2h ago")
}

// TestTheFirstFetchIsMarkedInFlight, or the tick a second later asks for the
// fleet again while the opening read is still running.
func TestTheFirstFetchIsMarkedInFlight(t *testing.T) {
	t.Parallel()

	m := NewModel(DefaultSchedule, false)
	m, effects := m.Init()
	require.Equal(t, []EffectKind{EffectSandboxes}, kinds(effects))

	_, again := m.tick(m.now.Add(time.Hour))
	require.Empty(t, kinds(again), "the opening read was asked for twice")
}

// TestALostSandboxDoesNotLeaveItsProcessesUnderTheNextOnesName.
//
// A refresh of the fleet can move the selection without a keystroke: when the
// registry no longer holds the sandbox the cursor was on, the cursor lands on
// whatever now occupies its index. That is a change of machine exactly as
// pressing "down" is, and everything scoped to the old one is now an answer
// about somewhere else — but only `move` cleared it.
//
// The visible cost was a processes pane titled "beta-builder (stale)" listing
// four processes belonging to a machine that had just left the fleet. The
// pane's own guard was written as "wrong sandbox *and* no error", so a failed
// refresh — which is exactly what a sandbox on its way out produces — let the
// rows through.
func TestALostSandboxDoesNotLeaveItsProcessesUnderTheNextOnesName(t *testing.T) {
	t.Parallel()

	m := demoModel(120, 40)
	require.Len(t, m.processes, 4)

	// A refresh of alpha fails, which is what a machine going away looks like.
	m, _ = m.Step(processesMsg{sandbox: "alpha", err: errors.New("no answer within the timeout")})
	require.True(t, m.procState.stale)

	// And then alpha leaves the registry, so the cursor lands on beta-builder.
	m, _ = m.Step(sandboxesMsg{sandboxes: demoFleet()[1:], at: fixedNow})
	sb, ok := m.selectedSandbox()
	require.True(t, ok)
	require.Equal(t, "beta-builder", sb.Name)

	require.Empty(t, m.processes,
		"the machine that left the fleet took its process list with it")
	require.Empty(t, m.detailFor)
	require.Empty(t, m.logs.Lines)

	frame := Render(m, NewTheme(ProfileNone), unicodeGlyphs)
	require.NotContains(t, frame, "web-dev-server",
		"one machine's processes are drawn under another machine's name")

	// And the pane refuses to draw them even if they are somehow still there,
	// which is the second lock on the same door.
	stuck := demoModel(120, 40)
	stuck.sandboxes = demoFleet()[1:]
	stuck.procState.err, stuck.procState.stale = errors.New("no answer within the timeout"), true
	require.NotContains(t, Render(stuck, NewTheme(ProfileNone), unicodeGlyphs), "web-dev-server",
		"the processes pane drew a list it holds for a different sandbox")
}

// TestARefreshThatKeepsTheSelectionKeepsEverythingElseToo, which is the other
// half: the clear above must not fire on the ordinary refresh, or every pane
// would blank twice a second.
func TestARefreshThatKeepsTheSelectionKeepsEverythingElseToo(t *testing.T) {
	t.Parallel()

	m := demoModel(120, 40)
	before := Render(m, NewTheme(ProfileNone), unicodeGlyphs)

	m, _ = m.Step(sandboxesMsg{sandboxes: demoFleet(), at: fixedNow})
	require.Len(t, m.processes, 4)
	require.Equal(t, "alpha", m.detailFor)
	require.Equal(t, before, Render(m, NewTheme(ProfileNone), unicodeGlyphs),
		"an ordinary fleet refresh redrew the panes it did not change")

	// Including one that re-sorts and gains a member, as long as the selection
	// survives it.
	grown := append([]Sandbox{{Name: "aaa-new", Health: client.HealthUnknown}}, demoFleet()...)
	m, _ = m.Step(sandboxesMsg{sandboxes: grown, at: fixedNow})
	require.Len(t, m.processes, 4, "a fleet that gained a member blanked the focused sandbox's panes")
}
