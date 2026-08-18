package tui

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/axelmierczuk/fleet-mcp/internal/client"
)

var update = flag.Bool("update", false, "rewrite the golden frames in testdata/")

// TestEveryFrameIsExactlyTheTerminalsSize is the anti-corruption test.
//
// A full-screen program corrupts a terminal in exactly two ways: a line wider
// than the screen, which wraps and scrolls everything up by one, and a frame
// with the wrong number of lines, which leaves the previous frame's tail
// underneath. Both survive the next repaint, so both are permanent until the
// operator quits.
//
// The sweep is over sizes, palettes and character sets together, because
// styling and glyphs are exactly what could break the measurement: an SGR
// sequence that ansi.StringWidth did not discount, or a box-drawing character
// counted as one column and drawn as two.
func TestEveryFrameIsExactlyTheTerminalsSize(t *testing.T) {
	t.Parallel()

	models := map[string]Model{
		"populated": demoModel(80, 24),
		"twenty":    withFleet(demoModel(80, 24), bigFleet()),
		"empty":     emptyModel(),
		"confirm":   confirmModel(),
		"signal":    modeModel(modeSignal),
		"help":      modeModel(modeHelp),
		"hostile":   hostileModel(),
	}
	themes := map[string]Theme{
		"none":  NewTheme(ProfileNone),
		"basic": NewTheme(ProfileBasic),
		"256":   NewTheme(ProfileANSI256),
	}
	glyphs := map[string]Glyphs{"unicode": unicodeGlyphs, "ascii": asciiGlyphs}

	for name, base := range models {
		for tname, theme := range themes {
			for gname, g := range glyphs {
				for _, size := range sizes() {
					m := base
					m.width, m.height = size[0], size[1]
					m.clampScroll()
					frame := Render(m, theme, g)

					lines := strings.Split(frame, "\n")
					require.Lenf(t, lines, atLeast(size[1], 1),
						"%s/%s/%s at %dx%d: wrong number of lines", name, tname, gname, size[0], size[1])
					for i, line := range lines {
						require.Equalf(t, atLeast(size[0], 1), ansi.StringWidth(line),
							"%s/%s/%s at %dx%d: line %d is %q", name, tname, gname, size[0], size[1], i, line)
					}
				}
			}
		}
	}
}

// sizes covers the named target, the boundaries between every mode, and a
// scatter either side of each.
func sizes() [][2]int {
	var out [][2]int
	for _, w := range []int{1, 10, 23, 24, 25, 40, 60, 75, 76, 77, 80, 100, 120, 200} {
		for _, h := range []int{1, 3, 5, 6, 7, 10, 11, 12, 17, 18, 19, 24, 40, 60} {
			out = append(out, [2]int{w, h})
		}
	}
	return out
}

// TestNothingASandboxSaysCanMoveTheCursor.
//
// Every string in a pane except the program's own chrome is a machine
// somewhere answering a question about itself, and a terminal acts on an escape
// sequence in one. The check is width-blind on purpose — ansi.StringWidth
// measures an escape as zero columns, so the size invariant above cannot see
// this — and looks for the bytes themselves.
func TestNothingASandboxSaysCanMoveTheCursor(t *testing.T) {
	t.Parallel()

	m := hostileModel()
	for _, size := range [][2]int{{80, 24}, {120, 40}, {60, 14}, {40, 9}} {
		m.width, m.height = size[0], size[1]
		frame := Render(m, NewTheme(ProfileNone), unicodeGlyphs)
		require.NotContainsf(t, frame, "\x1b", "an escape reached the frame at %dx%d", size[0], size[1])
		require.NotContains(t, frame, "\r")
		require.NotContains(t, frame, "\a")
		// The text either side of the escape survives, so the sanitising is
		// stripping the sequence rather than dropping the string.
		require.Contains(t, frame, "evil")
	}
}

// TestNoColorRendersNoEscapesAtAll. NO_COLOR is set by people who mean it, and
// a program that emits "just the bold ones" is a program they stop using.
func TestNoColorRendersNoEscapesAtAll(t *testing.T) {
	t.Parallel()

	frame := Render(demoModel(120, 40), NewTheme(DetectProfile(envOf(map[string]string{
		"NO_COLOR": "1",
		"TERM":     "xterm-256color",
	}))), unicodeGlyphs)
	require.NotContains(t, frame, "\x1b")
}

// TestColourNeverChangesAWidth. Everything this package emits is an SGR
// sequence, which occupies no cells; anything that moved the cursor would show
// up here as a frame whose styled and unstyled forms disagree.
func TestColourNeverChangesAWidth(t *testing.T) {
	t.Parallel()

	m := demoModel(100, 30)
	plain := Render(m, NewTheme(ProfileNone), unicodeGlyphs)
	for _, p := range []Profile{ProfileBasic, ProfileANSI256} {
		coloured := Render(m, NewTheme(p), unicodeGlyphs)
		require.NotContains(t, coloured, "\x1b[?", "a private-mode sequence is not a style")
		require.Equal(t, ansi.Strip(coloured), plain, "colour changed the text of the frame")
	}
}

// TestWideRunesDoNotPushABorderOut. A CJK name is two columns per rune and an
// emoji is two more; a table laid out in runes puts the right-hand border of a
// pane one column further right on the row that contains one.
func TestWideRunesDoNotPushABorderOut(t *testing.T) {
	t.Parallel()

	m := demoModel(80, 24)
	m.sandboxes[0].Name = "ビルドサーバー-01"
	m.processes[0].Name = "🚀 launcher"
	m.logs.Lines = append(m.logs.Lines, LogLine{Text: "起動しました 🚀🚀🚀"})

	for _, line := range strings.Split(Render(m, NewTheme(ProfileNone), unicodeGlyphs), "\n") {
		require.Equal(t, 80, ansi.StringWidth(line), line)
	}
}

// TestTheSelectedRowIsVisibleWithoutColour. Reverse video needs no colour
// support at all, which matters because which machine is selected is the one
// piece of state an operator cannot afford to lose track of before a
// confirmation — and NO_COLOR would otherwise take it away.
func TestTheSelectedRowIsVisibleWithoutColour(t *testing.T) {
	t.Parallel()

	m := demoModel(80, 24)
	m.sbCursor = 2
	require.Contains(t, Render(m, NewTheme(ProfileBasic), unicodeGlyphs), "\x1b[7m",
		"the selection is not drawn in reverse video")

	// And with no escapes at all, the fleet pane still says which row it is.
	require.Contains(t, Render(m, NewTheme(ProfileNone), unicodeGlyphs), "3/4")
}

// TestATooSmallTerminalGetsASentenceRatherThanAMess.
func TestATooSmallTerminalGetsASentenceRatherThanAMess(t *testing.T) {
	t.Parallel()

	frame := Render(withSize(demoModel(80, 24), 60, 4), NewTheme(ProfileNone), unicodeGlyphs)
	require.Contains(t, frame, "terminal is 60x4; need at least 24x6")

	// And on a terminal too narrow even for that sentence, a shorter one — the
	// message is the only thing on the screen, so it is the one thing that must
	// fit on it.
	frame = Render(withSize(demoModel(80, 24), 20, 4), NewTheme(ProfileNone), unicodeGlyphs)
	require.Contains(t, frame, "need at least 24x6")
	for _, line := range strings.Split(frame, "\n") {
		require.Equal(t, 20, ansi.StringWidth(line))
	}
}

// TestAnEmptyFleetSaysHowToEnrolOne, in the same words `fleetctl list` uses.
func TestAnEmptyFleetSaysHowToEnrolOne(t *testing.T) {
	t.Parallel()

	frame := Render(emptyModel(), NewTheme(ProfileNone), unicodeGlyphs)
	require.Contains(t, frame, "no sandboxes enrolled")
	require.Contains(t, frame, "fleetctl enroll mint")
}

// TestAnUnreachableSandboxIsDrawnAsUnreachable, with the reason, rather than
// being left out or left blank.
func TestAnUnreachableSandboxIsDrawnAsUnreachable(t *testing.T) {
	t.Parallel()

	frame := Render(demoModel(120, 40), NewTheme(ProfileNone), unicodeGlyphs)
	require.Contains(t, frame, "gamma")
	require.Contains(t, frame, "unreachable")
	require.Contains(t, frame, "no answer within the timeout")
	// And the ones either side of it are still there: one dead machine does
	// not blank the view.
	require.Contains(t, frame, "alpha")
	require.Contains(t, frame, "delta")
}

// TestADroppedLogGapIsVisible. A gap between two lines is a fact about those
// two lines, and a reader who sees them adjacent will draw a conclusion from
// their adjacency.
func TestADroppedLogGapIsVisible(t *testing.T) {
	t.Parallel()

	frame := Render(demoModel(120, 40), NewTheme(ProfileNone), unicodeGlyphs)
	require.Contains(t, frame, "412 line(s) dropped")
}

// TestTwentySandboxesStayReadable: the pane says which slice of the fleet it is
// showing, and the rows it shows are whole.
func TestTwentySandboxesStayReadable(t *testing.T) {
	t.Parallel()

	m := withFleet(demoModel(80, 24), bigFleet())
	m.sbCursor = 12
	frame := Render(m, NewTheme(ProfileNone), unicodeGlyphs)
	require.Contains(t, frame, "13/20", "the pane does not say where in the fleet it is")
	require.Contains(t, frame, "20 sandboxes")
	require.Contains(t, frame, "node-13")
}

// TestScrollingIsStableAcrossRefreshes.
//
// The flicker a twenty-sandbox fleet must not have is a window that recentres
// on every keystroke: a one-row move repaints the whole pane. A page window
// moves only when the cursor leaves it, so most moves repaint two rows.
func TestScrollingIsStableAcrossRefreshes(t *testing.T) {
	t.Parallel()

	// Same cursor, same window, whatever else changed.
	require.Equal(t, windowStart(20, 5, 7), windowStart(20, 5, 7))

	// Moving within a window does not move it.
	first := windowStart(20, 5, 5)
	for c := 5; c < 10; c++ {
		require.Equal(t, first, windowStart(20, 5, c), "cursor %d moved the window", c)
	}
	require.NotEqual(t, first, windowStart(20, 5, 10))

	// The last window is flush with the end of the list rather than hanging
	// off it, so the final page is full rather than one row of twenty.
	require.Equal(t, 15, windowStart(20, 5, 19))
	require.Equal(t, 0, windowStart(3, 5, 2))

	// And a refresh that does not move the cursor produces an identical frame,
	// which is what "does not flicker on refresh" means for a diffing renderer.
	m := withFleet(demoModel(80, 24), bigFleet())
	m.sbCursor = 7
	before := Render(m, NewTheme(ProfileNone), unicodeGlyphs)
	m, _ = m.Step(sandboxesMsg{sandboxes: bigFleet(), at: fixedNow})
	require.Equal(t, before, Render(m, NewTheme(ProfileNone), unicodeGlyphs))
}

// TestGoldenFrames pins what the program actually looks like at the sizes that
// matter. Run with -update to rewrite them, and read the diff before you do.
func TestGoldenFrames(t *testing.T) {
	cases := []struct {
		name  string
		model Model
	}{
		{"80x24", demoModel(80, 24)},
		{"120x40", demoModel(120, 40)},
		{"160x50", demoModel(160, 50)},
		{"twenty-80x24", func() Model { m := withFleet(demoModel(80, 24), bigFleet()); m.sbCursor = 6; return m }()},
		{"stacked-70x14", withSize(demoModel(80, 24), 70, 14)},
		{"minimal-40x9", withSize(demoModel(80, 24), 40, 9)},
		{"ascii-80x24", demoModel(80, 24)},
		{"confirm-80x24", confirmModel()},
		{"signal-80x24", modeModel(modeSignal)},
		{"help-80x24", modeModel(modeHelp)},
		{"empty-80x24", emptyModel()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := unicodeGlyphs
			if strings.HasPrefix(tc.name, "ascii") {
				g = asciiGlyphs
			}
			// The golden files are rendered with no colour, so they are the
			// frame's text and nothing else. What colour does to a frame is
			// pinned by TestColourNeverChangesAWidth, which is a property
			// rather than a picture.
			got := Render(tc.model, NewTheme(ProfileNone), g)
			path := filepath.Join("testdata", tc.name+".frame")
			if *update {
				require.NoError(t, os.MkdirAll("testdata", 0o755))
				require.NoError(t, os.WriteFile(path, []byte(got+"\n"), 0o644))
				return
			}
			want, err := os.ReadFile(path)
			require.NoError(t, err, "missing golden frame; run `go test ./internal/tui -update`")
			// Carriage returns are stripped from the file rather than trusted
			// to be absent. These are the first golden *text* files in this
			// repository, and whether they arrive with LF or CRLF is a property
			// of whoever checked them out — Git for Windows converts by default.
			// A frame never contains one (SafeText drops control characters and
			// the lines are joined with "\n"), so this normalises the file and
			// compares the rendering exactly.
			golden := strings.ReplaceAll(string(want), "\r\n", "\n")
			require.Equal(t, strings.TrimSuffix(golden, "\n"), got)
		})
	}
}

// ------------------------------------------------------------- fixtures

func withSize(m Model, w, h int) Model {
	m.width, m.height = w, h
	m.clampScroll()
	return m
}

func withFleet(m Model, sandboxes []Sandbox) Model {
	m.sandboxes = sandboxes
	m.procFor, m.detailFor = "", ""
	m.processes, m.logs = nil, Logs{}
	return m
}

func emptyModel() Model {
	m := NewModel(DefaultSchedule, false)
	m.now, m.sbLoaded = fixedNow, true
	m.width, m.height = 80, 24
	return m
}

func confirmModel() Model {
	m, _ := press(demoModel(80, 24), "x")
	return m
}

func modeModel(md mode) Model {
	m := demoModel(80, 24)
	m.mode = md
	return m
}

// hostileModel is what a compromised sandbox would say about itself: escape
// sequences in every string this program takes from the far side.
func hostileModel() Model {
	const attack = "\x1b[2J\x1b[Hevil\x07\r\x1b]0;pwned\x07"
	m := demoModel(80, 24)
	m.sandboxes[0].Name = attack
	m.sandboxes[0].Detail = attack
	m.sandboxes[0].Platform = attack
	m.sandboxes[0].Agent = attack
	m.processes[0].Name = attack
	m.processes[0].LastLog = attack
	m.processes[0].AdoptionNote = attack
	m.logs.Lines = append(m.logs.Lines, LogLine{Text: attack})
	m.detail.Hostname = attack
	m.detail.Kernel = attack
	m.detail.Principal = attack
	m.detail.AllowedRoots = []string{attack}
	m.detail.Toolchains = []Toolchain{{Name: attack, Version: attack}}
	m.toolchains = true
	return m
}

func envOf(vals map[string]string) func(string) string {
	return func(k string) string { return vals[k] }
}

// TestTheDetailPaneCanReachWhatItClips.
//
// The detail pane holds more than an 80x24 terminal can show, and toolchains —
// which the operator has to press a key to ask for — are at the bottom of it. A
// pane that clipped them silently would make that key look broken.
func TestTheDetailPaneCanReachWhatItClips(t *testing.T) {
	t.Parallel()

	m := demoModel(80, 24)
	m.toolchains = true
	m.detail.ToolchainsAsked = true
	m.detail.Toolchains = []Toolchain{{Name: "go", Version: "1.25.0"}, {Name: "node", Version: "22.4.1"}}

	frame := Render(m, NewTheme(ProfileNone), unicodeGlyphs)
	require.Contains(t, frame, "more (↑↓)", "the pane clips without saying so")
	require.NotContains(t, frame, "toolchains")

	// Focus the pane and go to the bottom of it.
	m.focus = PaneDetail
	m, _ = press(m, "G")
	frame = Render(m, NewTheme(ProfileNone), unicodeGlyphs)
	require.Contains(t, frame, "toolchains")
	require.Contains(t, frame, "go 1.25.0")

	// And the scroll is clamped: nothing scrolls past the end, at any size.
	for _, size := range [][2]int{{80, 24}, {200, 60}, {40, 9}} {
		m = withSize(m, size[0], size[1])
		m, _ = press(m, "G", "G", "G")
		require.LessOrEqual(t, m.detailScroll, m.detailOverflow())
		for _, line := range strings.Split(Render(m, NewTheme(ProfileNone), unicodeGlyphs), "\n") {
			require.Equal(t, size[0], ansi.StringWidth(line))
		}
	}
}

// TestAsciiFramesCarryNoUnicode.
//
// The ASCII character set exists for terminals that are not reading UTF-8, and
// it is worth nothing if the arrows in the footer or an ellipsis in a status
// line are still multi-byte. Both were, and both were only visible by looking
// at a frame drawn under LANG=C.
func TestAsciiFramesCarryNoUnicode(t *testing.T) {
	t.Parallel()

	models := []Model{
		demoModel(80, 24),
		demoModel(120, 40),
		withSize(demoModel(80, 24), 60, 14),
		modeModel(modeHelp),
		modeModel(modeSignal),
		confirmModel(),
		emptyModel(),
		loadingModel(),
		// The status line, which is prose the model writes rather than the
		// renderer, and which carried the last hard-coded ellipsis in the
		// package.
		actedModel(),
		erroredModel(),
	}
	for i, m := range models {
		m.toolchains = true
		frame := Render(m, NewTheme(ProfileNone), asciiGlyphs)
		for _, r := range frame {
			require.Lessf(t, r, rune(0x80), "model %d: %q is not ASCII\n%s", i, r, frame)
		}
	}
}

// actedModel is the frame just after a confirmed action, whose status line is
// written by the model rather than the renderer.
func actedModel() Model {
	m, _ := press(demoModel(80, 24), "x", "y")
	return m
}

// erroredModel has a failure in every pane, so the wrapped error sentences are
// covered too.
func erroredModel() Model {
	m := demoModel(80, 24)
	boom := errors.New("no answer within the timeout")
	m, _ = m.Step(processesMsg{sandbox: "alpha", err: boom})
	m, _ = m.Step(detailMsg{sandbox: "alpha", err: boom})
	m, _ = m.Step(sandboxesMsg{err: boom, at: fixedNow})
	m.detail.AllowedRoots, m.detail.Unconfined = nil, true
	return m
}

// loadingModel is the state between starting up and the first answer, where
// most of the "…" strings live.
func loadingModel() Model {
	m := demoModel(80, 24)
	m.sbLoaded = false
	m.procFor, m.detailFor = "", ""
	m.processes, m.logs = nil, Logs{}
	m.logFor = logTarget{}
	return m
}

// TestWrapAdvancesThroughItsInput. It used to not, when the input carried a
// style: the same line came out twice, and no width check could see it.
func TestWrapAdvancesThroughItsInput(t *testing.T) {
	t.Parallel()

	const sentence = "roots: none - this sandbox is unconfined and that is worth saying out loud"
	lines := wrap(sentence, 20, 10)
	require.Greater(t, len(lines), 1)
	require.Equal(t, sentence, strings.Join(lines, " "), "wrapping lost or repeated text")
	for _, line := range lines {
		require.LessOrEqual(t, ansi.StringWidth(line), 20)
	}
	require.Len(t, wrap(sentence, 20, 2), 2, "the height bound is not honoured")

	// Styled, every line carries the style and none of them repeats.
	styled := wrapStyled(NewTheme(ProfileBasic).Warn, sentence, 20, 10)
	require.Len(t, styled, len(lines))
	seen := map[string]bool{}
	for _, line := range styled {
		require.Contains(t, line, "\x1b[")
		require.False(t, seen[line], "wrapStyled repeated %q", line)
		seen[line] = true
	}

	// And the unconfined warning, which is where this was found, reaches the
	// frame once.
	m := demoModel(120, 45)
	m.detail.AllowedRoots, m.detail.Unconfined = nil, true
	frame := Render(m, NewTheme(ProfileNone), unicodeGlyphs)
	require.Equal(t, 1, strings.Count(frame, "roots: none - this"), "the warning is drawn more than once")
	require.Contains(t, frame, "unconfined", "the wrap broke a word it had room to keep whole")
}

// TestAStatusLineNeverHidesAConfirmationPrompt.
//
// The footer is one line and three things want it, and the order is a safety
// property rather than a preference: a status line lasts six seconds, so any
// action at all leaves a window in which the next `x` would open a prompt the
// operator cannot see — while `y` still confirms it. Nothing tested the order,
// and swapping the two cases left this package green.
func TestAStatusLineNeverHidesAConfirmationPrompt(t *testing.T) {
	t.Parallel()

	// Stop something, let it report, then propose the next one inside the
	// window the report is still on screen for.
	m, _ := press(demoModel(80, 24), "x", "y")
	m, _ = m.Step(actionMsg{done: "stopped web-dev-server on alpha", attempted: "stop web-dev-server on alpha"})
	require.NotEmpty(t, m.status, "this test needs a status line to compete with")

	m.procCursor = 1
	m, _ = press(m, "x")
	require.Equal(t, modeConfirm, m.mode)

	frame := Render(m, NewTheme(ProfileNone), unicodeGlyphs)
	require.Contains(t, frame, "[y/N]", "the prompt is not on screen while a status line is")
	require.Contains(t, frame, `"queue-worker"`, "the prompt does not name the process it will stop")
	require.NotContains(t, frame, m.status, "the status line is drawn over the prompt")

	// And the signal picker outranks it for the same reason.
	picking := demoModel(80, 24)
	picking.status, picking.mode = "stopped web-dev-server on alpha", modeSignal
	require.Contains(t, Render(picking, NewTheme(ProfileNone), unicodeGlyphs), "SIGTERM")
}

// TestTheProgramsOwnMarkersStayAsciiHoweverLongASandboxIsWinded.
//
// Agent-supplied text is the agent's business: a CJK process name is not this
// program's to transliterate. Its own chrome is a different matter, and the
// bound it puts on a sandbox's reason for not answering is chrome — it used to
// mark the cut with "…", which reached an ASCII frame at every size the moment
// a reason ran past two hundred bytes. Nothing in the ASCII sweep was long
// enough to find it.
func TestTheProgramsOwnMarkersStayAsciiHoweverLongASandboxIsWinded(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("the agent refused this call and explains itself at length ", 8)
	require.Greater(t, len(long), maxDetailBytes)

	for _, size := range [][2]int{{80, 24}, {120, 40}, {160, 50}} {
		m := demoModel(size[0], size[1])
		m.sandboxes[0].Detail = oneLine(long)
		m.processes = nil
		m, _ = m.Step(processesMsg{sandbox: "alpha", err: errors.New(long)})
		m, _ = m.Step(detailMsg{sandbox: "alpha", err: errors.New(long)})

		frame := Render(m, NewTheme(ProfileNone), asciiGlyphs)
		for _, r := range frame {
			require.Lessf(t, r, rune(0x80), "%dx%d: %q is not ASCII\n%s", size[0], size[1], r, frame)
		}
	}

	// The cut is still marked: an unmarked one reads as the whole reason.
	require.Contains(t, oneLine(long), asciiGlyphs.Ellipsis)
	require.LessOrEqual(t, len(oneLine(long)), maxDetailBytes+len(asciiGlyphs.Ellipsis))
	require.Equal(t, "short enough", oneLine("short enough"))
}

// TestOneFailureReadsTheSameWayEverywhere.
//
// The panes used to print the raw gRPC error while the fleet row printed the
// mapped one, so an unreachable sandbox was described two ways on one screen —
// five wrapped lines of "transport: Error while dialing…" beside a row saying
// "no answer within the timeout" about the same event.
func TestOneFailureReadsTheSameWayEverywhere(t *testing.T) {
	t.Parallel()

	unreachable := status.Error(codes.Unavailable, `connection error: desc = "transport: Error while dialing: dial tcp 127.0.0.1:49001: connect: connection refused"`)

	// Wide enough for the fleet pane's DETAIL column, which is where the row's
	// half of the comparison is.
	m := demoModel(140, 40)
	m.sandboxes[0].Health, m.sandboxes[0].Detail = client.HealthUnreachable, probeDetail(unreachable)
	m.processes = nil
	m.logs = Logs{}
	m, _ = m.Step(processesMsg{sandbox: "alpha", err: unreachable})
	m, _ = m.Step(detailMsg{sandbox: "alpha", err: unreachable})

	frame := Render(m, NewTheme(ProfileNone), unicodeGlyphs)
	require.NotContains(t, frame, "transport:", "a raw gRPC error reached a pane")
	require.NotContains(t, frame, "rpc error")
	require.GreaterOrEqual(t, strings.Count(frame, "no answer within the timeout"), 2,
		"the panes and the fleet row do not describe the failure the same way")
}

// TestNothingASandboxSaysCanMoveTheCursorFromTheFooterEither.
//
// The footer was the one string in a frame that did not go through [safe].
// Both things that land in it are far-side text: a confirmation prompt names a
// sandbox, and a status line is built from a sandbox name — and, once #43
// lands, from whatever [Status] the shell hook reports back with, which is a
// program on somebody else's machine describing how it exited.
//
// The sweep in TestNothingASandboxSaysCanMoveTheCursor could not see this: it
// renders in normal mode with no status set, which is the one state where the
// footer holds nothing but the program's own key hints.
func TestNothingASandboxSaysCanMoveTheCursorFromTheFooterEither(t *testing.T) {
	t.Parallel()

	const attack = "\x1b[2J\x1b[Hevil\x07\r\x1b]0;pwned\x07"

	// A prompt built the way the model builds one. %q is what keeps this
	// particular string safe today — it renders a control character as the
	// four printable bytes "\x1b" — so this case is the second lock rather
	// than the first, and it is here to fail if that ever becomes %s.
	confirming := demoModel(120, 40)
	confirming.sandboxes[0].Name = attack
	confirming.procFor = attack
	confirming, _ = press(confirming, "x")
	require.Equal(t, modeConfirm, confirming.mode)
	require.NotContains(t, confirming.confirm.Prompt, "\x1b", "the prompt is built with %q, which is what quotes the escape")

	// And a prompt that reached the footer unquoted, which is what the
	// renderer's own sanitising is for: the footer draws what it is given.
	raw := demoModel(120, 40)
	raw.confirm = Confirmation{Prompt: "Stop " + attack + "?", Effect: Effect{Kind: EffectSignal}}
	raw.mode = modeConfirm

	reported := demoModel(120, 40)
	reported, _ = reported.Step(Status("shell on " + attack + " exited 3"))

	acted := demoModel(120, 40)
	acted.sandboxes[0].Name = attack
	acted.procFor = attack
	acted, _ = press(acted, "x", "y")

	failed := demoModel(120, 40)
	failed.sandboxes[0].Name = attack
	failed.procFor = attack
	failed, _ = failed.Step(actionMsg{
		done:      "stopped web-dev-server on " + attack,
		attempted: "stop web-dev-server on " + attack,
		err:       status.Error(codes.PermissionDenied, "no"),
	})

	for name, m := range map[string]Model{
		"a confirmation prompt": confirming,
		"an unquoted prompt":    raw,
		"a hook's status":       reported,
		"an action in progress": acted,
		"a refused action":      failed,
	} {
		for _, size := range [][2]int{{80, 24}, {120, 40}, {40, 9}} {
			m := withSize(m, size[0], size[1])
			frame := Render(m, NewTheme(ProfileNone), unicodeGlyphs)
			require.NotContainsf(t, frame, "\x1b", "%s at %dx%d put an escape on the screen", name, size[0], size[1])
			require.NotContainsf(t, frame, "\a", "%s at %dx%d", name, size[0], size[1])
			require.NotContainsf(t, frame, "\r", "%s at %dx%d", name, size[0], size[1])
			require.Containsf(t, frame, "evil", "%s at %dx%d lost the text either side of the escape", name, size[0], size[1])
		}
	}
}

// TestTheFooterAlwaysOffersQuitAndHelp. An operator who can find neither is
// stuck inside a full-screen program, so those two hints are the ones the
// narrowing is not allowed to drop.
func TestTheFooterAlwaysOffersQuitAndHelp(t *testing.T) {
	t.Parallel()

	for w := minWidth; w <= 200; w++ {
		for _, h := range []int{minHeight, 9, 14, 24, 60} {
			m := withSize(demoModel(80, 24), w, h)
			lines := strings.Split(Render(m, NewTheme(ProfileNone), unicodeGlyphs), "\n")
			footer := lines[len(lines)-1]
			require.Containsf(t, footer, "q quit", "%dx%d: the footer does not say how to leave", w, h)
			require.Containsf(t, footer, "? help", "%dx%d: the footer does not say where the keys are", w, h)
		}
	}
}
