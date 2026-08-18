package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/x/ansi"

	"github.com/axelmierczuk/fleet-mcp/internal/cli"
	"github.com/axelmierczuk/fleet-mcp/internal/client"
)

// Rendering, and the one invariant that keeps a terminal from being corrupted:
//
//	a frame is exactly Height lines, and every line is exactly Width columns.
//
// Nothing below writes a line without going through [fit], which measures in
// display columns rather than bytes or runes — a CJK name is two columns per
// rune and an emoji in a process name is two more, and a table laid out in
// runes puts the right-hand border of a pane one column further right on the
// row that contains one. That is what "corrupt" looks like in practice, and it
// survives a resize, so it is worth measuring properly.
//
// Styles are applied only to text that has already been fitted. Every escape
// sequence this package emits is an SGR sequence, which occupies no cells, so
// styling cannot change a line's width. Nothing here moves the cursor: the
// position of every character is decided by the string, not by an escape.

// Glyphs are the box-drawing characters a frame is built from.
//
// Two sets, because the frame has to be legible on a terminal that is not
// reading UTF-8. Over ssh to a host with a POSIX locale, or on a Windows
// console on a legacy code page, a box-drawing character arrives as mojibake —
// often as more than one cell — and a border that is wider than it measures is
// exactly the corruption the invariant above exists to prevent.
type Glyphs struct {
	H, V, TL, TR, BL, BR string
	Ellipsis             string
	Bullet               string
	// Arrows names the movement keys in the footer. It is here rather than in
	// a string literal for the same reason the borders are: "↑↓" on a terminal
	// that is not reading UTF-8 is four bytes of noise where the operator is
	// being told how to move.
	Arrows string
}

var unicodeGlyphs = Glyphs{H: "─", V: "│", TL: "┌", TR: "┐", BL: "└", BR: "┘", Ellipsis: "…", Bullet: "●", Arrows: "↑↓"}
var asciiGlyphs = Glyphs{H: "-", V: "|", TL: "+", TR: "+", BL: "+", BR: "+", Ellipsis: "...", Bullet: "*", Arrows: "up/dn"}

// DetectGlyphs picks the character set from the locale.
//
// The locale variables are the only portable statement a terminal makes about
// its encoding, and ssh forwards them. Absent or non-UTF-8, this falls back to
// ASCII rather than hoping: a frame drawn in dashes is plain, and a frame drawn
// in replacement characters is unreadable.
func DetectGlyphs(env func(string) string) Glyphs {
	for _, key := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		v := strings.ToLower(env(key))
		if v == "" {
			continue
		}
		if strings.Contains(v, "utf-8") || strings.Contains(v, "utf8") {
			return unicodeGlyphs
		}
		return asciiGlyphs
	}
	return asciiGlyphs
}

// Render draws one frame. It is a pure function of the model, the palette and
// the character set, which is what lets the golden files exist.
func Render(m Model, t Theme, g Glyphs) string {
	l := computeLayout(m.width, m.height, m.focus)
	if l.Mode == ModeTooSmall {
		return renderTooSmall(m, g)
	}

	rows := make([]string, l.Height)
	rows[0] = renderHeader(m, t, g, l)
	rows[l.Height-1] = renderFooter(m, t, g, l)

	// Help replaces the body rather than floating over it. A pane-shaped
	// overlay drawn on top of a table has to know what it covered to undraw
	// it, and getting that wrong is a smear that survives until the next full
	// repaint.
	if m.mode == modeHelp {
		copy(rows[l.Body.y:], helpPane(m, t, g, l.Body))
		return strings.Join(rows, "\n")
	}

	drawn := map[Pane][]string{}
	for _, p := range panes {
		b, ok := l.Boxes[p]
		if !ok {
			continue
		}
		drawn[p] = renderPane(m, t, g, p, b)
	}

	// Compose row by row. The boxes tile the body exactly in every mode, but
	// composing from the boxes rather than from the mode means a layout that
	// ever failed to tile shows as a gap of spaces rather than as a line of
	// the wrong width.
	for y := l.Body.y; y < l.Body.y+l.Body.h && y < l.Height-1; y++ {
		var b strings.Builder
		x := 0
		for _, p := range panesAtRow(l, y) {
			box := l.Boxes[p]
			if box.x > x {
				b.WriteString(strings.Repeat(" ", box.x-x))
			}
			b.WriteString(drawn[p][y-box.y])
			x = box.x + box.w
		}
		rows[y] = fit(b.String(), l.Width, g)
	}
	for i, r := range rows {
		if r == "" {
			rows[i] = strings.Repeat(" ", l.Width)
		}
	}
	return strings.Join(rows, "\n")
}

// panesAtRow lists the panes covering an output row, left to right.
func panesAtRow(l Layout, y int) []Pane {
	var out []Pane
	for _, p := range panes {
		b, ok := l.Boxes[p]
		if ok && y >= b.y && y < b.y+b.h {
			out = append(out, p)
		}
	}
	// panes is in tab order, which for the layouts here is also left-to-right
	// within a row except for processes and detail; sort by x to be sure.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && l.Boxes[out[j]].x < l.Boxes[out[j-1]].x; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// renderTooSmall is what a terminal below the minimum gets: one sentence,
// still fitted, because "too small to draw" is not a licence to write past the
// edge of the screen.
func renderTooSmall(m Model, g Glyphs) string {
	w := atLeast(m.width, 1)
	rows := make([]string, atLeast(m.height, 1))
	for i := range rows {
		rows[i] = strings.Repeat(" ", w)
	}
	// Widest that fits, down to the size itself. The message is the only thing
	// on the screen, so a message that does not fit on it is the one failure
	// this branch could have.
	for _, msg := range []string{
		fmt.Sprintf("terminal is %dx%d; need at least %dx%d", m.width, m.height, minWidth, minHeight),
		fmt.Sprintf("need at least %dx%d", minWidth, minHeight),
		fmt.Sprintf("need %dx%d", minWidth, minHeight),
		fmt.Sprintf("%dx%d", minWidth, minHeight),
	} {
		if ansi.StringWidth(msg) <= w {
			rows[len(rows)/2] = fit(msg, w, g)
			break
		}
	}
	return strings.Join(rows, "\n")
}

// ---------------------------------------------------------------- chrome

func renderHeader(m Model, t Theme, g Glyphs, l Layout) string {
	left := "fleetctl tui"
	counts := fleetSummary(m.sandboxes)
	right := counts
	if m.sbState.err != nil {
		right = "fleet: " + paneError(m.sbState.err)
	}
	gap := l.Width - ansi.StringWidth(left) - ansi.StringWidth(right) - 2
	if gap < 1 {
		// No room for both. The summary goes rather than the name, because a
		// full-screen program that does not say what it is has no other place
		// to say it.
		return fit(" "+t.Header.apply(left), l.Width, g)
	}
	return fit(" "+t.Header.apply(left)+strings.Repeat(" ", gap)+t.Dim.apply(right)+" ", l.Width, g)
}

// fleetSummary counts the fleet by health, in the health vocabulary rather than
// in words of this package's own.
func fleetSummary(sandboxes []Sandbox) string {
	if len(sandboxes) == 0 {
		return "no sandboxes"
	}
	byHealth := map[string]int{}
	for _, sb := range sandboxes {
		byHealth[sb.Health]++
	}
	parts := []string{fmt.Sprintf("%d sandboxes", len(sandboxes))}
	for _, h := range []string{client.HealthServing, client.HealthDegraded, client.HealthDraining, client.HealthUnreachable, client.HealthUnknown} {
		if n := byHealth[h]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, h))
		}
	}
	return strings.Join(parts, "  ")
}

// renderFooter is the confirmation prompt if there is one, the status line if
// there is one, and the key hints otherwise — in that order, because a prompt
// that a status line could hide is not a prompt.
func renderFooter(m Model, t Theme, g Glyphs, l Layout) string {
	switch {
	case m.mode == modeConfirm:
		// The choice is fitted first and the prompt gets whatever is left. A
		// prompt long enough to push "[y/N]" off the end of an 80-column
		// terminal would leave the operator looking at a question with no
		// visible answer, which is the one way this footer can fail.
		const choice = "  [y/N]"
		room := l.Width - 1 - ansi.StringWidth(choice)
		return fit(" "+t.Alarm.apply(clipToWidth(m.confirm.Prompt, room, g)+choice), l.Width, g)
	case m.mode == modeSignal:
		return fit(" "+t.Alarm.apply("signal: ")+signalChoices(m, t), l.Width, g)
	case m.status != "":
		return fit(" "+t.Warn.apply(m.status), l.Width, g)
	default:
		return fit(" "+t.Dim.apply(hints(m, g, l)), l.Width, g)
	}
}

func signalChoices(m Model, t Theme) string {
	parts := make([]string, 0, len(signals))
	for i, s := range signals {
		label := fmt.Sprintf("%d SIG%s", i+1, s)
		if i == m.sigIdx {
			label = t.Selected.apply(label)
		}
		parts = append(parts, label)
	}
	return strings.Join(parts, "  ")
}

// hints are the keys, shortened as the terminal narrows. The two that must
// never be dropped are quit and help: an operator who cannot find either is
// stuck in a full-screen program.
func hints(m Model, g Glyphs, l Layout) string {
	act := "r restart"
	if p, ok := m.selectedProcess(); ok && !isLive(p.State) {
		act = "r start"
	}
	short := "? help   q quit"
	// Widest first; the first one that fits wins. Anything that does not fit is
	// dropped whole rather than truncated, because a hint cut off mid-word
	// ("? hel…") is worse than no hint: it looks like corruption.
	for _, h := range []string{
		"tab pane   " + g.Arrows + " move   enter focus   " + act + "   x stop   S signal   s shell   f follow   " + short,
		"tab pane   " + g.Arrows + " move   " + act + "   x stop   S signal   f follow   " + short,
		"tab pane   " + act + "   x stop   S signal   " + short,
		short,
	} {
		if ansi.StringWidth(h)+2 <= l.Width {
			return h
		}
	}
	return short
}

// renderPane draws one bordered pane, exactly b.h lines of exactly b.w columns.
func renderPane(m Model, t Theme, g Glyphs, p Pane, b box) []string {
	w, h := b.interior()
	out := make([]string, b.h)
	if w <= 0 || h <= 0 {
		for i := range out {
			out[i] = strings.Repeat(" ", atLeast(b.w, 0))
		}
		return out
	}

	border := t.Chrome
	if p == m.focus {
		border = t.Focused
	}

	title, subtitle := paneTitle(m, p)
	out[0] = border.apply(paneTop(g, b.w, title, subtitle))
	out[b.h-1] = border.apply(g.BL + strings.Repeat(g.H, b.w-2) + g.BR)

	body := paneBody(m, t, g, p, w, h)
	for i := 0; i < h; i++ {
		line := ""
		if i < len(body) {
			line = body[i]
		}
		out[i+1] = border.apply(g.V) + fit(line, w, g) + border.apply(g.V)
	}
	return out
}

// paneTop draws the top border with the pane's name in it, and its subtitle
// right-aligned when there is room. The subtitle is dropped rather than
// wrapped: a border is one line by definition.
func paneTop(g Glyphs, w int, title, subtitle string) string {
	label := " " + title + " "
	rest := w - 2 - ansi.StringWidth(label)
	if rest < 0 {
		return g.TL + strings.Repeat(g.H, atLeast(w-2, 0)) + g.TR
	}
	tail := strings.Repeat(g.H, rest)
	if subtitle != "" {
		sub := " " + subtitle + " "
		if n := ansi.StringWidth(sub); n+2 <= rest {
			tail = strings.Repeat(g.H, rest-n-1) + sub + g.H
		}
	}
	return g.TL + label + tail + g.TR
}

func paneTitle(m Model, p Pane) (title, subtitle string) {
	switch p {
	case PaneFleet:
		if n := len(m.sandboxes); n > 0 {
			return "fleet", fmt.Sprintf("%d/%d", clamp(m.sbCursor, 0, n-1)+1, n)
		}
		return "fleet", ""
	case PaneProcesses:
		return "processes", staleMark(m.procState, m.focusedName())
	case PaneLogs:
		if p, ok := m.selectedProcess(); ok {
			mark := staleMark(m.logState, p.Name)
			if !m.logFollow {
				mark += " paused"
			}
			return "logs", mark
		}
		return "logs", ""
	case PaneDetail:
		return "detail", staleMark(m.detailState, m.focusedName())
	}
	return p.Title(), ""
}

// staleMark says when what is on screen predates a failure, so a pane holding
// the last thing it saw does not read as a pane holding the truth.
func staleMark(s paneState, subject string) string {
	if s.err != nil && s.stale {
		return safe(subject) + " (stale)"
	}
	return safe(subject)
}

// ----------------------------------------------------------- pane bodies

func paneBody(m Model, t Theme, g Glyphs, p Pane, w, h int) []string {
	switch p {
	case PaneFleet:
		return fleetBody(m, t, g, w, h)
	case PaneProcesses:
		return processBody(m, t, g, w, h)
	case PaneLogs:
		return logBody(m, t, g, w, h)
	case PaneDetail:
		return detailBody(m, t, g, w, h)
	}
	return nil
}

// column is one column of a fixed-width table.
type column struct {
	head string
	w    int
	// grow marks a column that shares whatever width is left over, between w
	// and maxW.
	grow bool
	maxW int
	// minTotal is the table width below which this column is dropped.
	minTotal int
}

// layoutColumns drops the columns that do not fit and shares the rest of the
// width between the ones that grow.
//
// Dropping whole columns rather than shrinking every column is why a narrow
// pane stays a table instead of becoming a column of ellipses. Capping the
// growing ones is why a wide terminal does not spend forty columns on a
// sandbox name to squeeze the reason it is unreachable into twelve.
func layoutColumns(cols []column, w int) []column {
	out := make([]column, 0, len(cols))
	for _, c := range cols {
		if c.minTotal > 0 && w < c.minTotal {
			continue
		}
		out = append(out, c)
	}
	used, gaps := 0, len(out)-1
	for _, c := range out {
		used += c.w
	}
	spare := w - used - gaps

	// Round-robin, one column at a time, so a narrow surplus is shared rather
	// than swallowed by whichever column happens to be first.
	for spare > 0 {
		gave := false
		for i := range out {
			if spare == 0 {
				break
			}
			if !out[i].grow || (out[i].maxW > 0 && out[i].w >= out[i].maxW) {
				continue
			}
			out[i].w++
			spare--
			gave = true
		}
		if !gave {
			break
		}
	}
	return out
}

func headerRow(t Theme, g Glyphs, cols []column) string {
	cells := make([]string, len(cols))
	for i, c := range cols {
		cells[i] = fit(c.head, c.w, g)
	}
	return t.Header.apply(strings.Join(cells, " "))
}

// windowStart scrolls a list a page at a time rather than a line at a time.
//
// A window that recentres on every keystroke redraws the whole pane for a
// one-row move, which is the flicker a twenty-sandbox fleet must not have. A
// page window changes only when the cursor leaves it, so most moves repaint two
// rows, and it is a pure function of the cursor — no remembered scroll offset
// to get out of step with a list that changed underneath it.
func windowStart(total, height, cursor int) int {
	if height <= 0 || total <= height {
		return 0
	}
	start := (cursor / height) * height
	if start > total-height {
		start = total - height
	}
	return atLeast(start, 0)
}

func fleetBody(m Model, t Theme, g Glyphs, w, h int) []string {
	if !m.sbLoaded && m.sbState.err == nil {
		return []string{t.Dim.apply("reading the registry" + g.Ellipsis)}
	}
	if len(m.sandboxes) == 0 {
		return []string{
			"no sandboxes enrolled",
			t.Dim.apply("fleetctl enroll mint --name <name> --address <host:port>"),
		}
	}

	cols := layoutColumns([]column{
		{head: "", w: 1},
		{head: "NAME", w: 10, grow: true, maxW: 28},
		{head: "PLATFORM", w: 13, minTotal: 62},
		{head: "AGENT", w: 10, minTotal: 74},
		{head: "HEALTH", w: 11},
		{head: "LAST SEEN", w: 9, minTotal: 46},
		{head: "DETAIL", w: 12, grow: true, maxW: 48, minTotal: 92},
	}, w)

	rows := make([]string, 0, h)
	rows = append(rows, headerRow(t, g, cols))
	body := h - 1
	start := windowStart(len(m.sandboxes), body, m.sbCursor)
	for i := start; i < len(m.sandboxes) && len(rows) <= body; i++ {
		sb := m.sandboxes[i]
		hs := t.healthStyle(sb.Health)
		values := map[string]string{
			"":          g.Bullet,
			"NAME":      sb.Name,
			"PLATFORM":  sb.Platform,
			"AGENT":     sb.Agent,
			"HEALTH":    sb.Health,
			"LAST SEEN": cli.RelativeTime(sb.LastSeen, m.now),
			"DETAIL":    sb.Detail,
		}
		styles := map[string]style{"": hs, "HEALTH": hs}
		rows = append(rows, tableRow(t, g, cols, values, styles, i == m.sbCursor && m.focus == PaneFleet, w))
	}
	return rows
}

func processBody(m Model, t Theme, g Glyphs, w, h int) []string {
	sb, ok := m.selectedSandbox()
	if !ok {
		return []string{t.Dim.apply("no sandbox selected")}
	}
	if m.procFor != sb.Name && m.procState.err == nil {
		return []string{t.Dim.apply("asking " + safe(sb.Name) + g.Ellipsis)}
	}
	if len(m.processes) == 0 {
		if m.procState.err != nil {
			return wrapStyled(t.Bad, paneError(m.procState.err), w, h)
		}
		return []string{t.Dim.apply("no supervised processes on " + safe(sb.Name))}
	}

	cols := layoutColumns([]column{
		{head: "STATE", w: 10},
		{head: "NAME", w: 10, grow: true, maxW: 26},
		{head: "PID", w: 6, minTotal: 30},
		{head: "UPTIME", w: 7, minTotal: 38},
		{head: "RST", w: 3, minTotal: 44},
		{head: "PORTS", w: 11, minTotal: 56},
		{head: "LAST LOG", w: 14, grow: true, maxW: 48, minTotal: 92},
	}, w)

	rows := make([]string, 0, h)
	rows = append(rows, headerRow(t, g, cols))
	body := h - 1
	start := windowStart(len(m.processes), body, m.procCursor)
	for i := start; i < len(m.processes) && len(rows) <= body; i++ {
		p := m.processes[i]
		values := map[string]string{
			"STATE":    p.State,
			"NAME":     p.Name,
			"PID":      pidCell(p),
			"UPTIME":   p.Uptime,
			"RST":      restartCell(p),
			"PORTS":    portsCell(p.Ports),
			"LAST LOG": p.LastLog,
		}
		styles := map[string]style{"STATE": t.processStyle(p.State)}
		rows = append(rows, tableRow(t, g, cols, values, styles, i == m.procCursor && m.focus == PaneProcesses, w))
	}
	return rows
}

func pidCell(p Process) string {
	if p.PID == 0 {
		return "-"
	}
	return fmt.Sprintf("%d", p.PID)
}

func restartCell(p Process) string {
	if p.Restarts == 0 {
		return "-"
	}
	return fmt.Sprintf("%d", p.Restarts)
}

func portsCell(ports []uint32) string {
	if len(ports) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, fmt.Sprintf("%d", p))
	}
	return strings.Join(parts, ",")
}

// tableRow assembles one row, styling cells before joining so that a style can
// never change the row's width.
//
// Every value goes through [safe] on the way in. The source already sanitises
// what a sandbox says about itself, and this is the second lock on the same
// door: an escape sequence reaching a cell would be invisible to every
// width-based check in this file — ansi.StringWidth measures it as zero columns
// — and would corrupt the frame anyway, because the terminal acts on it.
func tableRow(t Theme, g Glyphs, cols []column, values map[string]string, styles map[string]style, selected bool, w int) string {
	cells := make([]string, len(cols))
	for i, c := range cols {
		text := fit(safe(values[c.head]), c.w, g)
		if !selected {
			if s, ok := styles[c.head]; ok {
				text = s.apply(text)
			}
		}
		cells[i] = text
	}
	row := strings.Join(cells, " ")
	if selected {
		// The selected row is reverse video over the whole row rather than a
		// colour per cell: reverse video needs no colour support at all, so
		// the selection survives NO_COLOR, which is the one piece of state an
		// operator cannot afford to lose track of before a confirmation.
		return t.Selected.apply(fit(row, w, g))
	}
	return row
}

func logBody(m Model, t Theme, g Glyphs, w, h int) []string {
	p, ok := m.selectedProcess()
	if !ok {
		return []string{t.Dim.apply("no process selected")}
	}
	if len(m.logs.Lines) == 0 {
		if m.logState.err != nil {
			return wrapStyled(t.Bad, paneError(m.logState.err), w, h)
		}
		if m.logFor.processID != p.ID {
			return []string{t.Dim.apply("reading " + safe(p.Name) + "'s output" + g.Ellipsis)}
		}
		return []string{t.Dim.apply(safe(p.Name) + " has produced no output")}
	}

	// An adoption note is not output, but it is the answer to the question a
	// process reading "orphaned" raises, and this is the only pane with room
	// for a sentence. It is pinned above the log rather than mixed into it.
	var out []string
	if p.AdoptionNote != "" {
		out = append(out, t.Warn.apply(clipToWidth("! "+safe(p.AdoptionNote), w, g)))
		h--
	}

	n := len(m.logs.Lines)
	end := clamp(n-m.logScroll, 0, n)
	start := atLeast(end-h, 0)
	for _, line := range m.logs.Lines[start:end] {
		text := clipToWidth(safe(line.Text), w, g)
		if line.Marker {
			// A gap in the log is not output, so it is not rendered as output.
			text = t.Warn.apply(text)
		}
		out = append(out, text)
	}
	return out
}

// detailBody windows the detail fields onto the pane, marking the ones it
// could not show. An operator who asked for toolchains and got a pane that
// silently ended above them would conclude the probe had failed.
func detailBody(m Model, t Theme, g Glyphs, w, h int) []string {
	lines := detailLines(m, t, g, w)
	if len(lines) <= h {
		return lines
	}
	start := clamp(m.detailScroll, 0, len(lines)-h)
	out := append([]string(nil), lines[start:start+h]...)
	if rest := len(lines) - start - h; rest > 0 {
		// Short enough to survive the narrowest detail pane there is: a
		// marker that is itself truncated tells the reader nothing.
		out[h-1] = t.Dim.apply(fit(fmt.Sprintf("%s %d more (%s)", g.Ellipsis, rest, g.Arrows), w, g))
	}
	return out
}

// detailLines is every line the detail pane would show if it had the room.
func detailLines(m Model, t Theme, g Glyphs, w int) []string {
	sb, ok := m.selectedSandbox()
	if !ok {
		return []string{t.Dim.apply("no sandbox selected")}
	}
	d := m.detail
	if m.detailFor != sb.Name {
		d = Detail{}
	}

	var out []string
	field := func(label, value string) {
		if value == "" {
			return
		}
		out = append(out, fit(t.Dim.apply(fit(label, 9, g))+" "+safe(value), w, g))
	}
	// Ordered by what an 80x24 terminal can afford to show, most useful first:
	// the pane is short, and everything past its last line is not shown at all.
	// Resources and roots come before kernel and hostname because they are what
	// the issue asks this pane for and what an operator is looking at it to
	// find out.
	field("sandbox", sb.Name)
	field("address", sb.Address)
	out = append(out, fit(t.Dim.apply(fit("health", 9, g))+" "+t.healthStyle(sb.Health).apply(safe(sb.Health)), w, g))
	if sb.Detail != "" {
		field("detail", sb.Detail)
	}
	field("platform", firstNonEmpty(d.Platform, sb.Platform))
	field("agent", firstNonEmpty(d.Agent, sb.Agent))
	if d.CPUCores > 0 {
		field("cpu", fmt.Sprintf("%d cores", d.CPUCores))
	}
	if d.MemoryTotal != "" {
		field("memory", fmt.Sprintf("%s of %s", dash(d.MemoryAvailable), d.MemoryTotal))
	}
	if d.DiskTotal != "" {
		field("disk", fmt.Sprintf("%s of %s", dash(d.DiskAvailable), d.DiskTotal))
	}
	if d.Load1m > 0 {
		field("load", fmt.Sprintf("%.2f (1m)", d.Load1m))
	}

	switch {
	case d.Unconfined && m.detailFor == sb.Name:
		// Said out loud, because an absent roots list reads exactly like
		// "nowhere is writable" when it means the opposite.
		out = append(out, wrapStyled(t.Warn, "roots: none - this sandbox is unconfined", w, 2)...)
	case len(d.AllowedRoots) > 0:
		field("roots", fmt.Sprintf("%d", len(d.AllowedRoots)))
		for _, root := range d.AllowedRoots {
			out = append(out, fit("  "+safe(root), w, g))
		}
	}
	field("uptime", d.Uptime)
	field("kernel", d.Kernel)
	field("hostname", d.Hostname)
	field("principal", d.Principal)
	if m.toolchains {
		switch {
		case len(d.Toolchains) > 0:
			out = append(out, t.Header.apply(fit("toolchains", w, g)))
			for _, tc := range d.Toolchains {
				out = append(out, fit("  "+safe(tc.Name+" "+tc.Version), w, g))
			}
		case d.ToolchainsAsked:
			field("toolchains", "none detected")
		default:
			field("toolchains", "probing"+g.Ellipsis)
		}
	}
	if m.detailState.err != nil {
		out = append(out, wrapStyled(t.Bad, paneError(m.detailState.err), w, 2)...)
	}
	return out
}

// helpKeys is the whole keymap, in one place, so the help and the program
// cannot disagree about what a key does.
var helpKeys = [][2]string{
	{"tab / shift+tab", "move between panes"},
	{"up/down, j/k", "move within the focused pane"},
	{"pgup / pgdn", "move a page"},
	{"g / G", "first / last"},
	{"enter", "focus the selected sandbox and read its processes"},
	{"r", "restart the selected process; start it, if it has exited"},
	{"x", "stop the selected process (SIGTERM, then SIGKILL)"},
	{"S", "send a specific signal to the selected process"},
	{"s", "open a shell on the focused sandbox"},
	{"f", "pause or resume log following"},
	{"t", "probe the focused sandbox for toolchains (slower)"},
	{"ctrl+r", "refresh everything now"},
	{"? / q", "this help / quit"},
}

// helpPane draws the keymap over the body.
func helpPane(m Model, t Theme, g Glyphs, b box) []string {
	w, h := b.interior()
	out := make([]string, b.h)
	if w <= 0 || h <= 0 {
		for i := range out {
			out[i] = strings.Repeat(" ", atLeast(b.w, 0))
		}
		return out
	}
	out[0] = t.Focused.apply(paneTop(g, b.w, "keys", "any key closes"))
	out[b.h-1] = t.Focused.apply(g.BL + strings.Repeat(g.H, b.w-2) + g.BR)

	lines := make([]string, 0, len(helpKeys)+2)
	for _, k := range helpKeys {
		what := k[1]
		if k[0] == "s" && !m.shellWired {
			what = "not in this build; see fleetctl shell (#43)"
		}
		lines = append(lines, t.Header.apply(fit(k[0], 16, g))+" "+what)
	}
	lines = append(lines,
		"",
		t.Dim.apply("Every action that changes a sandbox asks first, naming both the"),
		t.Dim.apply("sandbox and the process."),
	)
	for i := 0; i < h; i++ {
		line := ""
		if i < len(lines) {
			line = lines[i]
		}
		out[i+1] = t.Focused.apply(g.V) + fit(line, w, g) + t.Focused.apply(g.V)
	}
	return out
}

// --------------------------------------------------------------- helpers

// fit truncates s to w display columns and pads it to exactly w.
//
// Everything drawn goes through here. ansi.StringWidth measures the columns a
// terminal will actually use — two for a wide rune, none for an escape — which
// is the only measurement that keeps a border where it belongs.
func fit(s string, w int, g Glyphs) string {
	if w <= 0 {
		return ""
	}
	s = clipToWidth(s, w, g)
	if pad := w - ansi.StringWidth(s); pad > 0 {
		s += strings.Repeat(" ", pad)
	}
	return s
}

// clipToWidth truncates without padding, marking the cut.
func clipToWidth(s string, w int, g Glyphs) string {
	if w <= 0 {
		return ""
	}
	if ansi.StringWidth(s) <= w {
		return s
	}
	return ansi.Truncate(s, w, g.Ellipsis)
}

// wrapStyled breaks a sentence across at most h lines of w columns and styles
// each of them. It is for the one-off sentences — an error, a warning — not for
// tables.
//
// Wrapping first and styling second is not a preference: this used to style
// first and wrap the result, and it silently repeated a line. The wrap advanced
// through the text by trimming off what it had already emitted, and an escape
// sequence at the front of the input meant the piece it emitted was no longer a
// byte-prefix of the input, so nothing was trimmed and the same first line came
// out twice. Nothing about the frame's width was wrong, so no size check could
// see it; it was found by reading a screen.
func wrapStyled(st style, s string, w, h int) []string {
	lines := wrap(s, w, h)
	for i, line := range lines {
		lines[i] = st.apply(line)
	}
	return lines
}

// wrap breaks plain text across at most h lines of w columns, at spaces where
// it can and mid-word only for a word too long to fit on a line of its own.
//
// Plain: it measures what it is given, so styled input would have its escape
// sequences counted as text. See wrapStyled.
func wrap(s string, w, h int) []string {
	if w <= 0 || h <= 0 {
		return nil
	}
	var (
		out   []string
		line  string
		width int
	)
	flush := func() bool {
		out = append(out, line)
		line, width = "", 0
		return len(out) < h
	}
	for _, word := range strings.Fields(s) {
		ww := ansi.StringWidth(word)
		switch {
		case width == 0 && ww <= w:
			line, width = word, ww
		case width+1+ww <= w:
			line, width = line+" "+word, width+1+ww
		default:
			if width > 0 && !flush() {
				return out
			}
			// A word longer than the whole line has to be cut somewhere.
			for ansi.StringWidth(word) > w {
				head := ansi.Truncate(word, w, "")
				line = head
				if !flush() {
					return out
				}
				word = word[len(head):]
			}
			line, width = word, ansi.StringWidth(word)
		}
	}
	if width > 0 {
		out = append(out, line)
	}
	return out
}

// safe strips control characters from anything a sandbox said about itself.
//
// It is deliberately applied at both ends: internal/tui/source.go sanitises on
// the way in, and every cell of every pane sanitises again on the way out. The
// cost is a string copy of text that is about to be copied anyway; the failure
// it prevents is a sandbox repositioning the operator's cursor.
func safe(s string) string { return cli.SafeText(s) }

// paneError renders why a pane has nothing to show, in the vocabulary
// internal/client defines.
//
// Through the same mapping the fleet pane's DETAIL column uses, so one sandbox
// that is not answering reads the same way everywhere on the screen. Left raw,
// the panes reported the same failure as `client: sandbox unreachable:
// connection error: desc = "transport: Error while dialing: dial tcp
// 127.0.0.1:49001: connect: connection refused": rpc error: code = Unavailable
// …`, five wrapped lines of it, next to a fleet row that said "no answer within
// the timeout" about the identical event.
func paneError(err error) string {
	if err == nil {
		return ""
	}
	return probeDetail(err)
}

// oneLine makes an error safe and short enough for a pane.
func oneLine(msg string) string { return cli.Clip(cli.SafeText(msg), 200) }

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
