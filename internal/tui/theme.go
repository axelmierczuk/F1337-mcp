package tui

import (
	"strings"

	"github.com/axelmierczuk/fleet-mcp/internal/client"
)

// Colour, decided once, from the environment.
//
// This view is run over SSH, inside tmux, on a serial console and in a CI log,
// and TERM is the only thing that distinguishes them. Rather than ask a library
// at each call site, the whole decision is one function of the environment and
// one small enum, so "what does NO_COLOR do" and "what does TERM=dumb do" are
// questions with unit tests rather than opinions.
//
// The rule that keeps a frame from corrupting: a style may only wrap text that
// has already been fitted to its column. Every sequence below is an SGR
// (select-graphic-rendition) sequence, which occupies no cells, so styling
// never changes a string's display width. Nothing here moves the cursor.

// Profile is how much colour the terminal can be relied on for.
type Profile int

const (
	// ProfileNone renders no escape sequences at all. NO_COLOR, TERM=dumb, a
	// pipe, a golden file.
	ProfileNone Profile = iota
	// ProfileBasic is the sixteen ANSI colours, which every terminal that
	// claims a TERM at all has had since the 1980s.
	ProfileBasic
	// ProfileANSI256 is the 256-colour cube.
	ProfileANSI256
)

// DetectProfile decides how much colour to use from the environment.
//
// NO_COLOR wins over everything, per no-color.org: it is set by people who mean
// it, and a program that downgrades it to a hint is a program they stop using.
// Otherwise TERM decides, because it is the one variable that survives ssh and
// tmux, and the fallback is the basic sixteen rather than nothing: a terminal
// that named itself is a terminal that can bold and colour text, and the
// failure mode of guessing 256 colours wrong is illegible text.
//
// A truecolour COLORTERM buys this program nothing — nothing here needs a
// colour outside the 256-colour cube — so it is treated as ANSI256 rather than
// as a fourth case that renders differently and has to be verified separately.
func DetectProfile(env func(string) string) Profile {
	if strings.TrimSpace(env("NO_COLOR")) != "" {
		return ProfileNone
	}
	term := strings.ToLower(strings.TrimSpace(env("TERM")))
	switch {
	case term == "", term == "dumb":
		return ProfileNone
	case strings.Contains(term, "256color"), strings.Contains(term, "truecolor"), strings.Contains(term, "direct"):
		return ProfileANSI256
	case strings.EqualFold(strings.TrimSpace(env("COLORTERM")), "truecolor"),
		strings.EqualFold(strings.TrimSpace(env("COLORTERM")), "24bit"):
		return ProfileANSI256
	default:
		return ProfileBasic
	}
}

// style is a set of SGR parameters. The zero value renders nothing.
type style struct {
	// params are the SGR parameters, already joined, e.g. "1;31".
	params string
}

// Theme is the palette a frame is drawn with. Every field is a style, and a
// theme with ProfileNone has every style empty, which is what makes the golden
// files plain text.
type Theme struct {
	Profile Profile

	Chrome   style // pane borders and titles
	Focused  style // the border of the focused pane
	Header   style // column headers
	Selected style // the selected row
	Dim      style // secondary text
	Warn     style // something the operator should look at
	Bad      style // something that is wrong
	Good     style // something that is fine
	Alarm    style // the confirmation prompt
}

// NewTheme builds the palette for a profile.
func NewTheme(p Profile) Theme {
	t := Theme{Profile: p}
	switch p {
	case ProfileNone:
		return t
	case ProfileBasic:
		t.Chrome = style{"34"}    // blue
		t.Focused = style{"1;36"} // bright cyan
		t.Header = style{"1"}     // bold
		t.Selected = style{"7"}   // reverse video, which needs no colour at all
		t.Dim = style{"2"}
		t.Warn = style{"33"} // yellow
		t.Bad = style{"31"}  // red
		t.Good = style{"32"} // green
		t.Alarm = style{"1;33"}
	case ProfileANSI256:
		t.Chrome = style{"38;5;60"}
		t.Focused = style{"1;38;5;81"}
		t.Header = style{"1;38;5;252"}
		t.Selected = style{"7"}
		t.Dim = style{"38;5;244"}
		t.Warn = style{"38;5;179"}
		t.Bad = style{"38;5;167"}
		t.Good = style{"38;5;108"}
		t.Alarm = style{"1;38;5;179"}
	}
	return t
}

// apply wraps s in the style, or returns it untouched when the style is empty.
//
// The reset is the full "\x1b[0m" rather than a targeted one. A targeted reset
// has to know which attributes were set, and getting that wrong leaves a
// terminal bolded for the rest of the frame — the exact class of corruption
// this file exists to avoid.
func (s style) apply(text string) string {
	if s.params == "" || text == "" {
		return text
	}
	return "\x1b[" + s.params + "m" + text + "\x1b[0m"
}

// healthStyle picks the style for one of the health words in internal/client.
//
// It switches on the shared constants rather than on a local list, so a health
// state added there renders in the default style rather than silently matching
// the wrong colour.
func (t Theme) healthStyle(health string) style {
	switch health {
	case client.HealthServing:
		return t.Good
	case client.HealthDegraded, client.HealthDraining:
		return t.Warn
	case client.HealthUnreachable:
		return t.Bad
	default:
		return t.Dim
	}
}

// processStyle picks the style for one of the process state words in
// internal/client.
func (t Theme) processStyle(state string) style {
	switch state {
	case client.ProcessReady, client.ProcessRunning:
		return t.Good
	case client.ProcessStarting, client.ProcessRestarting:
		return t.Warn
	case client.ProcessCrashed, client.ProcessOrphaned:
		return t.Bad
	default:
		return t.Dim
	}
}
