package tui

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestColourIsDecidedFromTheEnvironment.
//
// This is the whole of "NO_COLOR and a non-truecolour TERM both render
// legibly": the decision is one function of the environment, so it is a table
// rather than something to be checked by looking at a terminal that happens to
// be to hand.
func TestColourIsDecidedFromTheEnvironment(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		env  map[string]string
		want Profile
	}{
		// NO_COLOR wins over everything, per no-color.org. A program that
		// downgrades it to a hint is a program the people who set it stop using.
		{"NO_COLOR beats a capable terminal", map[string]string{"NO_COLOR": "1", "TERM": "xterm-256color", "COLORTERM": "truecolor"}, ProfileNone},
		{"NO_COLOR beats COLORTERM alone", map[string]string{"NO_COLOR": "yes", "COLORTERM": "truecolor"}, ProfileNone},
		{"an empty NO_COLOR is not set", map[string]string{"NO_COLOR": "", "TERM": "xterm"}, ProfileBasic},
		{"whitespace is not set either", map[string]string{"NO_COLOR": "  ", "TERM": "xterm"}, ProfileBasic},

		{"no TERM at all", map[string]string{}, ProfileNone},
		{"TERM=dumb", map[string]string{"TERM": "dumb"}, ProfileNone},

		// A terminal that named itself can bold and colour text; the failure
		// mode of guessing 256 wrong is illegible text, so the fallback is the
		// sixteen every terminal has had since the 1980s.
		{"TERM=xterm", map[string]string{"TERM": "xterm"}, ProfileBasic},
		{"TERM=vt100", map[string]string{"TERM": "vt100"}, ProfileBasic},
		{"TERM=linux", map[string]string{"TERM": "linux"}, ProfileBasic},
		{"TERM=screen, as tmux sets", map[string]string{"TERM": "screen"}, ProfileBasic},

		{"TERM=xterm-256color", map[string]string{"TERM": "xterm-256color"}, ProfileANSI256},
		{"TERM=screen-256color, as tmux sets", map[string]string{"TERM": "screen-256color"}, ProfileANSI256},
		{"TERM=tmux-256color", map[string]string{"TERM": "tmux-256color"}, ProfileANSI256},
		{"TERM=xterm-direct", map[string]string{"TERM": "xterm-direct"}, ProfileANSI256},

		// Truecolour buys this program nothing — nothing here needs a colour
		// outside the cube — so it is not a fourth case that renders
		// differently and would have to be verified separately.
		{"COLORTERM=truecolor on a plain xterm", map[string]string{"TERM": "xterm", "COLORTERM": "truecolor"}, ProfileANSI256},
		{"COLORTERM=24bit", map[string]string{"TERM": "xterm", "COLORTERM": "24bit"}, ProfileANSI256},
		{"COLORTERM cannot rescue TERM=dumb", map[string]string{"TERM": "dumb", "COLORTERM": "truecolor"}, ProfileNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, DetectProfile(envOf(tc.env)))
		})
	}
}

// TestAProfileWithNoColourHasNoStyles, which is what makes the golden frames
// plain text and NO_COLOR mean what it says.
func TestAProfileWithNoColourHasNoStyles(t *testing.T) {
	t.Parallel()

	none := NewTheme(ProfileNone)
	for _, s := range []style{none.Chrome, none.Focused, none.Header, none.Selected, none.Dim, none.Warn, none.Bad, none.Good, none.Alarm} {
		require.Equal(t, "text", s.apply("text"))
	}
	for _, p := range []Profile{ProfileBasic, ProfileANSI256} {
		th := NewTheme(p)
		require.NotEqual(t, "text", th.Bad.apply("text"))
		// Reverse video for the selection, which needs no colour support at
		// all — the one piece of state an operator cannot afford to lose track
		// of before a confirmation.
		require.Equal(t, "\x1b[7mtext\x1b[0m", th.Selected.apply("text"))
	}
}

// TestGlyphsAreDecidedFromTheLocale. The locale variables are the only portable
// statement a terminal makes about its encoding, and ssh forwards them.
func TestGlyphsAreDecidedFromTheLocale(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		env  map[string]string
		want Glyphs
	}{
		{"nothing set", map[string]string{}, asciiGlyphs},
		{"LANG=C", map[string]string{"LANG": "C"}, asciiGlyphs},
		{"LANG=POSIX", map[string]string{"LANG": "POSIX"}, asciiGlyphs},
		{"LANG with UTF-8", map[string]string{"LANG": "en_US.UTF-8"}, unicodeGlyphs},
		{"LANG with utf8", map[string]string{"LANG": "en_GB.utf8"}, unicodeGlyphs},
		{"LC_ALL wins over LANG", map[string]string{"LC_ALL": "C", "LANG": "en_US.UTF-8"}, asciiGlyphs},
		{"LC_CTYPE wins over LANG", map[string]string{"LC_CTYPE": "en_US.UTF-8", "LANG": "C"}, unicodeGlyphs},
		{"an empty LC_ALL falls through", map[string]string{"LC_ALL": "", "LANG": "en_US.UTF-8"}, unicodeGlyphs},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, DetectGlyphs(envOf(tc.env)))
		})
	}
}

// TestHealthAndProcessStylesFollowTheSharedWords. A state added to
// internal/client renders in the default style rather than silently matching
// the wrong colour, because these switch on the constants rather than a copy.
func TestHealthAndProcessStylesFollowTheSharedWords(t *testing.T) {
	t.Parallel()

	th := NewTheme(ProfileANSI256)
	require.Equal(t, th.Good, th.healthStyle("serving"))
	require.Equal(t, th.Bad, th.healthStyle("unreachable"))
	require.Equal(t, th.Warn, th.healthStyle("degraded"))
	require.Equal(t, th.Dim, th.healthStyle("unknown"))
	require.Equal(t, th.Dim, th.healthStyle("a state this build has never heard of"))

	require.Equal(t, th.Good, th.processStyle("running"))
	require.Equal(t, th.Bad, th.processStyle("crashed"))
	require.Equal(t, th.Warn, th.processStyle("starting"))
	require.Equal(t, th.Dim, th.processStyle("exited"))
}
