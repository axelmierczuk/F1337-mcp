package fleetctl

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A sandbox is a machine running someone else's code, and everything it says
// about itself lands in an operator's terminal. A health message carrying a
// terminal escape would rewrite the listing it appears in — a lie about the
// fleet, printed by the tool the operator uses to check on the fleet.
func TestSafeText_StripsWhatAnAgentCouldUseToRewriteTheDisplay(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		// The escape byte goes and its parameters stay, as literal text. That
		// is the defused form: "[2K" printed is nothing, "[2K" acted on is a
		// cleared line.
		"escape sequence": {"\x1b[2Kall good", "[2Kall good"},
		// A carriage return would overwrite what came before it, so it becomes
		// a separator rather than vanishing — both halves stay visible.
		"carriage return": {"degraded\rserving", "degraded serving"},
		"newline":         {"line one\nline two", "line one line two"},
		"tabs":            {"a\t\tb", "a b"},
		// Escaped rather than written literally: a bidi override in a source
		// file does to the reviewer exactly what this test says it must not do
		// to the operator.
		"bidi override": {"disk \u202efull", "disk full"},
		"leading space": {"  padded  ", "padded"},
		"plain":         {"disk 91% full", "disk 91% full"},
	} {
		t.Run(name, func(t *testing.T) {
			out := safeText(tc.in)
			assert.Equal(t, tc.want, out)
			for _, r := range out {
				assert.False(t, unicode.IsControl(r), "a control character survived: %q", r)
			}
		})
	}
}

// One machine answering a probe with a stack trace must not turn a
// twenty-machine listing into a wall of text.
func TestOneLine_BoundsACellAndKeepsItValidUTF8(t *testing.T) {
	long := strings.Repeat("é", maxDetail)
	out := oneLine(long)

	assert.Less(t, len(out), len(long))
	assert.True(t, strings.HasSuffix(out, "…"))
	require.True(t, utf8.ValidString(out), "truncation split a rune, which would corrupt the JSON document")
}

func TestOneLine_LeavesAShortMessageAlone(t *testing.T) {
	assert.Equal(t, "disk 91% full", oneLine("disk 91% full"))
}
