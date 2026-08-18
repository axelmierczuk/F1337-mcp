package tui

import (
	"context"
	"io"
	"reflect"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"
)

// The two things [Run] tells bubbletea that a running program will not tell
// anyone, and that a reader of this package cannot check by looking at a
// terminal.
//
// Both were asserted by nothing at all. Deleting either left every test in
// this repository green, including the end-to-end suite: the frame rate is
// invisible except as CPU time, and whether bubbletea installs its own signal
// handler decides a race that on this hardware fell the safe way six times out
// of six. A claim that cannot fail is not a guard, so these read the settings
// back off a program built from the same options Run uses.
//
// They reach into *tea.Program with reflection, which is the price of pinning
// a decision the library takes no arguments about and answers no questions
// about. If a bubbletea upgrade renames a field, this fails loudly and names
// what to look for — which is the right failure. Silently losing the pin is
// not.

func programField(t *testing.T, p *tea.Program, name string) reflect.Value {
	t.Helper()
	f := reflect.ValueOf(p).Elem().FieldByName(name)
	require.Truef(t, f.IsValid(),
		"*tea.Program has no field %q any more; a bubbletea upgrade has moved it, and this test is what pins %q to the value Run asks for",
		name, name)
	return f
}

func builtProgram(t *testing.T, opts ...tea.ProgramOption) *tea.Program {
	t.Helper()
	return tea.NewProgram(&program{model: demoModel(80, 24)}, opts...)
}

// TestTheRendererRunsSlowerThanTheDefault.
//
// bubbletea's default is 60, which is a frame rate for animation. This
// program's fastest legitimate change is a keystroke. Measured on a pty over a
// two-minute idle window, the difference is 0.50% of one core against 0.15%,
// and "no busy-wait: idle CPU is ~0 when nothing is changing" is an acceptance
// criterion, so the constant is not decoration.
func TestTheRendererRunsSlowerThanTheDefault(t *testing.T) {
	t.Parallel()

	got := builtProgram(t, programOptions(context.Background(), io.Discard, nil)...)
	require.Equal(t, int64(renderFPS), programField(t, got, "fps").Int(),
		"the renderer is not running at renderFPS")

	// Left alone, the field stays zero and the renderer falls back to
	// bubbletea's own default — which is what asking for nothing looks like,
	// and what deleting the option would restore.
	require.Zero(t, programField(t, builtProgram(t), "fps").Int(),
		"bubbletea now carries its default in this field, so a zero here no longer means the option was skipped")
	require.Less(t, renderFPS, 60, "renderFPS is not slower than the default it exists to undercut")
}

// TestBubbleteaIsNotAskedToHandleSignals.
//
// Its handler goroutine does a blocking send of QuitMsg onto an unbuffered
// channel with no ctx.Done() case to escape through, while the same signal has
// already cancelled the program's context and given the event loop a second
// reason to return. Whichever the event loop's select happens to pick decides
// whether shutdown completes or waits on that goroutine forever with the
// terminal in raw mode. The signal handling is the caller's, through ctx.
//
// The bit is found by difference rather than named, because the constant that
// names it is unexported: a program built with the option and one built
// without it differ in exactly this bit, and Run's options must have it set.
func TestBubbleteaIsNotAskedToHandleSignals(t *testing.T) {
	t.Parallel()

	base := programField(t, builtProgram(t), "startupOptions").Int()
	withOpt := programField(t, builtProgram(t, tea.WithoutSignalHandler()), "startupOptions").Int()
	bit := base ^ withOpt
	require.NotZero(t, bit, "tea.WithoutSignalHandler sets no startup option; this test can no longer see it")

	got := programField(t, builtProgram(t, programOptions(context.Background(), io.Discard, nil)...), "startupOptions").Int()
	require.NotZerof(t, got&bit,
		"Run lets bubbletea install its own signal handler, which deadlocks against the cancelled context that arrives with the same signal")
}

// TestTheAlternateScreenIsAsked. A full-screen view that drew over the
// operator's scrollback and left it there would be the other half of "gives
// the terminal back".
func TestTheAlternateScreenIsAsked(t *testing.T) {
	t.Parallel()

	base := programField(t, builtProgram(t), "startupOptions").Int()
	bit := base ^ programField(t, builtProgram(t, tea.WithAltScreen()), "startupOptions").Int()
	require.NotZero(t, bit)

	got := programField(t, builtProgram(t, programOptions(context.Background(), io.Discard, nil)...), "startupOptions").Int()
	require.NotZero(t, got&bit, "the view does not run on the alternate screen")
}

// TestAnInputIsOnlyOverriddenWhenThereIsOne, so the ordinary case still gets
// bubbletea's own handling of a stdin that is not a terminal.
func TestAnInputIsOnlyOverriddenWhenThereIsOne(t *testing.T) {
	t.Parallel()

	require.Len(t, programOptions(context.Background(), io.Discard, nil), 5)
	require.Len(t, programOptions(context.Background(), io.Discard, io.LimitReader(nil, 0)), 6)
}
