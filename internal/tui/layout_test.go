package tui

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDegradationIsAStaircase pins which arrangement each size gets. Below the
// four-pane grid the answer is fewer panes with room to say something, not four
// panes each holding one useless line.
func TestDegradationIsAStaircase(t *testing.T) {
	t.Parallel()

	cases := []struct {
		w, h int
		want Mode
	}{
		{200, 60, ModeFull},
		{120, 40, ModeFull},
		{80, 24, ModeFull},
		{76, 18, ModeFull},
		{75, 24, ModeStacked},
		{80, 17, ModeStacked},
		{60, 14, ModeStacked},
		{40, 11, ModeStacked},
		{40, 10, ModeMinimal},
		{24, 6, ModeMinimal},
		{23, 24, ModeTooSmall},
		{80, 5, ModeTooSmall},
		{1, 1, ModeTooSmall},
		{0, 0, ModeTooSmall},
	}
	for _, tc := range cases {
		got := computeLayout(tc.w, tc.h, PaneFleet)
		require.Equalf(t, tc.want, got.Mode, "%dx%d", tc.w, tc.h)
	}
}

// TestEightyByTwentyFourShowsAllFourPanes is the size the issue names, so it is
// the size that is pinned rather than merely covered by the staircase above.
func TestEightyByTwentyFourShowsAllFourPanes(t *testing.T) {
	t.Parallel()

	l := computeLayout(80, 24, PaneFleet)
	require.Equal(t, ModeFull, l.Mode)
	for _, p := range panes {
		require.Truef(t, l.Visible(p), "%s is not drawn at 80x24", p.Title())
		b := l.Boxes[p]
		w, h := b.interior()
		require.GreaterOrEqualf(t, w, 20, "%s has no usable width at 80x24", p.Title())
		require.GreaterOrEqualf(t, h, 3, "%s has no usable height at 80x24", p.Title())
	}
}

// TestTheBodyIsTiledExactly sweeps every size the program will draw at and
// checks that the panes cover the body with no overlap, no gap, and nothing
// outside the frame.
//
// This is the structural half of "resizing reflows rather than corrupts". An
// overlap is two panes writing the same cell, and a box reaching past the frame
// is a line longer than the terminal, which scrolls the screen and smears every
// frame after it.
func TestTheBodyIsTiledExactly(t *testing.T) {
	t.Parallel()

	for w := 20; w <= 200; w++ {
		for h := 4; h <= 60; h++ {
			for _, focus := range panes {
				l := computeLayout(w, h, focus)
				if l.Mode == ModeTooSmall {
					require.Empty(t, l.Boxes)
					continue
				}
				for p, b := range l.Boxes {
					require.GreaterOrEqualf(t, b.x, 0, "%dx%d %s", w, h, p.Title())
					require.GreaterOrEqualf(t, b.y, 1, "%dx%d %s starts in the header", w, h, p.Title())
					require.LessOrEqualf(t, b.x+b.w, w, "%dx%d %s reaches past the right edge", w, h, p.Title())
					require.LessOrEqualf(t, b.y+b.h, h-1, "%dx%d %s reaches into the footer", w, h, p.Title())
					require.GreaterOrEqualf(t, b.h, paneMin, "%dx%d %s is too short to draw", w, h, p.Title())
				}
				// Row by row, the panes covering it must start at column zero,
				// abut exactly, and end at the right edge. Contiguity is the
				// same check as "no overlap and no gap", one dimension at a
				// time, and it is the same walk the compositor makes.
				for y := l.Body.y; y < l.Body.y+l.Body.h; y++ {
					x := 0
					for _, p := range panesAtRow(l, y) {
						b := l.Boxes[p]
						require.Equalf(t, x, b.x, "%dx%d row %d: %s does not abut what is left of it", w, h, y, p.Title())
						x = b.x + b.w
					}
					require.Equalf(t, w, x, "%dx%d row %d is not fully covered", w, h, y)
				}
			}
		}
	}
}

// TestTheFleetStaysVisibleWhenStacked. Which machine you are about to act on is
// the one fact a confirmation prompt cannot restore if you have lost track of
// it, so the fleet pane is not the one that goes first.
func TestTheFleetStaysVisibleWhenStacked(t *testing.T) {
	t.Parallel()

	for _, focus := range panes {
		l := computeLayout(70, 14, focus)
		require.Equal(t, ModeStacked, l.Mode)
		require.Truef(t, l.Visible(PaneFleet), "focus %s hid the fleet", focus.Title())
		if focus != PaneFleet {
			require.Truef(t, l.Visible(focus), "focus %s is not drawn", focus.Title())
		}
	}
}

// TestMinimalShowsTheFocusedPane, which is what makes tab still useful on a
// terminal too small for two panes rather than a key that moves an invisible
// cursor.
func TestMinimalShowsTheFocusedPane(t *testing.T) {
	t.Parallel()

	for _, focus := range panes {
		l := computeLayout(40, 9, focus)
		require.Equal(t, ModeMinimal, l.Mode)
		require.Len(t, l.Boxes, 1)
		require.True(t, l.Visible(focus))
	}
}

// TestInteriorIsNeverNegative. A box too small to have an interior reports a
// zero-sized one, because the alternative is strings.Repeat with a negative
// count, which panics inside a full-screen program.
func TestInteriorIsNeverNegative(t *testing.T) {
	t.Parallel()

	for _, b := range []box{{w: 0, h: 0}, {w: 1, h: 1}, {w: 2, h: 2}, {w: -5, h: -5}} {
		w, h := b.interior()
		require.GreaterOrEqual(t, w, 0, fmt.Sprint(b))
		require.GreaterOrEqual(t, h, 0, fmt.Sprint(b))
	}
}
