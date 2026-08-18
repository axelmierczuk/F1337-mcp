package tui

// Geometry, and what to do when there is not enough of it.
//
// "Degrades sensibly below 80x24 rather than corrupting" is two separate
// promises, and only one of them is about taste. Corruption is prevented
// structurally: every frame is exactly Height lines, every line is fitted to
// Width, and no pane is ever given a negative or zero interior to draw into —
// which is where an off-by-one turns into a border drawn past the right edge
// and a scrolled, smeared screen. Sense is the mode below: rather than shrink
// four panes until each holds one useless line, drop to fewer panes and give
// the ones that remain enough room to say something.

// Minimums. Below the first, a pane cannot hold a border, a title and a row;
// below the second, the four-pane grid cannot.
const (
	// minWidth and minHeight are the smallest terminal this program will draw
	// anything but an apology in.
	minWidth  = 24
	minHeight = 6

	// fullWidth and fullHeight are where the four-pane grid starts fitting.
	// 80x24 is the target and must be comfortably inside it, not exactly on
	// the boundary, or a terminal one column narrower falls off a cliff.
	fullWidth  = 76
	fullHeight = 18

	// stackedHeight is the smallest terminal that can show the fleet and one
	// other pane at once.
	stackedHeight = 11

	// detailMin and detailMax bound the detail column beside the processes
	// table. Narrower and its labels do not fit; wider and the processes table
	// starts losing columns on an 80-column terminal, which is the size this
	// is tuned for.
	detailMin = 24
	detailMax = 34

	// paneMin is the smallest a pane can be and still hold a border, a header
	// row and one row of content.
	paneMin = 4
)

// Mode is which arrangement of panes fits.
type Mode int

const (
	// ModeTooSmall cannot usefully show anything. One centred sentence.
	ModeTooSmall Mode = iota
	// ModeMinimal shows the focused pane and nothing else.
	ModeMinimal
	// ModeStacked shows the fleet above the focused pane, single column.
	ModeStacked
	// ModeFull shows all four panes: fleet and detail down the left, processes
	// and logs down the right.
	ModeFull
)

// String names a mode, for the status line and for test failures.
func (m Mode) String() string {
	switch m {
	case ModeFull:
		return "full"
	case ModeStacked:
		return "stacked"
	case ModeMinimal:
		return "minimal"
	default:
		return "too-small"
	}
}

// box is one pane's outer rectangle, in cells, top-left origin.
type box struct {
	x, y, w, h int
}

// interior is the area inside the border. It is never negative: a box too
// small to have an interior reports a zero-sized one, and every writer checks.
func (b box) interior() (w, h int) {
	w, h = b.w-2, b.h-2
	if w < 0 {
		w = 0
	}
	if h < 0 {
		h = 0
	}
	return w, h
}

// Layout is where every pane goes in a frame of a given size.
//
// Panes not present in Boxes are not drawn. That is the whole of the
// degradation policy: the renderer draws what the layout gives it and never
// decides for itself that something will not fit.
type Layout struct {
	Width, Height int
	Mode          Mode
	// Boxes holds a rectangle per visible pane.
	Boxes map[Pane]box
	// Body is the area between the header and the footer.
	Body box
}

// Visible reports whether a pane is drawn in this layout.
func (l Layout) Visible(p Pane) bool {
	_, ok := l.Boxes[p]
	return ok
}

// computeLayout decides the arrangement for a terminal of this size, with this
// pane focused.
//
// focus matters below ModeFull because the reduced modes show the focused pane:
// that is what makes tab still useful on a small terminal instead of a key that
// moves an invisible cursor.
func computeLayout(width, height int, focus Pane) Layout {
	l := Layout{Width: width, Height: height, Boxes: map[Pane]box{}}

	if width < minWidth || height < minHeight {
		l.Mode = ModeTooSmall
		return l
	}

	// One header line and one footer line, always. The footer carries the
	// confirmation prompt, and a layout that could drop it could put a
	// destructive action behind a prompt nobody sees.
	body := box{x: 0, y: 1, w: width, h: height - 2}
	l.Body = body

	switch {
	case width >= fullWidth && height >= fullHeight:
		l.Mode = ModeFull
		// The fleet gets the full width rather than a sidebar. It is the one
		// pane that is a table of the whole fleet — name, platform, agent,
		// health, last seen — and squeezed into a third of an 80-column
		// terminal it can show two of those five. Full width, it shows all of
		// them at 80 and the rest of the layout still fits.
		fleetH := atLeast(body.h*2/5, paneMin)
		logsH := atLeast(body.h*3/10, paneMin)
		midH := body.h - fleetH - logsH
		// The middle row is what gives when the body is short, so it is
		// checked last and takes back from the other two if it has to.
		if midH < paneMin {
			short := paneMin - midH
			take := min(short, fleetH-paneMin)
			fleetH, midH = fleetH-take, midH+take
			take = min(paneMin-midH, logsH-paneMin)
			logsH, midH = logsH-take, midH+take
		}
		detailW := clamp(width/3, detailMin, detailMax)
		procW := width - detailW

		l.Boxes[PaneFleet] = box{x: 0, y: body.y, w: width, h: fleetH}
		l.Boxes[PaneProcesses] = box{x: 0, y: body.y + fleetH, w: procW, h: midH}
		l.Boxes[PaneDetail] = box{x: procW, y: body.y + fleetH, w: detailW, h: midH}
		l.Boxes[PaneLogs] = box{x: 0, y: body.y + fleetH + midH, w: width, h: logsH}

	case height >= stackedHeight:
		l.Mode = ModeStacked
		// The fleet stays visible in this mode even when it is not focused:
		// which machine you are about to act on is the one fact a confirmation
		// prompt cannot restore if you have lost track of it.
		fleetH := body.h / 2
		if fleetH > 8 {
			fleetH = 8
		}
		other := focus
		if other == PaneFleet {
			other = PaneProcesses
		}
		l.Boxes[PaneFleet] = box{x: 0, y: body.y, w: width, h: fleetH}
		l.Boxes[other] = box{x: 0, y: body.y + fleetH, w: width, h: body.h - fleetH}

	default:
		l.Mode = ModeMinimal
		l.Boxes[focus] = box{x: 0, y: body.y, w: width, h: body.h}
	}
	return l
}

func clamp(v, lo, hi int) int {
	if hi < lo {
		return lo
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func atLeast(v, lo int) int {
	if v < lo {
		return lo
	}
	return v
}
