package fleetctl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/axelmierczuk/fleet-mcp/internal/client"
	"github.com/axelmierczuk/fleet-mcp/internal/platform"
	"github.com/axelmierczuk/fleet-mcp/internal/registry"
)

// This file is `fleetctl tui` — the command, its flags, and everything it does
// before there is anything to draw. What it does not do is import the thing
// that draws, and that omission is the point of the file.
//
// bubbletea's package init calls lipgloss.HasDarkBackground(), which writes an
// OSC 11 background-colour query and a cursor-position request to the terminal,
// puts it into no-echo non-canonical mode, and reads for up to five seconds
// waiting for the answers. Package inits run in every process that links the
// package, whatever subcommand was typed — so linking the view here made
// `fleetctl version` on a terminal that does not answer cost five seconds and
// eat whatever was typed meanwhile. There is no way to opt out from inside the
// process: every escape hatch termenv has (TERM, COLORFGBG, an explicit
// lipgloss background) is read *during* that init, and Go initialises an
// imported package before any code that imports it can run.
//
// So the base binary does not link it. [View] is the seam: nil here, non-nil in
// the one binary built to draw. See [handOff] for what nil means in practice
// and cmd/fleet-tui for the other side.

// View draws the fleet until the operator quits or ctx is cancelled.
//
// Its signature deliberately names nothing from internal/tui. A seam whose
// types come from the package it exists to keep out is not a seam.
type View func(ctx context.Context, in ViewInput) error

// ViewInput is everything the view needs that this command resolved: the
// operator's fleet, their credentials, and their terminal.
type ViewInput struct {
	// Fleet is the registry the panes read.
	Fleet *registry.Registry
	// Pool holds the operator's credentials and the background health loop
	// the view's refresh is built on. The caller closes it.
	Pool *client.Pool
	// ProbeTimeout is the per-sandbox deadline a health probe runs under, so
	// one machine that has gone away never holds up the view.
	ProbeTimeout time.Duration
	// TTY is the operator's terminal: what the view draws on, and what it
	// reads its keys from.
	TTY *os.File
}

// ErrNotATerminal is what a run without a terminal fails with.
//
// It lives here rather than in internal/tui because the refusal is this
// command's contract — it names `fleetctl list --json` — and because the base
// binary has to be able to make it without linking the view. Two sentinels for
// one condition would be worse than either: `errors.Is` would answer differently
// depending on which binary produced the error.
var ErrNotATerminal = errors.New("fleetctl tui needs a terminal")

// requireTerminal refuses a run that has no terminal to draw on.
//
// A full-screen program whose output is a pipe produces escape sequences and no
// frames, which reads as a hang. Saying so, and naming the command that does
// have machine-readable output, is the difference between a bug report and a
// second try.
func requireTerminal(f *os.File) error {
	if f == nil || !platform.IsTerminal(f.Fd()) {
		return fmt.Errorf("%w: stdout is not one. `fleetctl list --json` is the scriptable view of the same data", ErrNotATerminal)
	}
	return nil
}

// defaultHealthInterval is how often the pool re-probes each sandbox while the
// TUI is open.
//
// It is the only schedule in this program that scales with the size of the
// fleet, so it is the one that decides whether a large fleet is watchable. The
// pool probes every sandbox in parallel under its own per-sandbox deadline, so
// the cost of an interval is one round trip per machine, not one after another;
// ten seconds is frequent enough that a machine going away is noticed while the
// operator is still looking at the screen, and slow enough that a hundred
// machines is a hundred requests every ten seconds rather than a flood.
const defaultHealthInterval = 10 * time.Second

// healthIntervalFor is what --refresh means, including what it means when it
// is not a positive duration.
//
// Nought or less is the flag's default rather than "never". A pool asked for
// no interval gives the answer a one-shot command wants — a background loop
// that never fires again — and here that is a view whose health stopped after
// the first probe and does not say so.
func healthIntervalFor(refresh time.Duration) time.Duration {
	if refresh <= 0 {
		return defaultHealthInterval
	}
	return refresh
}

// tuiFlags is everything `fleetctl tui` reads off its command line.
//
// A struct rather than three locals so a test can hold the same values the
// command parsed into and then build the pool the one way the command builds
// it. See [tuiFlags.pool].
type tuiFlags struct {
	control      controlFlags
	registryPath string
	refresh      time.Duration
}

// pool builds the pool the view runs on: the operator's credentials, and the
// background health loop at the interval --refresh chose.
//
// A method rather than a line inside RunE because RunE refuses before it gets
// this far whenever the output is not a terminal, which is every test in this
// package — so the flag's journey to the pool was asserted by nothing.
// Replacing healthIntervalFor(f.refresh) with the default left this repository
// green, end-to-end suite included: the scenario that kills an agent waits a
// minute for the re-probe, and the ten-second default delivers one well inside
// that. What the scenario covers is that the view gets a probing pool at all,
// which is the other half.
func (f *tuiFlags) pool() (*client.Pool, error) {
	return f.control.pool(healthIntervalFor(f.refresh))
}

func newTUICommand(out io.Writer, view View) *cobra.Command {
	return newTUICommandWith(out, view, &tuiFlags{})
}

func newTUICommandWith(out io.Writer, view View, f *tuiFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Watch the fleet in a full-screen terminal view",
		Long: "tui opens a full-screen view of the fleet: every enrolled sandbox and its\n" +
			"health, the supervised processes on the focused sandbox, that process's\n" +
			"output, and the focused host's resources and allowed roots.\n\n" +
			"It is a view of exactly what the rest of the product reports — the same\n" +
			"client, the same health words, the same numbers as `fleetctl list` and\n" +
			"`fleetctl info` — and it is the same fleet the MCP server sees.\n\n" +
			"Health is refreshed in the background for every sandbox, in parallel and\n" +
			"under a per-sandbox deadline, so one machine that has gone away is drawn as\n" +
			"unreachable rather than holding up the view. Everything else is fetched only\n" +
			"for the sandbox you are looking at.\n\n" +
			"Every action that changes a sandbox asks first, naming the sandbox and the\n" +
			"process. Press ? for the keys.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// The view is drawn on the writer the command tree was built with,
			// and only if that is a terminal. Checking the writer rather than
			// os.Stdout is what stops a `fleetctl` embedded in something else
			// — a test, a harness — from painting a full screen over a pipe it
			// was told to write to.
			tty, ok := out.(*os.File)
			if !ok {
				return fmt.Errorf("%w: output is not a terminal. `fleetctl list --json` is the scriptable view of the same data", ErrNotATerminal)
			}
			if err := requireTerminal(tty); err != nil {
				return err
			}

			// Read here and cleared here, whichever branch runs below: it
			// describes exactly one exec, and the binary that draws goes on to
			// start other things that are the far side of nothing. Set, it
			// means this process is already the far side of a hand-off — and a
			// fleetctl on the far side of a hand-off is a fleet-tui that is
			// really fleetctl, so handing over again is the loop. See
			// [handOffMarker].
			handedOverTo := takeHandOffMarker()

			// Before the registry is opened and before a single agent is
			// dialled: this binary does not draw, so everything below would be
			// work done twice. See [handOff] — on Unix it does not return.
			//
			// os.Args rather than what cobra parsed, because the whole point is
			// that the command line is not rebuilt; see [handOff]. That is
			// exact for the two mains that reach here, which both pass
			// os.Args[1:], and unreachable for a caller that passes something
			// else, since every one of those writes to a buffer and is refused
			// above.
			if view == nil {
				err := handOff(handedOverTo, os.Args[1:])
				// Windows has no exec, so there the helper is a child and its
				// status is this command's. Silenced for the reason
				// `fleetctl shell` silences a remote shell's: the status is
				// the result, and cobra printing an error about it would be
				// noise over a screen the operator has already seen. Set here
				// rather than on the command, so a helper that could not be
				// found still prints why.
				var status *exitStatus
				if errors.As(err, &status) {
					cmd.SilenceErrors = true
				}
				return err
			}

			fleet, err := openRegistry(f.registryPath)
			if err != nil {
				return err
			}
			// The pool's background health loop is the view's health
			// source and the only thing in this program that probes on a
			// schedule, so it gets the interval the operator chose rather
			// than the one a command that probes once and exits wants.
			pool, err := f.pool()
			if err != nil {
				return err
			}
			defer func() { _ = pool.Close() }()

			// SIGTERM and SIGINT cancel the context, bubbletea shuts the
			// program down, and the terminal is restored on the way out. This
			// is the same pairing `fleetctl serve` uses; the difference is that
			// here the thing that must happen before the process exits is
			// putting the operator's terminal back.
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			return view(ctx, ViewInput{
				Fleet:        fleet,
				Pool:         pool,
				ProbeTimeout: f.control.probeTimeout(),
				TTY:          tty,
			})
		},
	}
	f.control.register(cmd)
	cmd.Flags().StringVar(&f.registryPath, "registry", "", "path to the fleet registry (default: <config dir>/registry.yaml)")
	cmd.Flags().DurationVar(&f.refresh, "refresh", defaultHealthInterval,
		"how often each sandbox's health is re-probed in the background")
	return cmd
}
