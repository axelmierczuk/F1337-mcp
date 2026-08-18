package fleetctl

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/axelmierczuk/fleet-mcp/internal/tui"
)

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

func newTUICommand(out io.Writer) *cobra.Command {
	var (
		control      controlFlags
		registryPath string
		refresh      time.Duration
	)
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
				return fmt.Errorf("%w: output is not a terminal. `fleetctl list --json` is the scriptable view of the same data", tui.ErrNotATerminal)
			}
			if err := tui.RequireTerminal(tty); err != nil {
				return err
			}

			fleet, err := openRegistry(registryPath)
			if err != nil {
				return err
			}
			// The pool's background health loop is the view's health
			// source and the only thing in this program that probes on a
			// schedule, so it gets the interval the operator chose rather
			// than the one a command that probes once and exits wants.
			pool, err := control.pool(healthIntervalFor(refresh))
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

			return tui.Run(ctx, tui.Options{
				Source:   tui.NewFleetSource(fleet, pool, control.probeTimeout()),
				Schedule: tui.DefaultSchedule,
				Out:      tty,
				TTY:      tty,
				// OpenShell is left nil until #43 lands. See the comment on
				// tui.Options.OpenShell: with it nil the key reports that
				// this build has no shell rather than doing nothing, and
				// wiring it is this one field — a closure that hands the
				// terminal to `fleetctl shell` through tea.Exec and reports
				// what it did with tui.Status.
			})
		},
	}
	control.register(cmd)
	cmd.Flags().StringVar(&registryPath, "registry", "", "path to the fleet registry (default: <config dir>/registry.yaml)")
	cmd.Flags().DurationVar(&refresh, "refresh", defaultHealthInterval,
		"how often each sandbox's health is re-probed in the background")
	return cmd
}
