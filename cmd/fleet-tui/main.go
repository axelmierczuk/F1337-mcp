// Command fleet-tui draws `fleetctl tui`.
//
// It is not a second CLI. It is fleetctl's own command tree — same flags, same
// defaults, same config directory, same credentials — with one thing added: the
// full-screen view is linked in. `fleetctl tui` finds this binary next to
// itself and hands its command line over unchanged, so an operator never types
// this name and there is nothing here to configure separately.
//
// It exists because of how the view is built. bubbletea's package init queries
// the terminal for its background colour and reads for up to five seconds
// waiting for an answer, and a package init runs in every process that links
// the package, whatever subcommand was typed. Linking the view into `fleetctl`
// therefore made `fleetctl version` on a terminal that does not answer — a bare
// pty, a CI log, a serial console — cost five seconds and swallow whatever was
// typed meanwhile. Nothing inside the process can opt out: every escape hatch
// the library has is read during that init, before any code of ours runs. So
// the cost is moved to the one command that was going to take over the terminal
// anyway. See internal/cli/fleetctl/tui.go.
package main

import (
	"context"
	"os"

	"github.com/axelmierczuk/fleet-mcp/internal/cli/fleetctl"
	"github.com/axelmierczuk/fleet-mcp/internal/tui"
	"github.com/axelmierczuk/fleet-mcp/internal/version"
)

func main() {
	// Before the command tree is built, for the reason cmd/fleetctl gives: the
	// root's --version and the `version` subcommand both read these.
	version.FromBuildInfo()

	os.Exit(fleetctl.MainWithView(context.Background(), os.Args[1:], os.Stdout, view))
}

// view is the seam internal/cli/fleetctl leaves for whoever links the view, and
// this function is the whole of what that binary adds.
func view(ctx context.Context, in fleetctl.ViewInput) error {
	return tui.Run(ctx, tui.Options{
		Source:   tui.NewFleetSource(in.Fleet, in.Pool, in.ProbeTimeout),
		Schedule: tui.DefaultSchedule,
		Out:      in.TTY,
		TTY:      in.TTY,
		// OpenShell is left nil until #43 lands. See the comment on
		// tui.Options.OpenShell: with it nil the key reports that this build
		// has no shell rather than doing nothing, and wiring it is this one
		// field — a closure that hands the terminal to `fleetctl shell` through
		// tea.Exec and reports what it did with tui.Status.
	})
}
