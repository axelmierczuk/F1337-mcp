// Package fleetctl implements the operator CLI for the fleet control
// plane: certificate authority management, enrollment token minting, the
// enrollment listener, and the operator's view of the fleet.
//
// All of it lives here rather than behind an MCP tool because every command in
// this package either holds or hands out a credential, and nothing a model can
// reach should be able to mint one.
//
// # Adding a command
//
// Write a newXCommand(out io.Writer) *cobra.Command constructor in its own
// file and add it to the list in [NewRootCommandWithView]. That list is the
// whole registration surface; there is no plugin table and no init() magic.
//
// There is one seam, and it is not a plugin table: `tui` takes a [View],
// because the package that draws it queries the terminal from an init and so
// must not be linked into `fleetctl` at all. See tui.go and handoff.go.
//
// Two conventions keep the commands consistent, and both are one line each:
//
//   - A command with a result embeds [outputFlags], calls register on it, and
//     renders through [output.Emit]. That is what --json is; no command parses
//     the flag itself.
//   - A command that needs the CA loads it with [loadCA], and one that needs to
//     reach agents builds its pool with [dialFleet]. Both turn a missing
//     credential into the command that creates it, rather than a path and an
//     errno.
package fleetctl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/axelmierczuk/fleet-mcp/internal/registry"
	"github.com/axelmierczuk/fleet-mcp/internal/security/ca"
	"github.com/axelmierczuk/fleet-mcp/internal/version"
)

// Main runs fleetctl and returns the process exit code.
func Main(args []string, out io.Writer) int {
	return MainContext(context.Background(), args, out)
}

// MainContext is Main with a cancellable context.
//
// serve is long-running, and cancelling the context is how a caller that is not
// a signal — a test, or an embedding process such as the interactive shell —
// stops it. The listener derives its own signal handling from this context, so
// the two paths converge rather than competing. fleet-agent's CLI has the same
// pair for the same reason.
func MainContext(ctx context.Context, args []string, out io.Writer) int {
	return MainWithView(ctx, args, out, nil)
}

// MainWithView is MainContext for a binary that links the full-screen view.
//
// Only cmd/fleet-tui calls it with a non-nil view. See the head of tui.go: the
// view's dependency queries the terminal from a package init, so `fleetctl`
// itself must not link it, and `fleetctl tui` hands over to the binary that
// does. Both binaries run this same command tree, which is what makes the
// hand-off invisible — there is one implementation of every flag, every default
// and every credential path, not two.
func MainWithView(ctx context.Context, args []string, out io.Writer, view View) int {
	root := NewRootCommandWithView(out, view)
	root.SetArgs(args)
	if err := root.ExecuteContext(ctx); err != nil {
		// A command that ran something elsewhere reports what it got, rather
		// than flattening every failure to 1. `fleetctl shell` is the first:
		// `exit 3` in a remote shell has to be `exit 3` here, or a script
		// wrapping it cannot tell a failed build from a failed connection. The
		// command silences cobra's own printing for this error; everything else
		// has already been printed by the time this runs.
		var status *exitStatus
		if errors.As(err, &status) {
			return status.code
		}
		return 1
	}
	return 0
}

// NewRootCommand builds the command tree, writing all output to out.
//
// The tree it builds does not draw the full-screen view; `tui` hands that to
// the binary that does. See [NewRootCommandWithView].
func NewRootCommand(out io.Writer) *cobra.Command { return NewRootCommandWithView(out, nil) }

// NewRootCommandWithView builds the command tree with view as what `tui` runs.
//
// A nil view is the base `fleetctl`, and is what every caller but cmd/fleet-tui
// wants.
func NewRootCommandWithView(out io.Writer, view View) *cobra.Command {
	root := &cobra.Command{
		Use:   "fleetctl",
		Short: "Operator CLI for the fleet control plane",
		Long: "fleetctl manages the fleet certificate authority, mints single-use\n" +
			"enrollment tokens, serves the endpoint hosts join the fleet through, and\n" +
			"shows the operator the same view of the fleet the MCP server has.",
		SilenceUsage: true,
		// Errors are printed once, by Execute's caller path below, rather
		// than twice with a usage dump in between.
		SilenceErrors:     false,
		RunE:              func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
		DisableAutoGenTag: true,
		Version:           version.String(),
	}
	root.SetOut(out)
	root.SetErr(os.Stderr)
	root.SetVersionTemplate("fleetctl {{.Version}}\n")

	// The registration surface. New subcommands go here.
	root.AddCommand(
		newCACommand(out),
		newEnrollCommand(out),
		newServeCommand(out),
		newAddCommand(out),
		newListCommand(out),
		newInfoCommand(out),
		newRemoveCommand(out),
		newSelectCommand(out),
		newShellCommand(out),
		newSocksCommand(out),
		newTUICommand(out, view),
		newVersionCommand(out),
	)
	return root
}

// defaultCADir is where the CA lives unless --ca-dir says otherwise. It sits
// inside the config directory but in its own subdirectory, because it holds
// key material and the registry beside it deliberately does not.
func defaultCADir() (string, error) {
	dir, err := registry.ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ca"), nil
}

func defaultTokenPath() (string, error) {
	dir, err := registry.ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "enrollment-tokens.yaml"), nil
}

// defaultControlCertPath and defaultControlKeyPath locate the control leaf this
// workstation presents to agents. They must match what fleet-mcp reads by
// default, or `fleetctl list` and the MCP server would disagree about who this
// operator is.
func defaultControlCertPath() (string, error) { return configFile("control.crt") }
func defaultControlKeyPath() (string, error)  { return configFile("control.key") }

func configFile(name string) (string, error) {
	dir, err := registry.ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

// resolve returns flagValue when set, else the default, so every command can
// take an explicit path without repeating the fallback.
func resolve(flagValue string, fallback func() (string, error)) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	return fallback()
}

func openRegistry(path string) (*registry.Registry, error) {
	if path == "" {
		var err error
		path, err = registry.DefaultPath()
		if err != nil {
			return nil, err
		}
	}
	return registry.Open(path)
}

// loadCA loads the fleet CA, turning "there is no CA here" into the command
// that makes one.
//
// Every command in this CLI that touches the CA goes through this rather than
// ca.Load. Running anything before `ca init` is the single most likely first
// experience of this tool, and answering it with "open
// /Users/x/.config/fleet/ca/ca.crt: no such file or directory" tells an
// operator neither what is missing nor what to do about it.
func loadCA(dir string) (*ca.CA, error) {
	authority, err := ca.Load(dir)
	if err != nil {
		return nil, actionable(dir, err)
	}
	return authority, nil
}

// actionable turns "there is no CA here" into the command that makes one, and
// passes everything else through untouched.
//
// It is separate from [loadCA] because not every command that has to answer for
// an empty CA directory loads the CA: `ca rotate --activate` reads the trust
// bundle instead, so that it can repair a directory whose key and certificate
// disagree.
func actionable(dir string, err error) error {
	if errors.Is(err, ca.ErrNotInitialized) {
		return fmt.Errorf("no fleet CA in %s: run `fleetctl ca init` to create one", dir)
	}
	return err
}

// readFile keeps the error message consistent across commands that take a path
// from the operator.
func readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is operator-supplied on the command line
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}
