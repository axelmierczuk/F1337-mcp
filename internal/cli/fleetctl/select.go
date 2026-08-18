package fleetctl

import (
	"io"

	"github.com/spf13/cobra"

	"github.com/axelmierczuk/fleet-mcp/internal/cli"
	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver/selection"
)

// selectResult is the `select` document: which sandbox this CLI will act on
// when a command does not name one.
type selectResult struct {
	// Name is empty when nothing is selected, which is a state a script has to
	// be able to see rather than infer from a missing key.
	Name     string `json:"name"`
	Address  string `json:"address,omitempty"`
	Handle   string `json:"handle,omitempty"`
	Selected bool   `json:"selected"`
}

func newSelectCommand(out io.Writer) *cobra.Command {
	var (
		flags        outputFlags
		registryPath string
	)
	cmd := &cobra.Command{
		Use:   "select [name]",
		Short: "Choose the sandbox later commands act on",
		Long: "select records a sticky default for this CLI, so `fleetctl shell` and the\n" +
			"commands after it can be run without naming a sandbox every time.\n\n" +
			"Called with no name, it reports what is currently selected.\n\n" +
			"The selection is fleetctl's own. Selections are recorded per client — the\n" +
			"MCP server keeps a separate one for each editor or agent that connects — so\n" +
			"choosing a sandbox here does not move a model's target, and a model calling\n" +
			"fleet_select does not move yours. `fleetctl list` shows the fleet.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			res, err := resolver(registryPath)
			if err != nil {
				return err
			}

			if len(args) == 0 {
				return reportSelection(out, &flags, res)
			}

			target, err := res.Select(cliIdentity, args[0])
			if err != nil {
				return operatorAdvice(err)
			}
			return flags.output(out).Emit(selectResult{
				Name:     target.Name(),
				Address:  target.Address(),
				Handle:   target.Handle,
				Selected: true,
			}, func(p *cli.Printer) {
				p.Printf("selected %s (%s)\n", target.Name(), dash(target.Address()))
			})
		},
	}
	flags.register(cmd)
	cmd.Flags().StringVar(&registryPath, "registry", "", "path to the fleet registry (default: <config dir>/registry.yaml)")
	return cmd
}

// reportSelection answers `fleetctl select` with no argument.
//
// A selection pointing at a sandbox that has since been removed is reported as
// no selection rather than as an error: the operator asked what is selected,
// and "that host is gone" is the answer, not a failure of the question.
func reportSelection(out io.Writer, flags *outputFlags, res *selection.Resolver) error {
	name, ok, err := res.Selected(cliIdentity)
	if err != nil {
		return err
	}

	result := selectResult{Name: name, Selected: ok && name != ""}
	if result.Selected {
		if sb, lookupErr := res.Lookup(name); lookupErr == nil {
			result.Address, result.Handle = sb.Address, selection.HandleFor(sb.Name)
		} else {
			result.Selected = false
		}
	}

	return flags.output(out).Emit(result, func(p *cli.Printer) {
		if !result.Selected {
			if name != "" {
				p.Printf("nothing selected: %q is no longer enrolled\n", name)
			} else {
				p.Println("nothing selected")
			}
			p.Println("Choose one with `fleetctl select <name>`; `fleetctl list` shows the fleet.")
			return
		}
		p.Printf("%s (%s)\n", result.Name, dash(result.Address))
	})
}
