package fleetctl

import (
	"io"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/axelmierczuk/fleet-mcp/internal/cli"
	"github.com/axelmierczuk/fleet-mcp/internal/version"
)

// versionResult identifies this build.
//
// The commit is here as its own field, not folded into a version string,
// because the question this command answers in practice is "is the fleetctl on
// this machine the one that has the fix" — and a tag does not answer that
// between releases.
type versionResult struct {
	Version  string `json:"version"`
	Commit   string `json:"commit"`
	Date     string `json:"date"`
	Go       string `json:"go"`
	Platform string `json:"platform"`
}

func newVersionCommand(out io.Writer) *cobra.Command {
	var flags outputFlags
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the fleetctl version",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			result := versionResult{
				Version:  version.Version,
				Commit:   version.Commit,
				Date:     version.Date,
				Go:       runtime.Version(),
				Platform: runtime.GOOS + "/" + runtime.GOARCH,
			}
			return flags.output(out).Emit(result, func(p *cli.Printer) {
				p.Printf("fleetctl %s\n", version.String())
				p.Printf("go:       %s\n", result.Go)
				p.Printf("platform: %s\n", result.Platform)
			})
		},
	}
	flags.register(cmd)
	return cmd
}
