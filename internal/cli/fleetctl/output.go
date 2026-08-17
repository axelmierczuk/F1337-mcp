package fleetctl

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/axelmierczuk/fleet-mcp/internal/cli"
)

// Rendering, in one place.
//
// Every command that has a result renders it the same way: build one value with
// JSON tags, hand it to [output.Emit] along with a function that writes the
// human form, and let the flag decide which the operator gets. Nothing branches
// on --json outside this file, and nothing re-declares the flag.
//
// Two properties this buys, both of which a per-command `if jsonOut` loses
// within a few commands: the JSON shape is the same value the human rendering
// describes rather than a second, drifting projection of it; and a command
// added later — the shell, the TUI and the SOCKS proxy each add some — gets
// both output modes by embedding one struct.

// outputFlags is embedded by every command that renders a result. Embed it,
// call register in the command's constructor, and take the writer from
// [outputFlags.output].
type outputFlags struct {
	asJSON bool
}

// register declares --json on cmd.
func (f *outputFlags) register(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&f.asJSON, "json", false, "render the result as JSON, for scripting")
}

// output binds the flag to a destination.
func (f *outputFlags) output(w io.Writer) *output {
	return &output{w: w, asJSON: f.asJSON}
}

// output renders one command's result, in whichever form was asked for.
type output struct {
	w      io.Writer
	asJSON bool
}

// JSON reports whether the operator asked for machine-readable output. Commands
// need it only to suppress prose that has no place in a JSON document —
// advice, next steps, warnings — never to build a second result.
func (o *output) JSON() bool { return o.asJSON }

// Emit renders doc as JSON, or calls text to write the human form.
//
// doc is always the complete result, including anything the human rendering
// summarises or leaves out, so a script never has to parse the table to reach a
// field the operator can see.
func (o *output) Emit(doc any, text func(*cli.Printer)) error {
	if o.asJSON {
		enc := json.NewEncoder(o.w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(doc); err != nil {
			return fmt.Errorf("render JSON output: %w", err)
		}
		return nil
	}
	p := cli.NewPrinter(o.w)
	text(p)
	return p.Err()
}

// table writes rows beneath headers, column-aligned. Human output only: a
// caller reaches it from inside the text function it passed to Emit.
func (o *output) table(headers []string, rows [][]string) error {
	tw := tabwriter.NewWriter(o.w, 0, 0, 2, ' ', 0)
	p := cli.NewPrinter(tw)
	p.Println(strings.Join(headers, "\t"))
	for _, row := range rows {
		p.Println(strings.Join(row, "\t"))
	}
	if err := p.Err(); err != nil {
		return err
	}
	return tw.Flush()
}

// dash renders an empty column as "-", so a missing value is visibly missing
// rather than a gap the eye slides over in a table.
func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
