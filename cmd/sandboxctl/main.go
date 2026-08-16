// Command sandboxctl is the operator CLI for the sandboxd control plane.
//
// It initialises the certificate authority, mints enrollment tokens, serves the
// enrollment endpoint, and inspects the fleet registry. PKI setup deliberately
// lives here rather than behind an MCP tool: minting credentials is an operator
// action, not something a model should be able to trigger.
//
// Wiring is filled in by the M0 and M3 milestone issues; this entrypoint exists
// so the module builds and the binary layout is fixed.
package main

import (
	"fmt"
	"os"

	"github.com/axelmierczuk/sandboxd-mcp/internal/version"
)

func main() {
	version.FromBuildInfo()

	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println("sandboxctl", version.String())
		return
	}

	fmt.Fprintln(os.Stderr, "sandboxctl: not implemented yet; see milestones M0 and M3")
	os.Exit(1)
}
