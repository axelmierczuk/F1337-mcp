// Command fleetctl is the operator CLI for the fleet control plane.
//
// It initialises the certificate authority, mints enrollment tokens, serves the
// enrollment endpoint, and inspects the fleet registry. PKI setup deliberately
// lives here rather than behind an MCP tool: minting credentials is an operator
// action, not something a model should be able to trigger.
package main

import (
	"os"

	"github.com/axelmierczuk/fleet-mcp/internal/cli/fleetctl"
	"github.com/axelmierczuk/fleet-mcp/internal/version"
)

func main() {
	// Before the command tree is built: the root command's --version and the
	// `version` subcommand both read these, and a `go install` build has its
	// commit only in the embedded VCS stamp.
	version.FromBuildInfo()

	os.Exit(fleetctl.Main(os.Args[1:], os.Stdout))
}
