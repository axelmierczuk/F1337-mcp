// Command sandboxctl is the operator CLI for the sandboxd control plane.
//
// It initialises the certificate authority, mints enrollment tokens, serves the
// enrollment endpoint, and inspects the fleet registry. PKI setup deliberately
// lives here rather than behind an MCP tool: minting credentials is an operator
// action, not something a model should be able to trigger.
package main

import (
	"fmt"
	"os"

	"github.com/axelmierczuk/sandboxd-mcp/internal/cli/sandboxctl"
	"github.com/axelmierczuk/sandboxd-mcp/internal/version"
)

func main() {
	version.FromBuildInfo()

	args := os.Args[1:]
	if len(args) > 0 && (args[0] == "--version" || args[0] == "version") {
		fmt.Println("sandboxctl", version.String())
		return
	}

	os.Exit(sandboxctl.Main(args, os.Stdout))
}
