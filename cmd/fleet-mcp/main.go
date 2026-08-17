// Command fleet-mcp is the MCP server that agent CLIs launch over stdio.
//
// It owns the sandbox registry and the current selection, and translates MCP
// tool calls into gRPC calls against fleet-agent instances.
//
// `serve` speaks JSON-RPC on stdin and stdout. Nothing else is ever written to
// stdout while it runs: a stray line there corrupts the protocol stream, and
// the symptom is a client that disconnects without explanation.
package main

import (
	"fmt"
	"os"

	"github.com/axelmierczuk/fleet-mcp/internal/cli/fleetmcp"
	"github.com/axelmierczuk/fleet-mcp/internal/version"
)

func main() {
	version.FromBuildInfo()

	args := os.Args[1:]
	if len(args) > 0 && (args[0] == "--version" || args[0] == "version") {
		fmt.Println("fleet-mcp", version.String())
		return
	}

	os.Exit(fleetmcp.Main(args, os.Stdout))
}
