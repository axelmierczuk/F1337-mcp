// Command sandboxd-mcp is the MCP server that agent CLIs launch over stdio.
//
// It owns the sandbox registry and the current selection, and translates MCP
// tool calls into gRPC calls against sandboxd-agent instances.
//
// Wiring is filled in by the M2 milestone issues; this entrypoint exists so the
// module builds and the binary layout is fixed.
package main

import (
	"fmt"
	"os"

	"github.com/axelmierczuk/sandboxd-mcp/internal/version"
)

func main() {
	version.FromBuildInfo()

	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println("sandboxd-mcp", version.String())
		return
	}

	fmt.Fprintln(os.Stderr, "sandboxd-mcp: not implemented yet; see milestone M2")
	os.Exit(1)
}
