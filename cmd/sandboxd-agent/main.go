// Command sandboxd-agent is the daemon that runs on each sandbox host.
//
// It serves the gRPC services defined in proto/sandboxd/v1 over mTLS, and
// supervises background processes independently of any MCP session.
//
// Wiring is filled in by the M1 milestone issues; this entrypoint exists so the
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
		fmt.Println("sandboxd-agent", version.String())
		return
	}

	fmt.Fprintln(os.Stderr, "sandboxd-agent: not implemented yet; see milestone M1")
	os.Exit(1)
}
