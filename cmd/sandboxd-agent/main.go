// Command sandboxd-agent is the daemon that runs on each sandbox host.
//
// It serves the gRPC services defined in proto/sandboxd/v1 over mTLS, and
// supervises background processes independently of any MCP session. Serving is
// wired up by the M1 milestone issues; the enroll command, which is what turns
// a bare host into a fleet member, is implemented here.
package main

import (
	"fmt"
	"os"

	"github.com/axelmierczuk/sandboxd-mcp/internal/cli/sandboxdagent"
	"github.com/axelmierczuk/sandboxd-mcp/internal/version"
)

func main() {
	version.FromBuildInfo()

	args := os.Args[1:]
	if len(args) > 0 && (args[0] == "--version" || args[0] == "version") {
		fmt.Println("sandboxd-agent", version.String())
		return
	}

	os.Exit(sandboxdagent.Main(args, os.Stdout))
}
