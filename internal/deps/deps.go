//go:build deps

// Package deps pins the dependency versions the implementation milestones are
// expected to build against.
//
// The scaffolding does not import these yet, and `go mod tidy` would otherwise
// drop them from go.mod — leaving each implementer to re-resolve versions and
// arrive somewhere slightly different. The build tag keeps this file out of
// every real build while still being visible to `go mod tidy`, which evaluates
// all build configurations.
//
// Delete an entry once real code imports the module; delete the file once all
// of them are in use.
package deps

import (
	// MCP server transport and tool registration (M2).
	_ "github.com/modelcontextprotocol/go-sdk/mcp"

	// Cross-platform service installation: systemd, launchd, Windows SC (M1).
	_ "github.com/kardianos/service"

	// PTY allocation on Unix and ConPTY on Windows (M1).
	_ "github.com/aymanbagabas/go-pty"

	// Stable identifiers for sandboxes, processes, and selection handles.
	_ "github.com/google/uuid"
)
