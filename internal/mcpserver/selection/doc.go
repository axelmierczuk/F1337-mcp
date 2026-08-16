// Package selection resolves which sandbox a tool call targets.
//
// MCP 2026-07-28 removed protocol-level sessions, so selection cannot live in
// transport state. Resolution order is: explicit "sandbox" argument, then the
// sticky default persisted for the calling client, then a structured error
// listing the available sandboxes.
//
// Implemented by milestone M2.
package selection
