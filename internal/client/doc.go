// Package client dials fleet-agent instances over gRPC — mutually authenticated
// unless a sandbox is registered as insecure — pooling
// connections and tracking health so fleet_list can report status without a
// round trip per call.
//
// This is the only package in fleet-mcp that knows how to dial an agent.
// Every tool that targets a sandbox goes through Pool: it caches one
// long-lived channel per sandbox name, reconnects lazily with the backoff
// gRPC already provides, and maps transport-level failures to sandbox-level
// errors once, here, rather than at every call site.
package client
