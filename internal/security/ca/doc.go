// Package ca implements the local certificate authority: key generation, CSR
// signing, and rotation.
//
// The CA issues every identity in the fleet and lives only in fleetctl,
// never in fleet-mcp: nothing a model can reach through the MCP server
// should be able to mint a credential. Two leaf profiles exist — agent
// (server auth, one per sandbox host) and control (client auth, held by
// fleet-mcp) — and each is restricted to its own extended key usage so a
// leaf issued for one cannot be presented as the other.
package ca
