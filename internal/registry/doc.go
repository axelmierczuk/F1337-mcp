// Package registry persists the sandbox inventory and the sticky selection to
// the user config directory.
//
// It is the MCP server's only durable state: which sandboxes exist, how to
// reach them, and which one each client currently has selected. It stores
// addresses and labels, not credentials — certificates and keys live under
// the CA directory with their own permissions.
package registry
