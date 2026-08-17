// Package host implements HostService: platform and resource introspection,
// toolchain detection, and health reporting.
//
// It is the first service the MCP server calls after dialing an agent, and
// Health is called on a timer for every connected sandbox thereafter — so the
// two RPCs are deliberately asymmetric. GetHostInfo may stat filesystems and,
// when asked, probe the PATH. Health reads atomics and returns.
package host
