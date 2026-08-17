// Package host implements HostService: platform and resource introspection,
// toolchain detection, and health reporting.
//
// It is the first service the MCP server calls after dialing an agent, and
// Health is called on a timer for every connected sandbox thereafter — so the
// two RPCs are deliberately asymmetric. GetHostInfo may stat filesystems and,
// when asked, probe the PATH. Health reads atomics and returns.
//
// # What this package does not measure
//
// Platform description and host capacity come from [internal/platform]: the
// kernel version, the cgroup-narrowed CPU and memory figures, the load average
// and the filesystem usage. This package chooses *which* filesystem to measure
// — the first allowed root that exists — bounds how long the measurement may
// take, and translates the result onto the wire. It does not read /proc,
// sysctl or Win32 itself, and it did once: two implementations of the same
// measurement, only one of them audited, is how a container-confined agent ends
// up advertising the host's memory.
//
// Toolchain detection does live here, because it is HostService's alone: the
// PATH sweep, its budget, and the deliberately minimal environment a version
// probe inherits.
package host
