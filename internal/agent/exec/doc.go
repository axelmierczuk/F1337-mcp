// Package exec implements ExecService: one-shot command execution with
// streaming output, wall-clock timeouts, and output caps.
//
// # The three things that are easy to get wrong
//
// A failing command is a successful RPC. The exit status goes in the result,
// never in the error, because the caller needs the output to understand it.
//
// The output cap stops buffering, not reading. A process blocked writing to a
// full pipe never exits, so a cap that stopped draining would turn "produced
// too much output" into "hung until the timeout".
//
// Killing means killing the group. `sh -c 'make -j8'` is nine processes, and
// signalling the leader leaves eight compilers running with nobody watching
// them. Both the timeout and the caller hanging up go through
// internal/platform's process group, which is a session on Unix and a job
// object on Windows.
//
// # What this package does not do
//
// It does not confine anything. working_dir is an ordinary path: an agent that
// runs commands can reach every path its account can, whatever any path check
// says, which is why the jail is wired in only on an agent with exec disabled.
// See docs/security.md.
//
// # Layout
//
//	exec.go     the service, the request path, and the kill escalation
//	env.go      the documented base environment and how a request overrides it
//	stream.go   chunking, the output cap, and the truncation report
//	shell_*.go  what `shell: true` routes through on each platform
//	sweep.go    the post-exec sweep and the collection it is ordered against,
//	            both of which platform.ProcessGroup performs
//	wait_*.go   reading a terminating signal out of a process state
package exec
