// Package process implements ProcessService: the supervisor for long-running
// background processes.
//
// Supervised processes are owned by the agent and outlive the MCP session that
// started them. They are spawned against a supervisor-owned context, never an
// RPC's — a dev server whose lifetime is tied to the call that created it dies
// when the agent CLI reconnects, and avoiding that is the reason this package
// exists rather than a longer exec timeout.
//
// # How the pieces fit
//
//   - state.go holds the state machine, and it is the only place a process's
//     state is assigned. Every transition goes through record.setState, which
//     consults one table.
//   - supervisor.go owns the record set, spawning, monitoring, the restart
//     policy, and the concurrency and name-uniqueness rules.
//   - tail.go captures output. A supervised process writes to files the agent
//     opened and the agent tails them, rather than writing to a pipe — a pipe's
//     read end dies with the agent, and a re-adopted process has to keep
//     producing logs.
//   - logbuf.go turns what is tailed into a bounded ring buffer for fast
//     tailing, a size-capped rotating file for history, and a fan-out to live
//     followers. A readiness probe is one of those followers, which is what
//     lets a log_pattern probe watch the stream without draining it.
//   - logs.go serves GetProcessLogs. Every follow has a deadline, always.
//   - probe.go decides when "spawned" has become "usable".
//   - signal.go delivers signals to the process group, re-validating the pid
//     against its recorded start identity every time.
//   - store.go and adopt.go persist records atomically and work out, on
//     startup, which recorded children are still this agent's children.
//
// Implemented by milestone M1, issues #11 through #15.
package process
