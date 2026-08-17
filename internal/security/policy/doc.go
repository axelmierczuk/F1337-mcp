// Package policy evaluates per-sandbox execution rules: command allow and deny
// lists, resource caps, and the audit trail.
//
// # What this is not
//
// The default is allow-all, and that is deliberate. sandboxd-agent is a remote
// code execution service by design, and a deny list on one is a speed bump: an
// operator who denies "sh" has not stopped a caller reaching a shell, they have
// stopped it reaching that one. Presenting a command list as a security
// boundary is worse than not having one, because it is what people plan
// around. Real confinement comes from outside the agent — a container, a VM, or
// an account that cannot read what you care about.
//
// What the lists are good for is narrowing an agent to a job on purpose:
// a build box that should only ever run "go" and "make", or one where "rm"
// has no business being called remotely. Judge them as operational guardrails
// rather than as a sandbox.
//
// # The audit log is forensic
//
// It records what was asked for and what happened. It does not prevent
// anything, and it does not survive an attacker: a caller who can execute code
// on the host can also reach the file the records are written to. Ship it
// off-host if it needs to outlive the host.
//
// # Layout
//
//	policy.go   the allow/deny lists, the caps, and the concurrency limiter
//	lookup.go   resolving argv[0] to the executable the kernel would run
//	audit.go    the append-only JSONL record and its size-based rotation
package policy
