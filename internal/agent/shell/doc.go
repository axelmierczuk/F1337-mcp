// Package shell implements sandboxd.v1.ShellService: one interactive
// pseudo-terminal session per stream.
//
// # What this is, in security terms
//
// This is the most direct remote-code-execution surface in the product. It is
// not a new capability — a caller who can reach ExecService already runs
// arbitrary commands as the agent's account — but it is the most convenient
// one, and the audit record therefore matters more here than anywhere else.
// See docs/security.md.
//
// # The contents of a session are never recorded
//
// A shell session carries whatever the operator types and whatever the host
// prints back: passwords at a sudo prompt, a token pasted into a curl command,
// the contents of a private key echoed by `cat`. An audit log holding that
// would be a credential store nobody meant to build, sitting on the least
// protected host in the fleet — and one with weaker handling than whatever it
// copied the secrets out of.
//
// The rule is enforced by the shape of this package rather than by everyone
// remembering it:
//
//   - The only value the audit path can see is [sessionAudit], which has no
//     field capable of holding a byte of the session. [Service.finish] is the
//     only call to Audit.Write in the package, and it takes nothing else.
//   - The code that touches session bytes is [session.pumpInput] and
//     [session.readTerminal], which is the loop [session.pumpOutput] and
//     [session.drainTerminal] share. None of them is given the audit log, the
//     record, or anything derived from them; each holds a buffer whose scope is
//     one loop iteration.
//   - Nothing in this package logs a buffer. Byte counts are volume rather
//     than content and are safe to keep; the bytes themselves never reach a
//     log line, at any level.
//
// A test asserts the property end to end — a session that types a secret and
// prints a different one, with neither anywhere in the audit log or the
// daemon's own output — because the structure above is what makes the mistake
// hard, not impossible.
//
// # Why this is not ExecService with a flag
//
// ExecService is one command run to completion with no terminal. The two
// differ in nearly every mechanic: output here is a single merged stream
// because a pseudo-terminal has already merged it, there is no output cap
// because the caller is a screen rather than a context window, the session is
// bounded by idleness rather than by wall-clock time, and an interrupt arrives
// as a byte rather than as a cancelled RPC. Bolting those onto Exec would have
// made one service with two behaviours and one set of tests that covers
// neither.
package shell
