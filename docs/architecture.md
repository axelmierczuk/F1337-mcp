# Architecture

## Components

```
   MCP client (Claude Code, Cursor, …)
              │  JSON-RPC over stdio
              ▼
   ┌──────────────────────────────────────┐
   │ fleet-mcp                            │
   │   internal/mcpserver/tools           │  tool handlers
   │   internal/mcpserver/selection       │  which sandbox does this call target
   │   internal/registry                  │  fleet inventory, sticky default
   │   internal/client                    │  mTLS gRPC dialer + pool
   └──────────────────────────────────────┘
              │  gRPC / mTLS  (:8722)
              ▼
   ┌──────────────────────────────────────┐
   │ fleet-agent                          │
   │   internal/agent/host                │  HostService
   │   internal/agent/exec                │  ExecService
   │   internal/agent/fs                  │  FileService
   │   internal/agent/process             │  ProcessService
   │   internal/agent/shell               │  ShellService
   │   internal/security/jail             │  path confinement
   │   internal/security/policy           │  command policy, caps, audit
   │   internal/platform                  │  OS-specific behaviour
   └──────────────────────────────────────┘

   ┌──────────────────────────────────────┐
   │ fleetctl                (:9443)      │
   │   internal/cli/fleetctl              │  operator commands
   │   internal/security/ca               │  CA, signing, rotation
   │   internal/security/enroll           │  EnrollmentService, tokens
   │   internal/client                    │  the same client fleet-mcp uses
   └──────────────────────────────────────┘
              │  `fleetctl tui` hands over its argv and its terminal
              ▼
   ┌──────────────────────────────────────┐
   │ fleet-tui                            │
   │   internal/cli/fleetctl              │  the same command tree
   │   internal/tui                       │  the full-screen view
   └──────────────────────────────────────┘
```

`fleetctl` is a separate control plane rather than a subcommand of the MCP
server for one reason: the MCP server is a process a model can reach. The CA
signing key must not be.

It reads the fleet through `internal/client` — the same package, TLS
configuration and health vocabulary `fleet-mcp` uses — rather than through
anything of its own. `fleetctl list` is what an operator reaches for when the
model reports a sandbox as unreachable, and a CLI with a second idea of fleet
health would answer that question about itself instead of about the fleet.

`fleetctl tui` (`internal/tui`) is held to the same rule one step further: it is
a view, not a second implementation. Its four panes are backed by the same
`internal/client` calls, and the only thing it puts on a schedule per sandbox is
the pool's own background health cache — the process list, the log follow and
the host detail are fetched for the focused sandbox alone, because polling every
pane for every host is what makes a large fleet unwatchable. The model, the
layout and the rendering are pure functions over values, so the parts a terminal
cannot be asked about in a test — refresh scheduling, confirmation gating,
degradation below 80x24 — are asserted on directly.

It is also the one thing here that is a separate process, and that is a linking
decision rather than a design one. bubbletea's package init asks the terminal
for its background colour and reads for up to five seconds waiting for an
answer; package inits run in every process that links the package, whatever
subcommand was typed, so linking the view into `fleetctl` made `fleetctl
version` on a terminal that does not answer cost five seconds and swallow
whatever was typed meanwhile (#73). Nothing inside the process can opt out —
every escape hatch the library has is read during that init, before any of our
code runs — so the only fix is not to link it, and the only way to keep the
command while not linking it is a second binary.

`fleet-tui` is therefore not a second CLI. It is this same command tree, built
by the same `NewRootCommandWithView`, with the view supplied; `fleetctl tui`
finds it beside itself and hands over its command line unchanged. There is one
implementation of every flag, every default and every credential path. What
holds that in place is `TestOnlyTheViewBinaryLinksATerminalUI`, which resolves
each command's imports and fails if a binary that draws nothing links something
that owns the terminal.

Because the two binaries are one command tree, a mis-install can put `fleetctl`
where the helper belongs — a packager's `cp`, `mv` or `ln -s` — and then the
hand-off is a process exec'ing something that hands over in turn. The hand-off
therefore carries a marker in the helper's environment, and a `fleetctl` that
finds one set refuses instead of handing over again: **the terminal is handed
over at most once**, whatever any binary works out about which file it is. That
guarantee is deliberately not an identity check — "am I the file I am about to
exec?" is unanswerable on a host that cannot name its own binary, and a wrong
answer refuses the *real* helper — so identity is used only to skip a bad
candidate and to name the file in the refusal.

## Selection under a stateless protocol

MCP `2026-07-28` removed protocol-level sessions. There is no handshake to hang
per-connection state off, and a server may be behind a round-robin load
balancer. The specification's guidance is to mint an explicit handle from a tool
and have the model pass it back as an argument.

A pure handle design is correct and unusable: the model must thread the handle
through every subsequent call, and it will eventually drop it. A pure implicit
design is usable and incorrect: it breaks with concurrent clients and cannot
survive a restart.

`fleet` resolves the target in a fixed order:

1. The call's explicit `sandbox` argument, if present. Always wins.
2. The sticky default recorded for the calling client identity (taken from
   `_meta`), persisted in the registry.
3. Otherwise: a structured error listing available sandboxes and instructing the
   model to call `fleet_select`.

`fleet_select` sets (2) and returns a handle usable as (1).

There is deliberately no fourth rule. A fleet of exactly one sandbox does not
resolve implicitly either: a fleet grows from one to two without anyone
revisiting the calls written while it had one member.

**Client identity** is taken from `_meta`, in order: the `io.fleet/clientId`
key, if the client sets one; otherwise the client implementation name, which
protocol `2026-07-28` carries in `_meta` as
`io.modelcontextprotocol/clientInfo`; otherwise a per-process fallback. Keying
on the name rather than name-and-version means upgrading a client does not
silently drop its selection. A client that runs several concurrent sessions and
wants each to hold its own target sets `io.fleet/clientId`.

A selection made under the per-process fallback is held in memory and never
written to the registry. The fallback is `process:<pid>`, and a pid is reused:
persisting under one would let an unrelated later process inherit a target
chosen by a session that ended weeks ago. That is implicit targeting reached by
a different route, and it is the failure this whole ordering exists to prevent.
An identity that cannot be keyed to anything stable gets a selection that lasts
as long as the process and no longer.

**Handles** are derived from the sandbox name — `sbx_` plus a truncated
SHA-256 — rather than minted and stored. That makes them stable across a
restart of both the server and the registry with nothing extra to persist, and
opaque enough that a model cannot construct one for a sandbox it was never
given.

A reference carrying the `sbx_` prefix resolves as a handle first and only then
as a name. `fleet_add` refuses to register a name with that prefix, but it is
not the only way a name reaches the registry: an enrollment token that reserves
no name lets the enrolling host choose its own. Matching names first would let
such a host name itself after another sandbox's handle and receive every call
aimed at it.

Every tool result carries the resolved sandbox name. This is not diagnostic
garnish — silent target confusion is the most destructive failure mode
available to this system, and it is invisible without an echo. The echo is
enforced structurally rather than by convention: a tool's output type must
embed the echo field to satisfy the registration helper's type constraint, and
the helper overwrites it with the resolved name after the handler returns.

## Transport

gRPC with protobuf, chosen for streaming, generated cross-language clients, and
a wire contract that can be checked for breaking changes in CI.

Streaming is used where buffering would be wrong, not everywhere:

| RPC | Shape | Reason |
| --- | --- | --- |
| `ExecService.Exec` | server stream | Progress visible during long commands; output caps applied incrementally rather than after the memory is already spent. |
| `FileService.ReadFile` | server stream | Large files never buffer whole on either side. |
| `FileService.WriteFile` | client stream | Same, in reverse. Written to a temp file and renamed, so a failed transfer cannot leave a truncated file. |
| `FileService.Grep` | server stream | Results before the walk finishes. |
| `ProcessService.GetProcessLogs` | server stream | Replay buffered output, then follow new output to a bounded deadline. |
| `ForwardService.Forward` | bidirectional | One stream per carried TCP connection — a port forward's and a SOCKS proxy's alike. A proxy marks its connections with `ForwardOpen.socks`, which selects which of the agent's two policies applies; it needs no RPC of its own, and a second byte-pump would be a second place to leak a goroutine per connection. |
| `ShellService.Shell` | bidirectional | One stream per interactive terminal session: keystrokes and resizes one way, terminal output the other, for as long as the operator holds it open. |

Everything else is unary.

## Process supervision

The supervisor is the most stateful part of the system and the part most
exposed to platform differences.

**State machine**

```
                ┌─────────┐
                │ STARTING│ ──probe passes──► READY ──┐
                └────┬────┘                           │
                     │ no probe configured            │
                     └──────────────────► RUNNING ────┤
                                                      │
                    exit 0 ──► EXITED ◄───────────────┤
                    exit ≠ 0, killed,                 │
                    or probe failed ──► CRASHED ◄─────┘
                                            │
                                  restart policy allows
                                            ▼
                                       RESTARTING ──► STARTING

   ORPHANED: the agent restarted and could not prove this process survived.
```

**Ownership.** Processes belong to the agent daemon, not to the MCP session that
created them. Agent CLIs restart constantly; a dev server bound to the editor's
lifetime is not useful.

**Process groups.** On Unix a child is placed in its own session and process
group, and signals go to the group. Signalling the leader alone routinely leaves
orphans — killing `npm run dev` without its group leaves the bundler holding the
port. On Windows the equivalent is a named job object; terminating `node.exe`
alone leaves the tree running. The job is deliberately *not*
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` — that flag kills every process in the job
when the last handle closes, which is exactly what an agent upgrade does, and it
would take down every dev server on the host at each restart. The name is what
lets a restarted agent reopen the job instead. One-shot `exec` is the opposite
case and does want kill-on-close; `platform.NewProcessGroup` refuses the two
together rather than resolving them.

**Concurrency.** `process.max_concurrent` is an agent-wide cap. Every service
that spawns a process takes a slot from one shared limiter, because a limit each
service enforced from its own count would not be a limit on the agent: two
services each allowing 32 is a host running 64.

**Command execution.** Starting a supervised process runs a command, so
`ProcessService` is refused on an agent configured with `exec.enabled: false` —
the one configuration in which `allowed_roots` is a real boundary. See
[security.md](security.md).

**Re-adoption after restart.** The supervisor persists
`{process_id, pid, start_time, argv_hash}`. On startup it re-adopts a process
only when the PID exists *and* its start time matches the record. PID reuse is
not a theoretical concern on a busy box, and adopting the wrong process means
the agent will later signal something it does not own. A mismatch produces
`ORPHANED` with an `adoption_note` explaining the decision. A process re-adopted
while it was still being probed has its readiness probe resumed, because
otherwise nothing would ever decide it: the probe was running in an agent that
no longer exists.

**Where the capture resumes.** A re-adopted process's logs pick up where the
previous agent stopped reading, at a byte offset the record carries. That offset
is the one piece of per-run state that changes continuously while nothing else
about the process changes at all, so it is written back on a cadence rather than
only when the process changes state. A stop rewrites the record on the way out
and so hides the difference; after a *killed* agent the next one would resume
from the position recorded when the process started, and replay a history that
opens with a duplicate of itself, at the moment an operator is least able to
afford distrusting the log (#71). The cadence bounds that duplication to what
the process wrote in the last few seconds, and a process that is producing no
output is not written at all.

**Readiness is per run, not per process.** A `log_pattern` probe scans the lines
already buffered before it starts following new ones — a process that announces
itself before the probe is set up would otherwise never be seen. The buffer
outlives a run, though: a restart keeps the whole log history, which is what
makes the output of the run that died readable afterwards. So each run records
the log sequence its output starts at, and the scan is bounded to it. Without
that bound a restarted process matched the *previous* run's announcement, and a
crash-looping service under `restart_policy: always` reported healthy on every
restart (#57). The bound is persisted with the record, so a resumed probe reads
the run's own history and not the history of the runs before it.

**Log buffering.** A bounded in-memory ring buffer serves fast tailing; a
size-capped rotating file on disk keeps history past a crash. A process that
outruns both has lines dropped, and the drop count is reported on the following
line — the model needs to know its view of the log has a hole in it.

**Bounded follow.** `GetProcessLogs` with `follow` always has a deadline, and
the agent clamps it to a configured maximum. An unbounded follow is
indistinguishable from a hung agent, and the model has no way to recover.

## Filesystem

The path jail is wired in only on an agent with `exec.enabled: false`. With exec
on — the default — one `ExecService` call runs
`["sh","-c","echo x > /etc/passwd"]` without touching `FileService` at all, so
the roots would confine nothing an attacker would do. They are ignored rather
than half-enforced, the daemon warns about it at every start, and `GetHostInfo`
reports the agent as unconfined. See [security.md](security.md).

Where it *is* in force, every path passes through `internal/security/jail`
before any syscall:

1. Resolve to an absolute path.
2. Resolve symlinks fully.
3. Check the *resolved* path for containment under an allowed root.

The order matters. Rejecting `..` in the requested path before resolution is the
classic mistake: a symlink inside the jail pointing outside it walks straight
through that check.

`fleet_edit` deliberately mirrors the exact-match, uniqueness-enforcing
contract of the agent's built-in edit tool. Matching that contract is what makes
the remote tool feel native, and the uniqueness requirement is what stops an
ambiguous match from silently editing the wrong line.

## Repository layout

```
proto/sandboxd/v1/      wire contract
gen/go/                 generated code, committed
cmd/                    every binary
internal/mcpserver/     MCP transport, tools, selection
internal/registry/      fleet inventory and persisted state
internal/client/        gRPC client, pooling, health
internal/agent/         server-side service implementations
internal/security/      CA, enrollment, jail, policy
internal/platform/      OS-specific behaviour
```

`internal/platform` exists so that every place the three operating systems
genuinely differ is in one package with build tags, rather than scattered
through the service implementations.
