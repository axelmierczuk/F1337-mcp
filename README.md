# sandboxd

**Let your coding agent choose which machine it runs on.**

An MCP server plus a small cross-platform daemon that give an agent CLI a fleet
of execution targets, with `exec`, `read`, `write`, `edit`, and process
supervision that behave like the tools it already has — except they run over
there.

> [!WARNING]
> `sandboxd-agent` is a remote code execution service. That is its purpose, not
> a caveat. Read [docs/security.md](docs/security.md) before installing it
> anywhere.

---

## Why

Your agent runs on your laptop, so your laptop is the only place it can execute.
Every way around that is unsatisfying:

| Approach | Why it falls short |
| --- | --- |
| **Just run it locally** | No isolation. Dependency installs, runaway builds, and the occasional `rm -rf` land on your daily driver. |
| **Tell the agent to SSH** | Agents are bad at interactive SSH. No structured exit codes, ad-hoc output truncation, fragile session state, no file primitives, and credentials smeared across command lines. |
| **Docker / devcontainers** | One machine. Cannot express "build on the ARM mac, fuzz on the big Linux box, reproduce on the Windows rig." |
| **Hosted sandbox SaaS** | You rent someone else's compute, ship your source to it, and still cannot point it at the hardware sitting under your desk. |

The gap is specific: **there is no simple, off-the-shelf way for an agent to
select a host from a fleet you control and then work on it.** Selection and
execution are separate problems, and nothing solves both.

`sandboxd` solves both. Register the machines you already own. The agent calls
`sandbox_select`, then uses a toolset that mirrors its native one.

```
you: run the integration suite on the GPU box, and start the dev server on the mac

agent: sandbox_select(name="gpu-01")
       sandbox_exec(argv=["go","test","./...","-tags=integration"])   → exit 0, 41s
       sandbox_select(name="mac-mini")
       sandbox_process_start(name="dev", argv=["npm","run","dev"],
                             ready_probe={tcp_port: 5173}, wait_for_ready=true)
                                                                     → state: ready
       sandbox_forward(remote_port=5173)                             → localhost:5173
```

## How it fits together

```
   Claude Code / Cursor / any MCP client
              │  stdio, via mcp.json
              ▼
        sandboxd-mcp ──────── registry + selection  (~/.config/sandboxd)
              │
              │  gRPC over mTLS
              ├──────────────► sandboxd-agent   linux/amd64    build box
              ├──────────────► sandboxd-agent   darwin/arm64   mac mini
              └──────────────► sandboxd-agent   windows/amd64  test rig

        sandboxctl ────────── CA, enrollment tokens, fleet inspection
```

Three binaries, one Go module:

| Binary | Runs on | Job |
| --- | --- | --- |
| `sandboxd-mcp` | your workstation | MCP server over stdio; owns the registry and the current selection |
| `sandboxd-agent` | every sandbox host | gRPC services over mTLS; supervises background processes |
| `sandboxctl` | your workstation | CA setup, enrollment tokens, fleet inspection |

The agent never imports the MCP SDK, and the MCP server never touches the CA
signing key. Minting credentials is an operator action, deliberately kept out of
reach of anything a model can call.

## Quickstart

**1. Install the workstation tools.**

```sh
go install github.com/axelmierczuk/sandboxd-mcp/cmd/sandboxd-mcp@latest
go install github.com/axelmierczuk/sandboxd-mcp/cmd/sandboxctl@latest
```

**2. Create a CA and mint an enrollment token.**

```sh
sandboxctl ca init
sandboxctl serve &                    # enrollment endpoint, :9443
sandboxctl enroll mint --name build-box
# → token: sbx_ey...   ca fingerprint: 9f2c...
```

**3. Turn a machine into a sandbox — one command.**

```sh
curl -fsSL https://raw.githubusercontent.com/axelmierczuk/sandboxd-mcp/main/install.sh \
  | sh -s -- --token sbx_ey... \
             --control your-workstation:9443 \
             --ca-fingerprint 9f2c... \
             --root /home/build/workspace
```

The installer detects the platform, verifies the release checksum, enrolls the
host — generating its keypair locally, so **the private key never crosses the
network** — and registers a system service. Windows hosts use `install.ps1`.

**4. Point your agent at it.**

```json
{
  "mcpServers": {
    "sandboxd": {
      "command": "sandboxd-mcp",
      "args": ["serve"]
    }
  }
}
```

That's it. `sandbox_list` should show `build-box`.

## Tools

Nineteen tools across five groups. See [docs/tools.md](docs/tools.md) for full
schemas.

**Fleet** — `sandbox_list` · `sandbox_select` · `sandbox_add` · `sandbox_remove` · `sandbox_info`

**Execute** — `sandbox_exec`

**Background processes** — `sandbox_process_start` · `sandbox_process_list` · `sandbox_process_logs` · `sandbox_process_signal` · `sandbox_process_restart`

**Files** — `sandbox_read` · `sandbox_write` · `sandbox_edit` · `sandbox_ls` · `sandbox_glob` · `sandbox_grep`

**Bridge** — `sandbox_transfer` · `sandbox_forward`

### How selection works

MCP `2026-07-28` made the protocol stateless: no session handshake, no
`Mcp-Session-Id`. So "the selected sandbox" cannot live in transport state. The
spec's own guidance is to mint an explicit handle and have the model pass it
back — but making the model thread a handle through forty consecutive calls is
miserable, and it will drop it.

So `sandbox_select` does both:

1. It returns an opaque **handle**.
2. It writes a **sticky default**, persisted per client, surviving restarts.
3. **Every** targeted tool takes an optional `sandbox` argument that overrides
   the default.
4. With no argument and no default, tools fail with a structured error listing
   what is available — never a silent guess.
5. **Every result echoes the sandbox that served it.**

That last rule is the one that matters most. An agent that believes it is on
host A while executing on host B is the worst failure this project can produce,
and it is the kind of bug that stays invisible until it destroys something.

### Why background processes get their own service

Running `npm run dev` is not "a command that takes a long time" — it is a
different lifecycle, and treating it like a slow `exec` breaks in specific ways
that `sandboxd` handles explicitly:

- **Processes outlive the MCP session.** They are owned by the agent daemon.
  Agent CLIs restart constantly; a dev server that dies with the editor is
  useless.
- **Readiness is not the same as spawned.** A dev server takes seconds to bind
  its port. Without a probe, the model curls immediately, gets a connection
  refused, and concludes the server is broken. `ready_probe` waits for a log
  pattern, a TCP port, or an HTTP response.
- **Killing means killing the tree.** Signalling only the leader leaves the
  bundler holding the port. On Unix each process gets its own group; on Windows
  a job object with `KILL_ON_JOB_CLOSE`.
- **Logs survive the crash.** A bounded ring buffer for fast tailing, plus a
  rotating file on disk, so a failure twenty minutes ago is still diagnosable.
  Dropped lines are reported, never silently swallowed.
- **Following is always bounded.** A tool call that never returns is
  indistinguishable from a hung agent, and the model cannot recover from it.
- **PID reuse is handled.** After an agent restart, a process is re-adopted only
  if its PID *and* start time both match.

## Security

The short version:

- **mTLS everywhere.** No plaintext mode, not even on loopback.
- **Keys never move.** Enrollment is a CSR exchange against a single-use token.
- **Path jail.** Symlinks are resolved *before* containment is checked —
  rejecting `..` up front is the classic way to build a jail a symlink walks
  straight out of.
- **No shell by default.** Commands take an argv, not a string. Opt in with
  `shell: true`.
- **Caps and audit.** Wall-clock timeouts, output limits, and an append-only
  JSONL record of every exec and every write.

**`sandboxd` does not sandbox.** It is remote execution against a host you
designate. The isolation is whatever that host already provides — a VM, a
container, a dedicated machine. Full threat model in
[docs/security.md](docs/security.md).

## Development

```sh
make tools     # pinned buf, protoc plugins, golangci-lint into .tools/
make proto     # regenerate Go from proto/
make build     # all three binaries
make check     # everything CI runs
```

The wire contract lives in [`proto/sandboxd/v1`](proto/sandboxd/v1). Generated
code is committed under `gen/`, so consuming the module needs no proto
toolchain; `make proto-check` fails CI if it drifts from the sources.

| Layer | Choice |
| --- | --- |
| Language | Go 1.25 |
| MCP | [`modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk) v1.7.0 (protocol `2026-07-28`) |
| RPC | gRPC v1.83 · protobuf v1.36 |
| Proto tooling | buf (lint, format, breaking-change detection) |
| PTY | `aymanbagabas/go-pty` (Unix PTY and Windows ConPTY) |
| Service install | `kardianos/service` (systemd, launchd, Windows SC) |
| Release | GoReleaser, six platform pairs, checksums and build provenance |

## Status

Early. The protocol schema, scaffolding, and build pipeline are in place; the
implementation is tracked in
[#29](https://github.com/axelmierczuk/sandboxd-mcp/issues/29) across four
milestones — M0 foundation, M1 agent, M2 MCP server, M3 distribution. See
[docs/architecture.md](docs/architecture.md) for the design in full.

## License

MIT. See [LICENSE](LICENSE).
