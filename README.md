<p align="center">
  <img src="docs/assets/logo.svg" alt="Three connected sandboxes" width="120">
</p>

# sandboxd

**Let your coding agent choose which machine it runs on.**

An MCP server plus a small cross-platform daemon that give an agent CLI a
fleet of execution targets — `exec`, file ops, and process supervision that
work like the tools it already has, except they run on a machine you
designate instead of your laptop.

> [!WARNING]
> `sandboxd-agent` is a remote code execution service. That is its purpose,
> not a caveat. Read [docs/security.md](docs/security.md) before installing
> it anywhere.


> [!NOTE]
> _**AI;DR:**_ This software was entirely developed using LLMs. Please use 
> IP-based allow-listing to prevent unauthorized parties from gaining remote
> code execution on the machine running the sandbox agent. 

## What it is

Three binaries, one Go module:

- **`sandboxd-mcp`** — runs on your workstation. The MCP server your agent
  talks to. Owns the registry of known sandboxes and the current selection.
- **`sandboxd-agent`** — runs on every sandbox host. Listens over gRPC/mTLS,
  runs commands, and supervises background processes.
- **`sandboxctl`** — runs on your workstation. Sets up the CA, mints
  enrollment tokens, and inspects the fleet.

The agent CLI (Claude Code, Cursor, etc.) calls `sandbox_select` to pick a
host, then uses the same exec/file/process tools it already knows — they
just execute wherever you pointed them.

## Install

**1. Get the workstation tools:**

```sh
go install github.com/axelmierczuk/sandboxd-mcp/cmd/sandboxd-mcp@latest
go install github.com/axelmierczuk/sandboxd-mcp/cmd/sandboxctl@latest
```

**2. Create a CA and mint an enrollment token:**

```sh
sandboxctl ca init
sandboxctl serve &                    # enrollment endpoint, :9443
sandboxctl enroll mint --name build-box
# → token: sbx_ey...   ca fingerprint: 9f2c...
```

**3. Enroll a machine as a sandbox:**

```sh
curl -fsSL https://raw.githubusercontent.com/axelmierczuk/sandboxd-mcp/main/install.sh \
  | sh -s -- --token sbx_ey... \
             --control your-workstation:9443 \
             --ca-fingerprint 9f2c... \
             --root /home/build/workspace
```

This detects the platform, verifies the release checksum, enrolls the host
(the private key is generated locally and never leaves the machine), and
installs a system service. Use `install.ps1` on Windows.

**4. Point your agent at the MCP server:**

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

Done. `sandbox_list` should show `build-box`.

## Tools

Nineteen tools across five groups — see [docs/tools.md](docs/tools.md) for
full schemas.

- **Fleet** — `sandbox_list`, `sandbox_select`, `sandbox_add`, `sandbox_remove`, `sandbox_info`
- **Execute** — `sandbox_exec`
- **Background processes** — `sandbox_process_start`, `sandbox_process_list`, `sandbox_process_logs`, `sandbox_process_signal`, `sandbox_process_restart`
- **Files** — `sandbox_read`, `sandbox_write`, `sandbox_edit`, `sandbox_ls`, `sandbox_glob`, `sandbox_grep`
- **Bridge** — `sandbox_transfer`, `sandbox_forward`

`sandbox_select` sets a sticky default sandbox (persisted per client), and
every targeted tool can override it with an optional `sandbox` argument.
Every result echoes back which sandbox actually served it, so the agent
never silently acts on the wrong host.

## Security

- **mTLS everywhere.** No plaintext mode, not even on loopback.
- **Keys never move.** Enrollment is a CSR exchange against a single-use token.
- **No shell by default.** Commands take an argv, not a string.
- **Caps and audit.** Wall-clock timeouts, output limits, append-only JSONL
  log of every exec and write.

`sandboxd` does not sandbox — it's remote execution against a host you
designate. Isolation is whatever that host already provides (VM, container,
dedicated machine). Full threat model in [docs/security.md](docs/security.md).

## Development

```sh
make tools     # pinned buf, protoc plugins, golangci-lint into .tools/
make proto     # regenerate Go from proto/
make build     # all three binaries
make check     # everything CI runs
```

Go 1.25, [`modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk),
gRPC/protobuf, buf for proto tooling, GoReleaser for release builds.

## Status

Early. Protocol schema and build pipeline are in place; implementation is
tracked in [#29](https://github.com/axelmierczuk/sandboxd-mcp/issues/29).
See [docs/architecture.md](docs/architecture.md) for the full design.

## License

MIT. See [LICENSE](LICENSE).
