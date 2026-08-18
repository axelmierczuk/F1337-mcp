<p align="center">
  <img src="docs/assets/logo.svg" alt="Three connected sandboxes" width="120">
</p>

# fleet

**Let your coding agent choose which machine it runs on.**

An MCP server plus a small cross-platform daemon that give an agent CLI a
fleet of execution targets — `exec`, file ops, and process supervision that
work like the tools it already has, except they run on a machine you
designate instead of your laptop.

> [!WARNING]
> `fleet-agent` is a remote code execution service. That is its purpose,
> not a caveat. Read [docs/security.md](docs/security.md) before installing
> it anywhere.


> [!NOTE]
> _**AI;DR:**_ This software was entirely developed using LLMs. Please use 
> IP-based allow-listing to prevent unauthorized parties from gaining remote
> code execution on the machine running the sandbox agent. 

## What it is

Four binaries, one Go module:

- **`fleet-mcp`** — runs on your workstation. The MCP server your agent
  talks to. Owns the registry of known sandboxes and the current selection.
- **`fleet-agent`** — runs on every sandbox host. Listens over gRPC/mTLS,
  runs commands, and supervises background processes.
- **`fleetctl`** — runs on your workstation. Sets up the CA, mints
  enrollment tokens, inspects the fleet, and opens an interactive shell on a
  host with `fleetctl shell`.
- **`fleet-tui`** — runs on your workstation, and you never type its name.
  `fleetctl tui` hands the terminal to it. It is a separate binary so that
  `fleetctl` itself does not link a terminal UI; see [the note
  below](#why-fleet-tui-is-its-own-binary).

The agent CLI (Claude Code, Cursor, etc.) calls `fleet_select` to pick a
host, then uses the same exec/file/process tools it already knows — they
just execute wherever you pointed them.

## Install

**1. Get the workstation tools:**

```sh
go install github.com/axelmierczuk/fleet-mcp/cmd/fleet-mcp@latest
go install github.com/axelmierczuk/fleet-mcp/cmd/fleetctl@latest
go install github.com/axelmierczuk/fleet-mcp/cmd/fleet-tui@latest   # for `fleetctl tui`
```

**2. Create a CA and mint an enrollment token:**

```sh
fleetctl ca init                       # prints the CA fingerprint — keep it
fleetctl ca sign --profile control     # this workstation's own identity
fleetctl serve &                       # enrollment endpoint, :9443 — stop it after
fleetctl enroll mint --name build-box --address build-box.internal:8722
```

**3. Enroll a machine as a sandbox:**

`enroll mint` prints the command to run, with the token, control address and CA
fingerprint already filled in. Paste it on the host:

```sh
curl -fsSL https://raw.githubusercontent.com/axelmierczuk/fleet-mcp/main/install.sh \
  | sh -s -- --token sbx_ey... \
      --control your-workstation:9443 \
      --ca-fingerprint 9F:2C:8A:1E:... \
      --listen 0.0.0.0:8722
```

This detects the platform, verifies the release checksum, enrolls the host
(the private key is generated locally and never leaves the machine), and
installs a system service. Use `install.ps1` on Windows — the PowerShell form
is printed too.

Then stop `fleetctl serve`, and check the fleet:

```sh
fleetctl list          # one listing
fleetctl tui           # or watch the whole fleet, its processes and their logs
```

**4. Point your agent at the MCP server:**

```json
{
  "mcpServers": {
    "fleet": {
      "command": "fleet-mcp",
      "args": ["serve"]
    }
  }
}
```

Done. `fleet_list` should show `build-box`.

### Why `fleet-tui` is its own binary

`fleetctl tui` is one command, and it stays one command — this is only about
what gets linked into what.

The view is built on bubbletea, whose package init asks the terminal for its
background colour and reads for up to five seconds waiting for the answer. A
package init runs in every process that links the package, whatever subcommand
was typed, so linking the view into `fleetctl` made `fleetctl version` cost five
seconds on any terminal that does not answer — a bare pty, a CI log, a serial
console — and swallow whatever was typed while it waited. Nothing inside the
process can opt out; every escape hatch the library has is read during that
init, before any of our code runs.

So the view lives in `fleet-tui`, and `fleetctl tui` hands it the terminal with
its command line unchanged. There is nothing extra to configure: `fleet-tui` is
`fleetctl`'s own command tree with the view linked in, reading the same config
directory, the same CA and the same registry.

## Tools

Twenty tools across five groups — see [docs/tools.md](docs/tools.md) for
full schemas.

- **Fleet** — `fleet_list`, `fleet_select`, `fleet_add`, `fleet_remove`, `fleet_info`
- **Execute** — `fleet_exec`
- **Background processes** — `fleet_process_start`, `fleet_process_list`, `fleet_process_logs`, `fleet_process_signal`, `fleet_process_restart`
- **Files** — `fleet_read`, `fleet_write`, `fleet_edit`, `fleet_ls`, `fleet_glob`, `fleet_grep`
- **Bridge** — `fleet_transfer`, `fleet_forward`, `fleet_socks`

`fleet_select` sets a sticky default sandbox (persisted per client), and
every targeted tool can override it with an optional `sandbox` argument.
Every result echoes back which sandbox actually served it, so the agent
never silently acts on the wrong host.

## Security

- **mTLS everywhere.** No plaintext mode, not even on loopback.
- **Keys never move.** Enrollment is a CSR exchange against a single-use token.
- **No shell by default.** Commands take an argv, not a string.
- **Caps and audit.** Wall-clock timeouts, output limits, append-only JSONL
  log of every exec and write.

`fleet` does not sandbox — it's remote execution against a host you
designate. Isolation is whatever that host already provides (VM, container,
dedicated machine). Full threat model in [docs/security.md](docs/security.md).

## Development

```sh
make tools        # pinned buf, protoc plugins, golangci-lint into .tools/
make proto        # regenerate Go from proto/
make build        # every binary
make check        # the gate: proto, vet and lint per GOOS, tests under -race
make test-norace  # the unit tests without -race, as CI and the release gate run them
```

Go 1.25, [`modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk),
gRPC/protobuf, buf for proto tooling, GoReleaser for release builds.

## Status

Early. Protocol schema and build pipeline are in place; implementation is
tracked in [#29](https://github.com/axelmierczuk/fleet-mcp/issues/29).
See [docs/architecture.md](docs/architecture.md) for the full design.

## License

MIT. See [LICENSE](LICENSE).
