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
- **`fleet-agent`** — runs on every sandbox host. Listens over gRPC,
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

**2. Put the agent on the sandbox host, and give it a config:**

```sh
curl -fsSL https://raw.githubusercontent.com/axelmierczuk/fleet-mcp/main/install.sh | sh
```

That downloads the release binary for the platform, checks it against the
published checksum, and installs it. Nothing else — no CA, no certificate, no
service. Windows uses `install.ps1` the same way.

```sh
sudo tee /etc/fleet/agent.yaml >/dev/null <<'YAML'
name: "build-box"
listen: "100.83.4.17:8722"    # this host's own address on your private network
tls:
  enabled: false
YAML
```

That path is Linux's. macOS reads `/Library/Application Support/fleet/agent.yaml`
and Windows `%ProgramData%\fleet\agent.yaml`; everything else is the same.

**Name the interface you mean.** With `tls.enabled: false` the agent refuses to
serve on an address that is neither loopback nor private, because on any other
address there would be nothing between the port and a shell on the host.
Loopback, RFC 1918, unique-local, link-local and CGNAT space — `100.64.0.0/10`,
where every Tailscale node lives — are permitted. A wildcard bind, a public
address, and a hostname it would have to resolve are refused. `serve
--allow-unauthenticated-public` is the only way past that, and the default
`listen` is `0.0.0.0:8722`, so a config that omits the line does not start.

Leaving `tls.enabled` out is not the same as writing `false`. Unset means "on if
this config names a certificate", so a host that enrolled keeps authenticating
across an upgrade, and one written like the above never starts asking for a CA.

**3. Start it:**

```sh
sudo fleet-agent service install
sudo fleet-agent service start
```

On Windows that registers a logon-triggered Scheduled Task in your own session
rather than a Windows service. A service runs in session 0 with no operator
profile, so it sees none of nvm, rustup, pyenv, cargo, scoop or npm globals —
most of `PATH` on a developer machine, and an agent whose job is running the
commands you would type cannot run them. The task stops when you log off;
`--mechanism service --user <account>` is the answer for a machine nobody signs
into. See [docs/service.md](docs/service.md).

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

**5. Register the sandbox.** There is no CA, so there is no enrollment: nothing
is issued and nothing is proved. What is left is giving the host a name, which
your agent does with one tool call:

```
fleet_add(name="build-box", address="100.83.4.17:8722", insecure=true)
```

`insecure` has to be said because it cannot be discovered — an agent serving
plaintext and one refusing a handshake look identical to a dialer that has not
been told. Get it wrong and the connection fails; it never quietly downgrades.
The call writes an entry to `~/.config/fleet/registry.yaml`, which you can write
yourself instead:

```yaml
version: 1
sandboxes:
  - name: build-box
    address: 100.83.4.17:8722
    insecure: true
    enrolled_at: 2026-08-18T00:00:00Z
```

That entry is a name this workstation assigned to an address, and the host never
proves it. If something else answers there, the fleet will call it `build-box`
and record its commands under that name. On a network that decides who can
answer, that is the whole of what a name means.

```sh
fleetctl list          # AUTH reads none, and a line under the table says what that means
fleetctl tui           # or watch the whole fleet, its processes and their logs
```

Done. `fleet_list` should show `build-box`.

### What the default assumes

Without mTLS the agent's authentication is whatever the network provides, and
nothing else. It runs arbitrary commands on its host by design, so on a port
something unauthorized can reach, that is unauthenticated remote code execution
— and the failure is silent, because an agent that skipped the CA works
immediately and looks exactly like a secured one. The precondition is that **the
network authenticates its peers**: a tailnet, a WireGuard mesh, a VPC whose
security groups admit only the control plane. On those, the identity check has
already been made by something that also encrypts the traffic, and a second
identity system buys nothing. If that is not true of your network, use mTLS.
[docs/security.md → Running without mTLS](docs/security.md#running-without-mtls)
is the full account.

<details>
<summary><strong>Setting up mTLS instead</strong></summary>

Both ends present certificates issued by a CA you run, and the handshake — not
the network — is the boundary. On your workstation:

```sh
fleetctl ca init                       # prints the CA fingerprint — keep it
fleetctl ca sign --profile control     # this workstation's own identity
fleetctl serve &                       # enrollment endpoint, :9443 — stop it after
fleetctl enroll mint --name build-box --address build-box.internal:8722
```

`enroll mint` prints the command to run on the host, with the token, control
address and CA fingerprint already filled in. Paste it there:

```sh
curl -fsSL https://raw.githubusercontent.com/axelmierczuk/fleet-mcp/main/install.sh \
  | sh -s -- --token sbx_ey... \
      --control your-workstation:9443 \
      --ca-fingerprint 9F:2C:8A:1E:... \
      --listen 0.0.0.0:8722
```

It verifies the release checksum, enrolls the host — the private key is
generated there and never leaves it — writes `tls.enabled: true` into the
config, and registers a system service when run as root. Windows gets the
PowerShell form, printed alongside.

Enrollment registers the sandbox for you, so there is no `fleet_add` step, and
`0.0.0.0` is an ordinary listen address here: the listen guard applies only when
the agent authenticates nobody.

Then stop `fleetctl serve`, and check the fleet:

```sh
fleetctl list          # AUTH reads mtls
```

The long form, including rotating the CA and adding more hosts, is
[docs/quickstart.md](docs/quickstart.md).

</details>

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

- **Transport authentication is a decision you make.** `fleet-agent enroll`
  writes `tls.enabled: true`, and both ends then present certificates from the
  fleet CA. A config with no certificates in it serves plaintext instead, for a
  network that already authenticates its peers — and then the agent refuses any
  address that is neither loopback nor private, says so at every start, shows as
  `auth none` in `fleetctl list`, and records every command against the address
  it came from rather than a verified identity.
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
