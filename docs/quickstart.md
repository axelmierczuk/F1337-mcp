# Quickstart

## Prerequisites

- Go 1.25+ on your workstation (until binary releases are published).
- A machine to use as a sandbox, reachable from your workstation.

Steps 2–6 below set up a fleet CA and enroll the host against it, so both ends
of every connection carry a certificate. That is worth doing when the agent's
port is reachable by anything you do not control, and it is the only part of
this document that needs the sandbox host to reach your workstation's
control-plane port.

If the network between them already authenticates its peers — a Tailscale
tailnet, a WireGuard mesh, a VPC whose security groups admit only the control
plane — skip to [On a network that already authenticates its
peers](#on-a-network-that-already-authenticates-its-peers), which is the
README's default path and needs no CA at all. Read
[security.md → Running without mTLS](security.md#running-without-mtls) first:
without mTLS the agent authenticates nobody, so the network has to.

## 1. Workstation tools

```sh
go install github.com/axelmierczuk/fleet-mcp/cmd/fleet-mcp@latest
go install github.com/axelmierczuk/fleet-mcp/cmd/fleetctl@latest
go install github.com/axelmierczuk/fleet-mcp/cmd/fleet-tui@latest
```

The third is what `fleetctl tui` draws with. Everything else works without it —
`fleetctl` looks for it next to itself, and says so if it is not there.

## 2. Create a fleet CA

```sh
fleetctl ca init
```

Writes the CA key and certificate to `~/.config/fleet/ca/`. The signing key
never leaves this directory, and no MCP tool can read it.

`ca init` prints the CA fingerprint in a box. **Keep it.** Every enrolling host
pins it, and a host enrolled without it trusts whatever answers on the network.
Read it again at any time:

```sh
fleetctl ca fingerprint
# SHA256 Fingerprint=9F:2C:8A:1E:...
```

## 3. Issue this workstation's identity

```sh
fleetctl ca sign --profile control
```

Writes `control.crt` and `control.key` beside the registry. This is the client
certificate `fleet-mcp` and `fleetctl list` present to agents; without it they
can see which hosts are enrolled but cannot talk to any of them.

## 4. Start the enrollment endpoint

```sh
fleetctl serve --listen 0.0.0.0:9443
```

**Stop it once your hosts have enrolled.** It is the only endpoint an
unauthenticated caller can reach, a fleet is enrolled in minutes and runs for
months, and an enrollment endpoint left listening is attack surface that buys
nothing for almost all of its uptime.

## 5. Mint a token

```sh
fleetctl enroll mint --name build-box --address build-box.internal:8722 \
  --control your-workstation:9443 --ttl 15m
```

Which prints the token, its id, the CA fingerprint, and the command to run on
the host — token, control address and fingerprint already filled in:

```
token:          sbx_ey...
token-id:       bac4a8a2b7e3
name:           build-box
expires:        2026-08-17T18:57:20Z (in 15m0s)
ca-fingerprint: 9F:2C:8A:1E:...

Run this on the host, as-is:

  curl -fsSL https://raw.githubusercontent.com/axelmierczuk/fleet-mcp/main/install.sh \
    | sh -s -- --token sbx_ey... \
        --control your-workstation:9443 \
        --ca-fingerprint 9F:2C:8A:1E:... \
        --listen 0.0.0.0:8722
```

Single-use and short-lived. Getting it to the host is your job — the same way
you would move any other bootstrap secret. Without `--control` the command names
this machine's hostname and says so, so pass it when the host reaches you by
some other name.

`--name` and `--address` are what the token authorizes, and the certificate the
host is issued carries exactly those. An enrolling host cannot widen either, so
give the address you will actually dial the sandbox by: without it the leaf
names only `build-box`, and a control plane connecting to
`build-box.internal:8722` will reject it.

Changed your mind, or the token did not reach the host? Withdraw it by id:

```sh
fleetctl enroll revoke bac4a8a2b7e3
fleetctl enroll list                 # outstanding tokens, with state and expiry
```

`enroll list` never shows a token's value, in any output mode. The store keeps
only a hash; the plaintext exists once, in the output above.

## 6. Install the agent

Paste the command `enroll mint` printed. Add `--root` if you want to record the
paths the agent should stay within — but read
[docs/security.md](security.md#filesystem-confinement) first, because roots are
enforced only on an agent with `exec` disabled.

Windows hosts get the PowerShell form, printed directly below the shell one.

That command names every answer the installer needs, so it asks nothing. Run
with no arguments and a terminal, it asks instead — the posture, this host's own
addresses (enumerated and labelled, tailnet first), and whether to register a
service — then writes the config, registers the service, starts it, and waits
until the agent is up before saying so. `--dry-run` prints the plan and changes
nothing; `--non-interactive` turns every unanswered question into an error
naming the flag that answers it, which is what a provisioning script wants.

Prefer not to pipe to a shell? Download the archive from the releases page,
check it against `checksums.txt`, then run `fleet-agent enroll` yourself with
the same flags.

Then stop `fleetctl serve`.

## 7. Wire up your agent CLI

Add to `mcp.json`:

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

Restart the CLI. Confirm the fleet is visible:

```sh
fleetctl list
# NAME       ADDRESS                   AUTH  PLATFORM     AGENT  HEALTH   LAST SEEN  DETAIL
# build-box  build-box.internal:8722   mtls  linux/amd64  v0.3.0 serving  2s ago
```

`list` probes every sandbox concurrently under a per-host deadline, so a
powered-off host is reported `unreachable` rather than holding up the listing.
It reads health through the same client the MCP server uses, so `fleetctl list`
and `fleet_list` cannot disagree about whether a host is up.

## 8. Use it

```
fleet_list()                                    → build-box (linux/amd64, serving)
fleet_select(name="build-box")                  → selected
fleet_exec(argv=["go","test","./..."])          → exit 0
```

## Operating the fleet

```sh
fleetctl add box --address host:8722 --insecure   # register a host that is already running an agent
fleetctl list                     # the fleet, with health
fleetctl list --json              # the same, for scripting
fleetctl info build-box           # one host in full: resources, roots, uptime
fleetctl tui                      # watch the whole fleet at once
fleetctl select build-box         # the host later commands act on
fleetctl shell                    # an interactive shell on it
fleetctl remove build-box         # deregister locally; the host is untouched
fleetctl version
```

`--json` is available on every command that reports something, and is the
supported interface for scripts — the tables are laid out for people.

`tui` is the same data as `list` and `info`, kept on screen: every sandbox and
its health, the supervised processes on the sandbox you are looking at, that
process's output as it arrives, and the host's resources and allowed roots.
Press `?` for the keys.

```
 fleetctl tui                        3 sandboxes  2 serving  1 unreachable
┌ fleet ──────────────────────────────────────────────────────────────── 1/3 ─┐
│  NAME             PLATFORM      AGENT   HEALTH      LAST SEEN               │
│● build-box        linux/amd64   v0.3.0  serving     2s ago                  │
│● gpu-01           linux/amd64   v0.3.0  serving     3s ago                  │
│● laptop           darwin/arm64  v0.3.0  unreachable 2h ago                  │
└─────────────────────────────────────────────────────────────────────────────┘
┌ processes ──────────────────────── build-box ─┐┌ detail ───── build-box ────┐
│STATE    NAME             PID    UPTIME  RST   ││sandbox   build-box         │
│ready    web-dev-server   4211   12m4s   -     ││health    serving           │
│running  queue-worker     4300   3m10s   2     ││cpu       8 cores           │
└───────────────────────────────────────────────┘└────────────────────────────┘
┌ logs ──────────────────────────────────────────────────── web-dev-server ───┐
│listening on :8080                                                           │
│E| upstream timeout after 30s                                                │
└─────────────────────────────────────────────────────────────────────────────┘
 Stop "web-dev-server" on "build-box"? SIGTERM, then SIGKILL after 10s  [y/N]
```

Two things about it are deliberate. Every action that changes a sandbox asks
first and names both the sandbox and the process, because a keystroke away from
"signal every process on prod-db" is a different risk from typing that as a
command. And health is the only thing refreshed for the whole fleet — in the
background, in parallel, under a per-sandbox deadline — while processes, logs
and host detail are fetched only for the sandbox you are looking at, so a
hundred-machine fleet costs one machine's worth of traffic beyond health.

It needs a terminal; `fleetctl list --json` is the scriptable view of the same
data. `--refresh` sets how often health is re-probed (default 10s).

`remove` is local only. The agent keeps running and keeps its certificate, so a
removed sandbox can be re-registered without re-enrolling; to actually stop it
serving, uninstall the agent on the host.

### A shell on a host

```sh
fleetctl select build-box         # once; later commands use it
fleetctl shell                    # a real terminal on build-box
fleetctl shell gpu-01             # or name a host for this session only
fleetctl shell -- /bin/zsh        # or choose the shell yourself
```

It is a full terminal: `top`, `vi` and anything that prompts for a password all
work, the window reflows when you resize yours, and Ctrl-C interrupts what is
running on the far end rather than the command carrying it. The remote shell's
exit code becomes `fleetctl`'s, so `fleetctl shell -- make test` reports the
build's own status.

It needs a terminal, and refuses without one: a session driven by a pipe would
sit at a prompt nobody can answer. To run a command from a script and collect
its output, use the `fleet_exec` tool.

A session ends when you exit it, when the connection drops, or when the agent's
`shell.idle_timeout` reaps an abandoned one. Whichever it is, the session's
whole process tree goes with it.

This is the most direct remote-code-execution surface in the product, and every
session is recorded on the host: who opened it, when, for how long, and how it
ended — never what was typed or printed. Read
[docs/security.md → The interactive shell](security.md#the-interactive-shell)
before you hand the control certificate to somebody else.

Replacing the CA without a flag day is
[docs/security.md → Rotating the CA](security.md#rotating-the-ca).

## Adding more hosts

Repeat steps 4–6. Restart `fleetctl serve` while you do; stop it again after.
`--name` distinguishes hosts; labels let the model choose by capability rather
than hostname:

```sh
fleetctl enroll mint --name gpu-01 --address gpu-01.internal:8722 \
  --label gpu=a100 --label arch=amd64
```

## On a network that already authenticates its peers

Steps 2–6 exist to give both ends of every connection an identity. On a
Tailscale tailnet, a WireGuard mesh, or a VPC whose security groups admit only
the control plane, that identity check has already been made by something that
also encrypts the traffic, and you can skip the CA entirely:

```sh
# On the host. It asks the posture, offers this host's own addresses with the
# tailnet one first, writes the config, registers the service and starts it.
curl -fsSL https://raw.githubusercontent.com/axelmierczuk/fleet-mcp/main/install.sh | sudo sh
```

Or say it outright, which is the same install with nothing to answer:

```sh
curl -fsSL https://raw.githubusercontent.com/axelmierczuk/fleet-mcp/main/install.sh \
  | sudo sh -s -- --no-mtls --listen 100.83.4.17:8722 --name tailnet-box
```

Either way what lands on the host is an `agent.yaml` with no certificates in it:

```yaml
name: "tailnet-box"
listen: "100.83.4.17:8722"   # this host's tailnet address, not 0.0.0.0
tls:
  enabled: false
```

By hand instead — the same file, written at
`/etc/fleet/agent.yaml`, `/Library/Application Support/fleet/agent.yaml` or
`%ProgramData%\fleet\agent.yaml` — then:

```sh
sudo fleet-agent service install    # creates the state and log directories
sudo fleet-agent service start
```

`serve` reads the same config if you would rather run it in the foreground, but
it writes to the system state directory (`/var/lib/fleet`, or
`/Library/Application Support/fleet/state` on macOS), so it wants the same
privileges `service install` does.

Then register it from the workstation:

```sh
fleetctl add tailnet-box --address 100.83.4.17:8722 --insecure
```

It appears in `fleetctl list` as `auth none`. `add` contacts the host first and
refuses a posture the host contradicts in either direction — an agent serving
plaintext registered as authenticated would report `auth mtls` for a connection
nothing authenticates, and an enrolled one registered `--insecure` would fail
every call. An address nothing answers at is refused too; `--no-probe` registers
a host that is not up yet. `fleet_add(name="tailnet-box",
address="100.83.4.17:8722", insecure=true)` is the same registration for a model
that discovers the host. To write it by hand instead, add the sandbox to
`~/.config/fleet/registry.yaml`:

```yaml
version: 1
sandboxes:
  - name: tailnet-box
    address: 100.83.4.17:8722
    insecure: true
    enrolled_at: 2026-08-18T00:00:00Z
```

**Read [docs/security.md → Running without mTLS](security.md#running-without-mtls)
before you do this.** With mTLS off the agent authenticates nobody: anyone who
can reach the port can run commands on that host. The agent refuses to serve on
an address that is neither loopback nor private for exactly that reason, so
`listen: 0.0.0.0:8722` will not start — name the interface you mean.

## Upgrading from sandboxd

The project was called `sandboxd` before it was called `fleet`. If you enrolled
hosts under the old name, nothing is lost and nothing has to be done urgently —
but the names moved, and it is worth moving your state to match.

**Nothing breaks if you do nothing.** Both binaries read the old locations when
the new ones are absent: `SANDBOXD_CONFIG_DIR` is still honoured when
`FLEET_CONFIG_DIR` is unset, and a populated `~/.config/sandboxd` is used when
`~/.config/fleet` does not exist. You get one warning per process saying which
old name is in use and what to do about it. The old names will be removed
eventually, so treat the warning as a deadline you set yourself.

Migrating is a move, done while nothing is running. It is not done for you: the
directory holds private keys, and a daemon that quietly relocated them on first
start would be doing something you did not ask for and could not undo.

On your workstation, with `fleet-mcp` and `fleetctl serve` stopped:

```sh
mv ~/.config/sandboxd ~/.config/fleet
```

If you set the environment variable anywhere — a shell profile, an `mcp.json`
`env` block, a CI secret — rename it too:

```diff
-  "SANDBOXD_CONFIG_DIR": "${HOME}/.config/sandboxd"
+  "FLEET_CONFIG_DIR": "${HOME}/.config/fleet"
```

On each enrolled host, first stop and remove the old service. It is registered
as `sandboxd-agent`, and the `service` subcommands only know the new name — so
`fleet-agent service stop` will report it as not installed while it is running
fine, and `fleet-agent service install` would register a *second* service beside
it. Use the platform's own tools and the old name; the exact commands for all
three platforms are in
[service.md → A service installed before the fleet rebrand](service.md#a-service-installed-before-the-fleet-rebrand):

```sh
sudo systemctl disable --now sandboxd-agent
sudo rm /etc/systemd/system/sandboxd-agent.service && sudo systemctl daemon-reload
```

Then move the directories:

```sh
sudo mv /etc/sandboxd     /etc/fleet       # config, certificate, key, CA bundle
sudo mv /var/lib/sandboxd /var/lib/fleet   # supervised process state
sudo mv /var/log/sandboxd /var/log/fleet   # audit log
```

macOS uses `/Library/Application Support/sandboxd` and `/Library/Logs/sandboxd`;
Windows uses `%ProgramData%\sandboxd`. Move each to its `fleet` equivalent.

The agent's config names these paths explicitly, so edit `/etc/fleet/agent.yaml`
after the move and update `tls.certificate`, `tls.private_key`, `tls.ca_bundle`,
`audit.path` and `state_dir`. Then register the service under the new name and
start it:

```sh
sudo fleet-agent service install
sudo fleet-agent service start
```

On Linux the new unit will say `User=sandboxd`, and that is deliberate: the
`sandboxd` system account still exists, still owns the directories you just
moved, and `mv` did not change that. `install` keeps it rather than creating a
second system account and chowning your state away from the one using it. If you
would rather run under a `fleet` account, create it and pass `--user fleet` —
`install` chowns the state and log directories to whatever account you name. See
[service.md → The service account](service.md#the-service-account).

**Do not create the new directory before you are ready to move.** An empty
`~/.config/fleet` next to a populated `~/.config/sandboxd` is the one case worth
avoiding — though even then the resolver treats an empty directory as absent and
keeps using the populated one, precisely so a stray `mkdir` cannot make a fleet
look like it vanished.

Two things deliberately keep the old name, and you should not change them:

- **`require_client_ou: "sandboxd-control"`** in every agent config. This is
  stamped into every certificate your CA has issued and is checked at every
  connection. Changing it means re-enrolling every host on the same day.
- **The `sandboxd.v1` gRPC package.** It is internal to the wire protocol and
  never appears in anything you configure.

You do not need to re-enroll, re-issue certificates, or re-create your CA.

## Troubleshooting

**Agent does not appear in `fleet_list`.**
Check the service is running (`fleet-agent service status`), and that your
workstation can reach its listen address.

**`certificate signed by unknown authority`.**
The agent was enrolled against a different CA. Re-enroll with a fresh token.

**`path escapes allowed roots`.**
The path resolved — after following symlinks — to somewhere outside the roots
given at install time. Check `fleet_info` for the roots actually in force.
Only an agent with `exec.enabled: false` produces this error at all; with exec
on there is no jail to escape.

**Enrollment fails with `enrollment token rejected`.**
The token was unrecognized, expired, revoked, or already redeemed — the control
plane reports all four identically to an unauthenticated caller, and names which
one in its own log. Mint another. This message is about the token and only the
token: a request refused for anything else — a `--name` the token does not
reserve, an `--address` it does not authorize — says so, and leaves the token
spendable, so the corrected command works without a re-mint.
