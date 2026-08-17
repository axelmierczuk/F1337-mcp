# Quickstart

## Prerequisites

- Go 1.25+ on your workstation (until binary releases are published).
- A machine to use as a sandbox, reachable from your workstation.
- The sandbox host must be able to reach your workstation's control-plane port
  once, during enrollment.

## 1. Workstation tools

```sh
go install github.com/axelmierczuk/fleet-mcp/cmd/fleet-mcp@latest
go install github.com/axelmierczuk/fleet-mcp/cmd/fleetctl@latest
```

## 2. Create a fleet CA

```sh
fleetctl ca init
```

Writes the CA key and certificate to `~/.config/fleet/ca/`. The signing key
never leaves this directory, and no MCP tool can read it.

Print the fingerprint to pin during enrollment:

```sh
fleetctl ca fingerprint
# 9f2c8a1e...
```

## 3. Start the enrollment endpoint

```sh
fleetctl serve --listen 0.0.0.0:9443
```

Only needed while enrolling hosts. Stop it afterwards.

## 4. Mint a token

```sh
fleetctl enroll mint --name build-box --address build-box.internal:8722 --ttl 15m
# token: sbx_ey...
```

Single-use and short-lived. Getting it to the host is your job — the same way
you would move any other bootstrap secret.

`--name` and `--address` are what the token authorizes, and the certificate the
host is issued carries exactly those. An enrolling host cannot widen either, so
give the address you will actually dial the sandbox by: without it the leaf
names only `build-box`, and a control plane connecting to
`build-box.internal:8722` will reject it.

## 5. Install the agent

On the sandbox host:

```sh
curl -fsSL https://raw.githubusercontent.com/axelmierczuk/fleet-mcp/main/install.sh \
  | sh -s -- --token sbx_ey... \
             --control your-workstation:9443 \
             --ca-fingerprint 9f2c8a1e... \
             --root /home/build/workspace
```

Windows, in an elevated PowerShell:

```powershell
$s = irm https://raw.githubusercontent.com/axelmierczuk/fleet-mcp/main/install.ps1
& ([scriptblock]::Create($s)) -Token sbx_ey... `
    -Control your-workstation:9443 `
    -CaFingerprint 9f2c8a1e... `
    -Root C:\workspace
```

Prefer not to pipe to a shell? Download the archive from the releases page,
check it against `checksums.txt`, then run `fleet-agent enroll` yourself with
the same flags.

## 6. Wire up your agent CLI

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
```

## 7. Use it

```
fleet_list()                                    → build-box (linux/amd64, serving)
fleet_select(name="build-box")                  → selected
fleet_exec(argv=["go","test","./..."])          → exit 0
```

## Adding more hosts

Repeat steps 4 and 5. `--name` distinguishes them; labels let the model choose
by capability rather than hostname:

```sh
fleetctl enroll mint --name gpu-01 --address gpu-01.internal:8722 \
  --label gpu=a100 --label arch=amd64
```

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

**Enrollment fails with `token expired or already used`.**
Tokens are single-use. Mint another.
