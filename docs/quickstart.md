# Quickstart

## Prerequisites

- Go 1.25+ on your workstation (until binary releases are published).
- A machine to use as a sandbox, reachable from your workstation.
- The sandbox host must be able to reach your workstation's control-plane port
  once, during enrollment.

## 1. Workstation tools

```sh
go install github.com/axelmierczuk/fleet-mcp/cmd/sandboxd-mcp@latest
go install github.com/axelmierczuk/fleet-mcp/cmd/sandboxctl@latest
```

## 2. Create a fleet CA

```sh
sandboxctl ca init
```

Writes the CA key and certificate to `~/.config/sandboxd/ca/`. The signing key
never leaves this directory, and no MCP tool can read it.

Print the fingerprint to pin during enrollment:

```sh
sandboxctl ca fingerprint
# 9f2c8a1e...
```

## 3. Start the enrollment endpoint

```sh
sandboxctl serve --listen 0.0.0.0:9443
```

Only needed while enrolling hosts. Stop it afterwards.

## 4. Mint a token

```sh
sandboxctl enroll mint --name build-box --address build-box.internal:8722 --ttl 15m
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
check it against `checksums.txt`, then run `sandboxd-agent enroll` yourself with
the same flags.

## 6. Wire up your agent CLI

Add to `mcp.json`:

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

Restart the CLI. Confirm the fleet is visible:

```sh
sandboxctl list
```

## 7. Use it

```
sandbox_list()                                    → build-box (linux/amd64, serving)
sandbox_select(name="build-box")                  → selected
sandbox_exec(argv=["go","test","./..."])          → exit 0
```

## Adding more hosts

Repeat steps 4 and 5. `--name` distinguishes them; labels let the model choose
by capability rather than hostname:

```sh
sandboxctl enroll mint --name gpu-01 --address gpu-01.internal:8722 \
  --label gpu=a100 --label arch=amd64
```

## Troubleshooting

**Agent does not appear in `sandbox_list`.**
Check the service is running (`sandboxd-agent service status`), and that your
workstation can reach its listen address.

**`certificate signed by unknown authority`.**
The agent was enrolled against a different CA. Re-enroll with a fresh token.

**`path escapes allowed roots`.**
The path resolved — after following symlinks — to somewhere outside the roots
given at install time. Check `sandbox_info` for the roots actually in force.
Only an agent with `exec.enabled: false` produces this error at all; with exec
on there is no jail to escape.

**Enrollment fails with `token expired or already used`.**
Tokens are single-use. Mint another.
