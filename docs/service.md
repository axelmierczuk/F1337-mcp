# Running the agent as a service

`fleet-agent service install` registers the daemon with the platform's
service manager so it starts at boot. It needs elevation, and it refuses
early — before creating a user or a directory — when it does not have it.

```sh
sudo fleet-agent service install          # systemd, launchd, or the Windows SCM
sudo fleet-agent service start
fleet-agent service status
```

`install` bakes the config path into the service definition, so the daemon does
not have to rediscover it as whichever account it ends up running as.

## The service account

**The agent does not run as root by default, and you should not make it.** The
agent executes arbitrary commands on behalf of a remote caller. Whatever
account it runs as is the account every one of those commands runs as, and
every file they write is owned by. Running as root means handing root to the
model.

| Platform | Default account | Created by install? |
| --- | --- | --- |
| Linux | `fleet`, a system account | Yes, via `useradd` or `adduser` |
| macOS | The invoking user (`$SUDO_USER`) | No — pass `--user` for a different one |
| Windows | `NT AUTHORITY\NetworkService` | n/a, it is a built-in identity |

`--user` overrides the default everywhere. `--create-user=false` turns off
account creation, so an install against a missing account fails with a message
naming it rather than inventing one.

The defaults differ because the right answer differs. On Linux a system daemon
conventionally gets a dedicated system account and `useradd` makes creating one
a single command. On macOS creating a system account means a sequence of `dscl`
calls and a hand-picked UID, and the account that already has the toolchains,
the caches, and a home directory the agent can build in is the one the operator
is sitting in front of. On Windows, `NetworkService` is a standing
non-administrative identity — unlike `LocalSystem`, which is what the SCM would
pick on its own and is the Windows equivalent of root.

`--user root` (or `--user LocalSystem`) works. It prints a warning naming the
consequence, and does what you asked.

**Whatever account you choose must be able to read and write the allowed
roots.** On Linux and macOS that is ordinary ownership. On Windows it is ACLs,
and `install` does not set them: grant the service account access to the roots
yourself.

### The enrollment material changes hands

`enroll` writes `agent.yaml` and the private key at `0600`, into a `0700`
directory when it runs elevated, owned by whoever ran it. `install` is the step
that decides the daemon will run as somebody else — so on Linux and macOS it
hands that account the config, certificate, key, and CA bundle, and the
directory holding them.

The directory only changes hands when it is one `enroll` created (`/etc/fleet`,
`/Library/Application Support/fleet`, or the per-user enrollment directory).
Point `--config` somewhere else and `install` gives away the four files but
leaves the directory alone, and says so: `--config /etc/agent.yaml` must not
turn into `chown fleet /etc`. Make that directory traversable by the service
account yourself.

On Windows nothing is chowned: access there is by ACL, and `%ProgramData%\fleet`
already admits the built-in service identities.

## Hardening

`--hardening` selects how much the service manager is asked to constrain the
daemon:

- `standard` (default) — `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=full`.
- `strict` — `ProtectSystem=strict` with the allowed roots, the state directory,
  and the log directory as `ReadWritePaths`. The roots carry systemd's `-`
  prefix, so a root you have not created yet is skipped rather than failing the
  unit's mount namespace and with it the whole service.
- `none` — no confinement directives.

This is deliberately conservative. The agent's job is running arbitrary
commands and writing files under its roots, so a directive that is obviously
correct on a daemon serving HTTP breaks this one:

- **`ProtectHome` is never set.** Every developer toolchain caches in the
  service user's home directory — `~/.cache/go-build`, `~/.npm`, `~/.cargo` —
  and making it inaccessible breaks `go build` long before it inconveniences an
  attacker.
- **`PrivateTmp` is skipped when an allowed root lives under `/tmp` or
  `/var/tmp`**, as it does in `examples/agent.yaml`. A private `/tmp` would
  make everything the agent wrote there invisible to the rest of the host and
  lose it on restart. Silently breaking a configured root is worse than
  skipping one directive, so the rendered unit says why it was omitted.
- **`ProtectSystem=strict` is opt-in.** It is the right shape, but a toolchain
  that writes anywhere outside the roots stops working under it. Use it when
  you know what your builds touch. It is also the only filesystem boundary that
  survives an exec-enabled agent: the agent's own path jail is off in that
  configuration (see [security.md](security.md#filesystem-confinement)), and a
  kernel-enforced `ReadWritePaths` is not something a `sh -c` can talk its way
  past.
- **`PrivateDevices`, `RestrictAddressFamilies`, and `SystemCallFilter` are not
  set at any level.** The agent runs arbitrary programs; each of those turns an
  ordinary build failure into an unexplainable one.

`NoNewPrivileges` blocks setuid escalation from inside a sandbox command, which
means `sudo` does not work under the agent. That is the intent.

## What is not hardening: `KillMode=process`

The systemd unit sets `KillMode=process` and the launchd job sets
`AbandonProcessGroup`. Neither is optional.

systemd's default `KillMode=control-group` sends `SIGTERM` to every process in
the unit's cgroup when the service stops — which is every background process
the agent supervises. launchd does the equivalent to the job's process group.
Without these, `systemctl restart fleet-agent` kills every dev server that
agent is running, and an agent upgrade does it across the entire fleet at once.

Supervised processes belong to the host, not to the daemon that started them.
The daemon never signals one, and the service definition must not either.

`TimeoutStopSec` is set above the daemon's own drain deadline, so the service
manager does not `SIGKILL` the daemon partway through the drain it was just
asked to perform.

## Uninstall keeps your identity

```sh
sudo fleet-agent service uninstall
```

removes the unit, job, or service registration and **leaves**:

- `agent.yaml`, and the certificate, private key, and CA bundle beside it
- the state directory (`state_dir`), holding supervised process records

Re-installing therefore rejoins the fleet without minting and redeeming a new
enrollment token. To leave a fleet properly, remove the enrollment directory by
hand after uninstalling.

Installing twice is idempotent: the second `install` replaces the definition
rather than failing, and restarts the service if it was running. That is what
lets an installer script be re-run safely and what lets you change `--user` or
`--hardening` without uninstalling first.

## Manual verification

CI cannot install services — it does not run as root, and a GitHub runner has
no launchd session or Windows SCM to register against. Everything that decides
*what* gets installed is unit-tested (`unit_test.go` covers the rendered systemd
unit, the launchd plist, and the Windows SCM options), but the install itself
has to be checked by hand.

### Linux, systemd

```sh
sudo fleet-agent service install
sudo fleet-agent service start
fleet-agent service status                 # installed, running, with a PID
systemctl show -p KillMode --value fleet-agent.service   # must print: process
journalctl -u fleet-agent -n 20            # structured slog output

# Supervised processes survive a restart of the daemon:
#   start a background process through the MCP server, note its PID,
sudo systemctl restart fleet-agent
#   then confirm that PID is still alive.

sudo systemctl reboot                          # comes back after a reboot
fleet-agent service status

sudo fleet-agent service install            # idempotent: reinstalls, no error
sudo fleet-agent service uninstall
ls /etc/fleet /var/lib/fleet             # credentials and state still there
```

### macOS, launchd

```sh
sudo fleet-agent service install --user "$(whoami)"
sudo fleet-agent service start
fleet-agent service status
sudo launchctl list fleet-agent             # PID, and AbandonProcessGroup in the job
tail -f /Library/Logs/fleet/fleet-agent.err.log

sudo shutdown -r now                           # survives a reboot
sudo fleet-agent service uninstall
```

### Windows

From an elevated PowerShell:

```powershell
fleet-agent service install
fleet-agent service start
fleet-agent service status
Get-Service fleet-agent                     # Running, StartType Automatic
sc.exe qfailure fleet-agent                 # restart action, 5s delay
Get-EventLog -LogName Application -Source fleet-agent -Newest 20

Restart-Computer                               # survives a reboot
fleet-agent service uninstall
```
