# Running the agent as a service

`fleet-agent service install` registers the daemon with the platform's
service manager so it starts at boot. It needs elevation, and it refuses
early — before creating a user or a directory — when it does not have it.

```sh
sudo fleet-agent service install          # systemd, launchd, or Windows
sudo fleet-agent service start
fleet-agent service status
```

`install` bakes the config path into the service definition, so the daemon does
not have to rediscover it as whichever account it ends up running as.

`fleet-agent service install --dry-run` resolves everything and registers
nothing. It needs no elevation and changes no file, and it is the way to see
which mechanism a host will get, under which account, and whether the binary is
somewhere that account can read — before running the command that acts on it.

## Windows has two mechanisms, and the difference decides whether it works

**Every Windows service runs in session 0**, which has been isolated from every
interactive session since Vista. Under a built-in service identity it has no
operator profile at all, so it sees none of nvm, rustup, pyenv, cargo, scoop,
npm globals, or the credentials in `%APPDATA%` that git and the package
registries read. On a developer machine that is most of `PATH`, and an agent
whose entire purpose is running the commands the operator would type cannot run
them. That was the default until #74; it is not any more.

| `--mechanism` | What it registers | Runs as | Sees the operator's toolchains |
| --- | --- | --- | --- |
| `task` (Windows default) | A logon-triggered Scheduled Task | The invoking user, in their own session | Yes |
| `service` | A Windows service, through the SCM | `--user`, in session 0 | Only if the SCM loaded that account's profile |
| `service --user 'NT AUTHORITY\NetworkService'` | A Windows service | A built-in identity, in session 0 | No, by construction |

`auto` — the default — picks `task`, unless `--user` names a built-in service
identity, which is a deliberate ask for a confined agent and can only be a
service. `--mechanism task` with a built-in identity is refused rather than
registered: a logon trigger fires when an account logs on interactively, and
those accounts never do.

### The Scheduled Task

```powershell
fleet-agent service install                 # elevated; runs as you, in your session
fleet-agent service start
```

No password, no session-0 isolation, the full profile and `PATH`. The rendered
definition sets `InteractiveToken`, `LeastPrivilege` (your ordinary token, not
your elevated one), `ExecutionTimeLimit` `PT0S` so the three-day default does
not kill it, and turns off the battery settings that otherwise refuse to start a
task on a laptop and stop it when the laptop unplugs.

Two things it costs, both said by `install` at the moment you get them:

- **It stops at logout.** A logon trigger runs the task while that account is
  logged on. For a machine nobody signs into, use `--mechanism service` with a
  `--user`.
- **`service stop` takes the supervised processes with it.** Task Scheduler ends
  a task by terminating what the task started. That is the opposite of what
  `KillMode=process` and `AbandonProcessGroup` buy on the other two platforms,
  and Windows offers no setting for it.

### The service, under a named account

```powershell
fleet-agent service install --mechanism service --user 'WORKSTATION\build'
# prompts for the password; --password-stdin reads it from a pipe instead
```

The SCM logs the account on to start the service, so it needs credentials. The
password is read once, handed to `CreateService`, and stored by the SCM as a
machine-bound LSA secret. Nothing here writes it to a file, an environment
variable, or a log line, and nothing can read it back off the machine it was
stored on.

The account is still in session 0. Whether it sees its own per-user toolchains
depends on whether its profile is loaded, which the SCM does not guarantee —
so `service status` checks rather than assumes. See
[When the agent is running and cannot work](#when-the-agent-is-running-and-cannot-work).

## The service account

**The agent does not run as root by default, and you should not make it.** The
agent executes arbitrary commands on behalf of a remote caller. Whatever
account it runs as is the account every one of those commands runs as, and
every file they write is owned by. Running as root means handing root to the
model.

| Platform | Default account | Created by install? |
| --- | --- | --- |
| Linux | `fleet`, a system account (but see the pre-rebrand rule below) | Yes, via `useradd` or `adduser` |
| macOS | The invoking user (`$SUDO_USER`) | No — pass `--user` for a different one |
| Windows | The invoking user, in a logon-triggered Scheduled Task | No — pass `--user` for a different one |

`--user` overrides the default everywhere. `--create-user=false` turns off
account creation, so an install against a missing account fails with a message
naming it rather than inventing one.

**On a host installed before the fleet rebrand, the Linux default is `sandboxd`,
not `fleet`.** That account already exists there and already owns the state and
log directories, and the daemon is already running as it. Defaulting to the new
name would create a second system account on every upgraded host and chown those
directories away from the account using them, so `install` keeps the one that is
there: it uses `fleet` unless `fleet` is absent and `sandboxd` is present. Once
both exist — because you created `fleet` deliberately — `fleet` wins, and the
leftover `sandboxd` account is yours to remove. `--user` overrides this like any
other default. It is the same rule the config directories follow; see
[quickstart.md](quickstart.md#upgrading-from-sandboxd).

The defaults differ because the right answer differs. On Linux a system daemon
conventionally gets a dedicated system account and `useradd` makes creating one
a single command. On macOS creating a system account means a sequence of `dscl`
calls and a hand-picked UID, and the account that already has the toolchains,
the caches, and a home directory the agent can build in is the one the operator
is sitting in front of. On Windows the same reasoning applies, and until #74 it
had simply never been applied: the account with the toolchains is the
operator's, and the only way to run as it is a task in their session. `NT AUTHORITY\NetworkService`
is still available — it is a standing non-administrative identity, unlike
`LocalSystem`, which is what the SCM would pick on its own and is the Windows
equivalent of root — and it is now something you choose rather than something
you get by not choosing.

`--user root` (or `--user LocalSystem`) works. It prints a warning naming the
consequence, and does what you asked.

**Whatever account you choose must be able to read and write the allowed
roots.** On Linux and macOS that is ordinary ownership. On Windows it is ACLs,
and `install` sets them for its own directories only — the state directory, the
log directory and the enrollment material, via `icacls`. Grant the account
access to the allowed roots yourself.

### install refuses a binary the account cannot read

`install` registers the binary where it is; it does not copy it. A manual
download lands on the Desktop, which is inside a profile directory whose ACL
admits its owner, `SYSTEM` and the administrators and nobody else — so
registering a service there under a built-in identity used to produce a service
that installed cleanly and then failed every start with **error 5, access
denied**, before a line of agent code ran.

`install` knows the path it is about to register and the account it is about to
register it for, so it refuses, names both, and prints the copy that fixes it.
Installing from your own Desktop to run as yourself — which is what the Windows
default now is — is fine and is not refused. On Linux and macOS the same check
runs against the mode bits and **warns** rather than refusing, because a
supplementary group can grant what the bits appear to deny.

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

On Windows nothing is chowned — access there is by ACL — but the same handover
happens through `icacls`: the enrollment material is granted read to the account
the daemon will run as, and the state and log directories are granted modify,
inheritable. `%ProgramData%\fleet` already admits the built-in service
identities, and admits nothing else: the directories are created by an elevated
install, so their contents belong to the administrators and an ordinary
operator token cannot write them without this step. The old default needed
none of it; the new one does.

## When the agent is running and cannot work

An agent confined out of doing its job is up, answers health checks, and fails
every command a model gives it. Nothing about the process looks wrong, so
`service status` used to report it as `running` and the operator found out one
failed command at a time.

It now reports:

```
service fleet-agent: running, but unusable
mechanism:  Windows service
platform:   windows-service
pid:        4242
runs as:    NT AUTHORITY\NetworkService
home:       C:\Windows\ServiceProfiles\NetworkService
per-user toolchains: unknown (none installed under the home directory it was started with)

UNUSABLE
  This agent is running in session 0 as NT AUTHORITY\NetworkService.
  ...
```

and **exits non-zero**. "Not installed" is the answer to a question and still
exits zero; an agent that is registered, running, and cannot execute anything
the operator has installed is a fault, and a script that branches on this
command should not read it as success.

### Where the answer comes from

`service status` runs as the operator, in the operator's session. Everything
that decides whether the daemon can work — which session it landed in, the home
directory it was given, whether the `PATH` a spawned command gets reaches
anything installed per-user — is observable only from inside the daemon. So the
daemon writes it down.

At every start, `serve` records `state_dir/runtime.json`: its pid and start
identity, the account the platform says it is running as, the home directory it
was started with, whether it is in session 0, and the result of a probe. The
probe looks on disk for the directories a toolchain installs into when it is
installed for one user — `.cargo\bin`, `AppData\Roaming\npm`, `scoop\shims`,
`.local/bin` and the rest — and then asks whether the `PATH` the exec service
hands every command reaches them. Where it does, it resolves one program it
recognises **by name off that PATH**, checks that what it resolved is the copy
under the home directory, and runs it. "`PATH` is not empty" proves nothing: a
session-0 service has a `PATH`, it is the machine's, and that is exactly the
failure.

Three answers, and the third is not a failure:

- **visible** — a per-user directory is on that `PATH`, and a program in it was
  found by name and ran.
- **hidden** — per-user toolchains are installed and `PATH` reaches none of the
  directories holding them. The report names them.
- **unknown** — nothing is installed per-user, so there is nothing to conclude.
  A freshly imaged machine is not a broken one.

`status` reads the file back and refuses it unless the process that wrote it is
still the process running — same pid *and* same start identity, so a reused pid
cannot answer for a daemon that is gone.

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

## A service installed before the fleet rebrand

The service used to register as `sandboxd-agent`. It now registers as
`fleet-agent`, and **the `service` subcommands only know the new name.** On a
host where the old service is still installed, that means:

- `fleet-agent service status` reports it as not installed, while the old
  service is running perfectly well beside it.
- `fleet-agent service uninstall` will not remove it.
- `fleet-agent service install` registers a *second* service pointing at the
  same config and state. Both would start at boot and fight over the same
  supervised processes.

`install`, `uninstall` and `status` each check for the old registration and say
so before doing any of that — `install` before it creates, chowns or registers
anything, so you can stop there having changed nothing. The check is a warning,
not a refusal: removing a service is not something the agent should do to your
host on its own.

So remove the old one first, using the old name, with the platform's own tools:

```sh
# Linux
sudo systemctl disable --now sandboxd-agent
sudo rm /etc/systemd/system/sandboxd-agent.service && sudo systemctl daemon-reload

# macOS
sudo launchctl bootout system /Library/LaunchDaemons/sandboxd-agent.plist
sudo rm /Library/LaunchDaemons/sandboxd-agent.plist

# Windows, elevated
sc.exe stop sandboxd-agent
sc.exe delete sandboxd-agent
```

Then `sudo fleet-agent service install`. Your enrollment is untouched by any of
this — the identity lives in the config directory, not in the service
registration. See the migration steps in
[quickstart.md](quickstart.md#upgrading-from-sandboxd), which also move the
directories the unit points at.

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

Everything that decides *what* gets registered is unit-tested on every runner —
the rendered Scheduled Task XML, the mechanism rule, the session-0 rule, the
executable-access refusal, and the probe that decides `visible`/`hidden`. What
cannot be tested anywhere is the registration itself and the session the daemon
lands in. From an elevated PowerShell:

```powershell
fleet-agent service install --dry-run       # changes nothing; says which mechanism

# The default: a task in your own session.
fleet-agent service install
fleet-agent service start
fleet-agent service status                  # running; per-user toolchains: visible (ran ...)
Get-ScheduledTask fleet-agent | Format-List TaskName, State
Get-ScheduledTaskInfo fleet-agent

# The claim, checked from outside the agent: the daemon is in your session,
# not in session 0.
Get-Process fleet-agent | Select-Object Id, SessionId    # SessionId must not be 0

# The other half: a per-user toolchain resolves through the agent. Run a
# command through the MCP server that only a per-user install can answer, e.g.
#   cargo --version, or `where.exe cargo`
# and confirm the path it reports is under your profile.

fleet-agent service uninstall

# Now the confined shape, deliberately, to see it reported:
fleet-agent service install --mechanism service --user "NT AUTHORITY\NetworkService"
fleet-agent service start
fleet-agent service status                  # MUST print "running, but unusable"; exits 1
Get-Service fleet-agent                     # Running, StartType Automatic
sc.exe qfailure fleet-agent                 # restart action, 5s delay
fleet-agent service uninstall

# And a service under a named account, which is the headless answer:
fleet-agent service install --mechanism service --user "$env:COMPUTERNAME\build"
#   prompts for the password; the SCM stores it as an LSA secret
fleet-agent service status                  # visible or hidden, depending on the profile

Restart-Computer                               # survives a reboot
```

The task is registered through `schtasks.exe /Create /XML`, so the definition
above is what `schtasks /Query /TN fleet-agent /XML` prints back.

**Not verified anywhere.** `service stop` under the task mechanism ends the task,
and Task Scheduler terminates what the task started. Whether that reaches the
job objects the supervisor puts each background process in has not been checked
on a real Windows host; the documentation states the conservative reading, which
is that supervised processes stop with the agent.
