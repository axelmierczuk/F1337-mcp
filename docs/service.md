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
It also says when the host does not have the account: Linux creates a system
account and says it will, and everywhere else a missing account is what the
real `install` refuses on, so a plan that did not mention it was a plan that
could not be carried out.

**A dry run reports what `install` would refuse; it does not refuse.** It
registers nothing, so there is nothing for a refusal to prevent, and returning
one instead of the plan withholds the two answers an operator has no other way
to get. It fails only when it cannot produce a plan at all — `--mechanism task`
under a built-in service identity has no plan to print.

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
| `service` | A Windows service, through the SCM | `--user`, or asked for, in session 0 | Only if the SCM loaded that account's profile |
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
- **Ending the task takes the supervised processes with it.** Task Scheduler
  ends a task by terminating what the task started. That is the opposite of what
  `KillMode=process` and `AbandonProcessGroup` buy on the other two platforms,
  and Windows offers no setting for it. It is not only `service stop`:
  `service restart`, `service uninstall`, and the `service install` that
  replaces a running task all end it, and each says so before it does.

### The service, under a named account

```powershell
fleet-agent service install --mechanism service
# asks which account, then asks for that account's password without echoing it
```

**`--mechanism service` asks.** The account a Windows service runs as is the
account every command this agent runs executes as, and every file it writes is
owned by; it also decides whether the agent can see a per-user toolchain at all.
That is too large a decision to resolve on the operator's behalf, so when
`--user` does not say, `install` stops and asks — rather than quietly
registering whoever happened to open the elevated prompt.

**It does not ask on the default install.** The logon-triggered Scheduled Task
runs in the operator's own session and needs no credential, so there is nothing
to ask for. The prompt belongs to the one mechanism that cannot work without a
stored password. A workstation install is still one command and no questions.

The scripted form supplies both halves non-interactively:

```powershell
# an unattended install; nothing is prompted for, and nothing is echoed
'the password' | fleet-agent service install `
    --mechanism service --user 'WORKSTATION\build' --password-stdin
```

`--password-stdin` makes stdin the password, which leaves nothing to ask "which
account" with — so `--mechanism service --password-stdin` without `--user` is
refused rather than guessed at. There is deliberately **no environment variable**
for the password: an environment block is readable by anything running as the
same account and is inherited by every child process, while a pipe exists only
for the length of the command.

The SCM logs the account on to start the service, so it needs credentials. The
password is read once, handed to `CreateService`, and stored by the SCM as a
machine-bound LSA secret. Nothing here writes it to a file, an environment
variable, the service definition, or a log line, and nothing can read it back
off the machine it was stored on.

#### The credential is checked before anything is registered

`CreateService` stores a password and validates nothing. The logon happens at
every *start*, so a mistyped password produces a service that registers cleanly
and then fails forever — and by then the directories, the ACL grants and the
registration are all already on the host.

So `install` performs the SCM's own logon first: `LogonUser` with
`LOGON32_LOGON_SERVICE`, against the account spelled exactly as `CreateService`
will be given it, before the first directory is created. Three outcomes:

| What Windows says | What `install` does |
| --- | --- |
| The logon succeeds | Registers, and stops warning about a right it just used |
| `ERROR_LOGON_FAILURE` and friends | Asks again — three times at a prompt, once from a pipe — then refuses |
| `ERROR_LOGON_TYPE_NOT_GRANTED` | Refuses immediately, naming `SeServiceLogonRight` |
| Anything else | Warns that it could not check, and registers anyway |

The last row is deliberate. A status code this program has never seen is not
evidence that the install would fail, and refusing on one would block an install
that works for a reason nobody anticipated. The two codes that *are* evidence
are named.

Every refusal happens before the state directory, the log directory, the ACL
grants and the registration, so a host that refused is a host that was not
touched — and the refusal says so.

**The account needs the "Log on as a service" right**, and nothing in this
command grants it. `CreateService` stores the password; the privilege
(`SeServiceLogonRight`) is separate, the Services MMC grants it as a side
effect and the API does not, and without it the service installs cleanly and
every start fails with **error 1069, "the service did not start due to a logon
failure"** — the same shape as the error 5 below, from the other direction.
The check above is what turns that from something discovered afterwards into a
refusal; where the check could not run, `install` says so when it registers.
Granting it means `LsaAddAccountRights`, which is not something to hand-roll
into an installer; do it with `secedit`, or under *Local Security Policy → Local
Policies → User Rights Assignment → Log on as a service*.

The account is still in session 0. Whether it sees its own per-user toolchains
depends on whether its profile is loaded, which the SCM does not guarantee —
so `service status` checks rather than assumes, and `install` now says so at the
moment it registers one, naming the command that answers it and the mechanism
that does not have the question. #99 was an operator who asked for a service
under their own account, was told nothing about session 0, and had the #74
outcome. See
[When the agent is running and cannot work](#when-the-agent-is-running-and-cannot-work).

### There is no third mechanism, and that is a decision

The configuration neither of the two covers is "starts at boot with no logon,
follows whoever is at the console, survives a reboot on an unattended machine".
Reaching it means a `LocalSystem` launcher —
`WTSGetActiveConsoleSessionId`, `WTSQueryUserToken`, a duplicated primary token
with its session set, `CreateEnvironmentBlock` after `LoadUserProfile`, and
session-change handling for fast user switching and RDP. It is deliberately not
built. The reasoning is recorded in full on
[PR #79](https://github.com/axelmierczuk/fleet-mcp/pull/79); in short, it is a
standing privilege-escalation primitive on every host in the fleet, for the
third-most-common configuration, written entirely in the part of the tree no
runner here can execute. If that configuration is ever actually reported, the
cheaper partial answer is a second trigger on the task — and the expensive one
belongs in a separate binary with its own review, not in another branch of
`service install`.

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
| Windows | The invoking user, in a logon-triggered Scheduled Task; `--mechanism service` asks | No — pass `--user` for a different one |

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
`--dry-run` prints the same thing as part of the plan and exits zero, because a
dry run registers nothing and has nothing to refuse.
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
account yourself — `install` prints the command, `chown` here and an `icacls`
grant on Windows.

On Windows nothing is chowned — access there is by ACL — but the same handover
happens through `icacls`: the enrollment material is granted read to the account
the daemon will run as, and the state and log directories are granted modify,
inheritable. `%ProgramData%\fleet` already admits the built-in service
identities, and admits nothing else: the directories are created by an elevated
install, so their contents belong to the administrators and an ordinary
operator token cannot write them without this step. The old default needed
none of it; the new one does.

A `--config` outside `%ProgramData%\fleet` gets the same treatment as on Unix:
the four files are granted read individually and the directory holding them is
left alone. It needs the traverse grant `install` prints, or the daemon starts
and fails on a config it cannot open.

## When the agent will not start

A service manager reports what *it* saw, and on Windows that is not the reason.

`agent.yaml` with `listen: "0.0.0.0:8722"` and `tls.enabled: false` is refused —
correctly, and in four lines naming the address, what it would expose, and three
ways out. Run by hand you read them. Started as a Windows service you used to get:

> **Error 1053: The service did not respond to the start or control request in a
> timely fashion.**

The daemon exited before it could perform the SCM's start handshake, so the
manager had nothing to report but silence, and reported it as a timeout. The four
lines went to a stderr the SCM discards. That was the product's most likely
first-run failure on Windows — `0.0.0.0` is the obvious thing to write in a
listen field — arriving as a timeout about nothing.

Three things now carry the reason:

**The startup happens inside the manager's own start callback.** The config is
resolved, the posture is checked, the log is opened and the listener is bound
from inside `Start`, which the SCM is told about *after* it has been told the
service is starting. A refusal there is a service that reports `SERVICE_STOPPED`
with a service-specific exit code, in milliseconds:

```powershell
sc.exe query fleet-agent
#   STATE            : 1  STOPPED
#   WIN32_EXIT_CODE  : 1066  (ERROR_SERVICE_SPECIFIC_ERROR)
#   SERVICE_EXIT_CODE: 1
```

That is also what stops the restart loop. The definition sets a recovery action
— restart after 5s — and the SCM applies recovery actions to a service that
terminates *without* reporting stopped, which is what a daemon exiting early
does. A clean stop with an error code is not that.

**The reason goes to the Windows event log**, through the logger
`kardianos/service` binds to the event source `install` registers:

```powershell
Get-WinEvent -LogName Application -MaxEvents 20 |
    Where-Object { $_.ProviderName -eq 'fleet-agent' } | Format-List TimeCreated, Message
# or, on an older host:
Get-EventLog -LogName Application -Source fleet-agent -Newest 5 | Format-List
```

`services.msc` shows the same entries. The message is the daemon's own error,
verbatim and remedy included, because paraphrasing it is the whole defect. On
Linux and macOS the manager's log is journald and launchd's error path, which
already had the same text from stderr.

**And the daemon records why, where `service status` reads it.** The event log is
the SCM's; a logon-triggered Scheduled Task has nothing of the kind — it is
started by `schtasks /Run`, which succeeds whatever the process does next, and
its stderr goes to the scheduler. So a daemon that cannot start writes
`state_dir/start-failure.json`: when it happened, the config it resolved, the
version that failed, and the error verbatim. `service status` prints it:

```
service fleet-agent: installed, stopped
mechanism:  logon-triggered Scheduled Task
platform:   windows-service
config:     C:\ProgramData\fleet\agent.yaml

LAST START FAILED
  The last attempt to start this agent, at 2026-08-18T09:30:00Z, ended with:
    agent: refusing to serve without mTLS on an address that is neither loopback
    nor private: 0.0.0.0:8722 binds every interface on this host, including any
    public one
    ...
  config:  C:\ProgramData\fleet\agent.yaml
  version: 0.1.0
```

The record is one file, 0644, holding no secret — a timestamp, a version, a pid,
a config path and an error. A start that reaches its listener deletes it, so what
`status` reports is always the *last* attempt and never a fault that has since
been fixed. `service start` and `service restart` say where to look when the
manager refuses them, because what the manager returns is about the manager.

The exit code does not change: an agent that failed to start is still reported
with `0`, the way "not installed" is. Only an agent that is up and cannot work
exits non-zero; see [What a script can branch on](#what-a-script-can-branch-on).

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
runs as:    NT AUTHORITY\NETWORK SERVICE
home:       C:\Windows\ServiceProfiles\NetworkService
per-user toolchains: unknown (none installed under the home directory it was started with)

UNUSABLE
  This agent is running in session 0 as NT AUTHORITY\NETWORK SERVICE.
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
was started with, whether it is in session 0, and the result of a probe.

The account is the one the *platform* names, not the one the service definition
asked for, and on Windows those are spelled differently: `CreateService` takes
`NT AUTHORITY\NetworkService` and `LookupAccountSid` gives back the display name
for the same well-known SID, `NT AUTHORITY\NETWORK SERVICE`. Both are recognised
as the same built-in identity, in the report and in `--user`. The two disagreeing
is itself worth seeing, which is why the record keeps the platform's answer.

**And the record keeps the account's SID beside its name, because the name is
not a stable string.** `LookupAccountSid` returns a *display* name, and Windows
localises those: the account this whole document is about is spelled with
different letters on a German or French installation than on an English one.
There is no list of spellings that can be kept complete and no amount of case-
or space-folding that reaches them, so a verdict drawn from the name alone
cannot fire on a host whose display language is not English — it falls through
to the named-account case, which tells the operator their agent's "profile was
never loaded", and with `%USERPROFILE%` unset through that one too, into plain
`running`. `S-1-5-18`, `S-1-5-19` and `S-1-5-20` are those three strings on
every installation of Windows in every language. Either spelling is enough:
`account_sid` is empty off Windows, and on a host whose token could not be read,
and the name decides it there exactly as before. The
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

A home directory that is a filesystem root — `/`, `C:\` — is `unknown` too, and
is not probed at all. Every question the probe asks is "is this under the home
directory", and a root answers yes to all of them: `HOME=/` makes `$HOME/bin`
mean `/bin`, so the probe would find a machine directory, find it on `PATH`,
report `visible`, and run whichever of `node`, `go` or `cargo` happens to be in
there as its evidence. A container started for a uid with no `passwd` entry gets
`HOME=/`, so this is the shape a fleet agent lands in on a build box.

The question is asked of the *canonical* path, not of the string as it arrived.
`/.`, `/..` and `/anywhere/..` all name the root once anything cleans them —
and everything else the probe does with the home directory does clean it, since
`filepath.Join` resolves `..` and `filepath.Rel` cleans both its arguments — so
a check against the literal `/` would let every one of those spellings back in
with the false `visible`, and the execution, intact.

There is one confined shape the probe cannot see, because it looks under the
home directory the daemon was given and the daemon was given the wrong one: a
service under a named account started with a built-in *service* profile —
`C:\Windows\system32\config\systemprofile`, `C:\Windows\ServiceProfiles\...` or
`C:\Users\Default` — has no profile of its own loaded at all, so the probe finds
nothing to look for and answers `unknown`. `status` reads that pair of recorded
facts, the ordinary account and the service profile, and reports it as unusable
rather than as a machine with nothing installed.

`status` reads the file back and refuses it unless the process that wrote it is
still the process running — same pid *and* same start identity, so a reused pid
cannot answer for a daemon that is gone.

**When it cannot read the file, it says so.** A missing record is an ordinary
state and means nothing; a record that is there and cannot be read is this
command being unable to reach the only source of every answer above. On Linux
that is the common case rather than the exotic one: `install` gives the state
directory to the service account at `0750`, and `status` is not an elevated
command, so an operator who is not in that group gets `permission denied` here.
Reported as "no record", that silently turned the whole verdict off and still
exited zero. It now prints a `NOTE` naming the file and the reason, and says to
re-run as the service account or elevated.

**And when there is no record at all under a daemon that is running, it says
that too.** `serve` writes the record before it binds the listener, so "something
is running here" and "there is no record of it" cannot both be true of the same
daemon — but they can both be true of this command. `install --config` bakes a
config path into the service definition; `status` discovers a config of its own
and reads `state_dir` out of whichever it found. Point `--config` outside the
discovered location and `status` looks in the wrong state directory, finds
nothing, and used to print `running` and exit zero — which is the outcome this
whole section exists to stop. It now names the file it looked for and says that
a `--config` other than the one it printed is where a running daemon's record
goes instead.

### What a script can branch on

Three states, and the exit code separates two of them:

| State | Exit | Headline |
| --- | --- | --- |
| Not installed | `0` | `service fleet-agent: not installed` |
| Running and able to work | `0` | `service fleet-agent: running` |
| Running and confined | `1` | `service fleet-agent: running, but unusable`, plus an `UNUSABLE` block |

`1` is also what the command exits with when it fails for an ordinary reason, so
a script that has to tell "unusable" from "status itself broke" matches the
`UNUSABLE` block rather than the exit code alone.

## One host, one agent — and every command acts on both

A host can carry both registrations. That is not hypothetical: it is what
switching mechanisms produces unless something removes the old one, and two
registrations means two daemons starting against the same state directory, both
re-adopting the same supervised processes.

`install` removes the one it replaces and `status` warns when it finds two. It
also **starts the new registration when the one it removed was running**, so
following the `--mechanism task` advice `status` prints does not take the agent
down: switching mechanism is a replacement, and `install` restarts what it
replaces. A daemon that was stopped before the command stays stopped — `install`
registers, `service start` starts.

The registration being replaced is stopped before it is removed, whether it is
the other mechanism's or `install`'s own. On Windows that is load-bearing rather
than tidy: `DeleteService` only *marks* a running service for deletion, the
entry stays in the SCM database until the process exits, and the `CreateService`
that follows fails with "service fleet-agent already exists" — leaving a host
with a definition marked for deletion and no replacement. And when the thing
being stopped is a Scheduled Task, stopping it ends the processes the agent
supervises, so `install` prints the same warning `stop` does before it happens.

**Which is why the agent comes back through a *start*, not a restart.** The stop
above is what makes the definition `install` writes a freshly created one that
has never run, and none of the three managers will restart that. `kardianos`'s
Windows `Restart` is `ControlService(SERVICE_CONTROL_STOP)` followed by
`StartService` and returns at the first failure, so the stop fails with
`ERROR_SERVICE_NOT_ACTIVE` and `StartService` is never reached; launchd's
unload-then-load has the same shape. `install` asks the registration what it is
doing after the replacement lands and starts what is not running — which keeps
systemd right too, since `systemctl disable` plus removing the unit file leaves
the process up, so the replacement really is still running there and
`systemctl restart` is what puts it on the new definition.

If the write fails after the old registration is gone, the host has no agent
registered on it at all, and the error says so rather than leaving "install
failed" to be read as "nothing happened". A *removal* that fails says so too,
and says something different: the daemon was stopped so the definition could be
replaced, so the agent is down whatever the manager did with the definition.
`service restart` under the task mechanism waits for the instance it ended
before asking for a new one. Neither verb is what it looks like: `schtasks /End`
asks the scheduler to terminate the instance and returns without waiting, and
the definition sets `MultipleInstancesPolicy` `IgnoreNew` — deliberately, so a
second logon does not start a second daemon — so a run requested while the
previous instance is still on its way out is *dropped*, with `schtasks` printing
"SUCCESS: Attempted to run the scheduled task" and exiting zero either way. The
wait is against the daemon's own `runtime.json` rather than anything `schtasks`
prints, for the reason `status` is: every human-readable field the scheduler
prints is localised, and an exit code cannot say "still running".

`start`, `stop`, `restart` and `uninstall` act on **every** registration the
host carries, and keep going when one of them refuses — a `stop` that stops the
service and returns before it reaches the task leaves the daemon an operator
just asked to stop still running, with an error naming the other mechanism as
the reason. Whatever failed is reported; the command exits non-zero once, at the
end.

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

`uninstall` stops every registration it removes, so on Windows removing a
Scheduled Task ends the background processes the agent supervises. It says so
before it does it, for the same reason `stop` does.

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
executable-access refusal, the rule deciding whether `install` stops to ask for
an account, the classification of what a service logon answered, and the probe
that decides `visible`/`hidden`. The sequences built on those — the account
prompt, the password retry, and each refusal leaving the host unregistered — are
driven from the real argv on the Windows runner, with two calls replaced: the
registration itself, and the service logon.

**What is asserted versus what is invoked.** No CI runner can register a
service, and none can perform a real service logon either: that needs a real
LSA, a real account, and that account's real password, none of which a runner
has or should have. So `LogonUser` is *invoked* only by hand, from the list
below; every decision drawn from its answer is *asserted*, on every runner,
against a supplied one. The same split holds for the two most recent findings:

- **#98, a startup failure the SCM turned into a timeout.** That the daemon hands
  its reason to the service manager's logger, that the failure comes back out of
  the manager's own `Start` rather than being decided before the manager is
  involved, and that the record it writes is what `service status` reports are all
  *asserted* on every runner, driven from `fleet-agent serve` with the manager
  replaced (`PinServiceManagerForTest`). What is *invoked* only by hand is the one
  line underneath: `eventlog.Open` writing to a real Windows event log, and the
  SCM deciding what to do with a service-specific exit code. Steps 0a–0c below.
- **#99, the mechanism `install` chose.** That nothing reads the host's existing
  registration to pick a mechanism is asserted from every runner — a registered
  task does not make Linux install a task — and the Windows half of it, `auto`
  under an interactive account resolving to the Scheduled Task with a *service*
  already registered, is driven from the operator's argv on the Windows runner
  with the registration replaced. What no runner can do is register the real
  service that steers it. Step 0d below is the reproduction the issue asks for.

The rows that follow marked MUST are the ones only a real host can settle. From
an elevated PowerShell:

```powershell
# 0a. #98: the refusal an operator meets first, as a service. Write the config
#     that produced it — a plaintext agent on the address that binds everything.
#     (Back up the real one first; this deliberately breaks the daemon.)
Copy-Item C:\ProgramData\fleet\agent.yaml C:\ProgramData\fleet\agent.yaml.bak
#     set: listen: "0.0.0.0:8722", and tls.enabled: false
fleet-agent service install --mechanism service --user "NT AUTHORITY\NetworkService"
fleet-agent service start
#   MUST fail in seconds, not after 30, and MUST NOT be error 1053.
sc.exe query fleet-agent
#   MUST print STATE STOPPED, WIN32_EXIT_CODE 1066, SERVICE_EXIT_CODE 1.
#   MUST stay stopped: a recovery action applies to a service that dies without
#   reporting stopped, and this one reports it.
Get-WinEvent -LogName Application -MaxEvents 20 |
    Where-Object { $_.ProviderName -eq 'fleet-agent' } |
    Format-List TimeCreated, Message
#   MUST carry the whole refusal: "refusing to serve without mTLS",
#   "0.0.0.0:8722", "binds every interface", and all three ways out. This is the
#   only place a service operator can read it, and the one line CI cannot reach.
fleet-agent service status
#   MUST print "installed, stopped", and exit 0.
Get-Content C:\ProgramData\fleet\state\start-failure.json
#   The record — which a built-in identity can only leave if it can write the
#   state directory. It is the same file, and the same question, as the
#   runtime.json the confined shape below is checked through: %ProgramData%
#   admits Users, and NETWORK SERVICE is not one. Where it is there, `status`
#   MUST print a LAST START FAILED block with the refusal verbatim, the config
#   path and the version; where it is not, the event log above is the channel and
#   step 0c is where the record is the only one there is.

# 0b. The fix takes, and the record does not outlive it.
#     Put listen back to a loopback or private address.
fleet-agent service start
fleet-agent service status
#   MUST be running, and MUST NOT print LAST START FAILED: a start that reached
#   its listener deletes the record, or `status` reports a fault already fixed.
Test-Path C:\ProgramData\fleet\state\start-failure.json    # False

# 0c. The same failure under the task mechanism, which has no event log at all:
#     it is started by `schtasks /Run`, which succeeds whatever the daemon does.
#     Break the config again, then:
fleet-agent service install                 # the task
fleet-agent service start                   # MUST report success; the scheduler did
fleet-agent service status
#   MUST print LAST START FAILED with the reason. Nothing else on this host has
#   it — this is the step that says why the record exists and not only the log.
Copy-Item C:\ProgramData\fleet\agent.yaml.bak C:\ProgramData\fleet\agent.yaml -Force

# 0d. #99: what a host that has carried a service gets from a bare install.
#     This is the reproduction the issue asks for, in both directions.
fleet-agent service install --mechanism service --user "NT AUTHORITY\NetworkService"
fleet-agent service uninstall
fleet-agent service install                 # elevated, no --user, no --mechanism
#   MUST print "mechanism: logon-triggered Scheduled Task" and "runs as: <you>".
#   A Windows service here is #74 arriving again after the fix, for the
#   population it was filed for.
Get-Service fleet-agent -ErrorAction SilentlyContinue    # MUST be nothing
Get-ScheduledTask fleet-agent | Format-List TaskName, State
#     And with a service still registered and running, which is the upgrade path:
fleet-agent service install --mechanism service --user "NT AUTHORITY\NetworkService"
fleet-agent service start
fleet-agent service install                 # again: no --user, no --mechanism
#   MUST say it removed the existing Windows service, MUST register the task, and
#   MUST leave the agent running — it was running when this command started.
fleet-agent service status
#     Then the account spellings this program itself produces, which no runner
#     has an SCM to be handed:
fleet-agent service install --dry-run --user ".\LocalSystem"
#   MUST resolve a Windows service, and MUST warn that every command the agent
#   runs will run as the machine. A task here, or silence, is the #99 hypothesis.
fleet-agent service install --dry-run --mechanism task --user ".\NetworkService"
#   MUST refuse: a logon trigger fires when an account logs on, and this one
#   never does.
fleet-agent service install --dry-run --mechanism service --user "$env:COMPUTERNAME\$env:USERNAME"
#   MUST say the service runs in session 0 whoever it runs as, and MUST name
#   `service status` as what answers whether the profile was loaded.
fleet-agent service uninstall
```

Then the rest of the walkthrough:

```powershell
fleet-agent service install --dry-run       # changes nothing; says which mechanism

# The default: a task in your own session.
fleet-agent service install
fleet-agent service start
# `service start` only asks the scheduler to run the task; give the daemon a
# second to bind and write its record before asking what it can reach, or
# `status` answers about the moment before it started.
fleet-agent service status                  # running; per-user toolchains: visible (ran ...)
Get-ScheduledTask fleet-agent | Format-List TaskName, State
Get-ScheduledTaskInfo fleet-agent

# `runs as:` must be YOUR account. If this host makes you elevate with a
# *different* administrator account — UAC's over-the-shoulder prompt, which is
# what a standard user gets — then `install` defaulted to that administrator,
# and a logon-triggered task for an account nobody signs in as never starts.
# Re-run it with `--user <your account>`.

fleet-agent service restart
fleet-agent service status                  # running again, with a new pid
#   `restart` ends the task and runs it again. Ending a task is asynchronous and
#   the definition sets MultipleInstancesPolicy IgnoreNew, so a run asked for
#   too early is dropped by the scheduler with schtasks still reporting success.
#   If this ever reports `installed, stopped`, that is what happened.

# The claim, checked from outside the agent: the daemon is in your session,
# not in session 0.
Get-Process fleet-agent | Select-Object Id, SessionId    # SessionId must not be 0

# The other half: a per-user toolchain resolves through the agent. Run a
# command through the MCP server that only a per-user install can answer, e.g.
#   cargo --version, or `where.exe cargo`
# and confirm the path it reports is under your profile.

# The mechanism's two defining behaviours, and the only place either can be
# checked. Nothing in CI has a session to log out of.
#   1. Log off, and from another account or an RDP session confirm no
#      fleet-agent process is left. `service status` then reports the task as
#      installed and stopped.
#   2. Log back on. The logon trigger starts it again with no command run:
#      `Get-Process fleet-agent` has a pid, in your new session id.
#   3. Restart-Computer, log on, and confirm the same. A task with only a logon
#      trigger comes back at logon, not at boot — which is the trade this
#      mechanism makes and the reason --mechanism service exists.

fleet-agent service uninstall
#   NOTE printed first: ending the task terminates what it started, so anything
#   the agent was supervising is gone. Confirm that is what happened.

# Now the confined shape, deliberately, to see it reported:
fleet-agent service install --mechanism service --user "NT AUTHORITY\NetworkService"
fleet-agent service start
fleet-agent service status                  # MUST print "running, but unusable"; exits 1
#   `runs as:` is whatever LookupAccountSid calls S-1-5-20 on this host: on an
#   English install `NT AUTHORITY\NETWORK SERVICE`, spelled with a space that
#   CreateService's own spelling does not have, and on a localised install a
#   name in that language. The verdict must fire either way — it is drawn from
#   `account_sid` in the record as well as from the name.
Get-Content C:\ProgramData\fleet\state\runtime.json | ConvertFrom-Json |
  Select-Object account, account_sid    # account_sid must be S-1-5-20
Get-Service fleet-agent                     # Running, StartType Automatic
sc.exe qfailure fleet-agent                 # restart action, 5s delay
fleet-agent service install --mechanism service --user "NT AUTHORITY\NetworkService"
#   re-run over the running service: it stops it, replaces the definition and
#   starts it again. DeleteService only marks a running service for deletion, so
#   without the stop this is where the replacement fails and the host is left
#   with no registration.
fleet-agent service status                  # MUST be running, not "installed, stopped"
#   The stop is what makes the definition it writes a freshly created one that
#   has never run, and a restart there is ControlService(STOP) first: it fails
#   with ERROR_SERVICE_NOT_ACTIVE and never reaches StartService. So the agent
#   has to come back through a *start*, and this is the line that says it did.
fleet-agent service uninstall

# And a service under a named account, which is the headless answer. It needs an
# account that exists and has the "Log on as a service" right.
net user build * /add                       # if this host does not have one;
#   the * prompts for a password, and the account needs one: the SCM will not
#   log a service on with an empty one, and `install` refuses an empty answer at
#   its own prompt.

# 1. The account prompt. No --user, so install asks; type the account.
fleet-agent service install --mechanism service
#   MUST print "Account [...]" and MUST NOT register anything until answered.
#   Answer with COMPUTERNAME\build.

# 2. The credential check, against an account that has no SeServiceLogonRight
#    yet. This is the case CI cannot reach at all: a real LSA saying no.
#   MUST refuse naming SeServiceLogonRight, and MUST leave the host untouched —
#   confirm with:
Get-Service fleet-agent -ErrorAction SilentlyContinue     # nothing
Get-ScheduledTask fleet-agent -ErrorAction SilentlyContinue
Test-Path C:\ProgramData\fleet\state                     # False, if this is a fresh host

# 3. Grant the right — secedit, or Local Security Policy > User Rights
#    Assignment > Log on as a service; `install` prints the commands — and
#    re-run. Now mistype the password deliberately:
fleet-agent service install --mechanism service --user "$env:COMPUTERNAME\build"
#   MUST say the password was not accepted and ask again, up to three times,
#   MUST NOT echo what was typed, and MUST NOT have created anything when it
#   gives up. Then type it correctly.
fleet-agent service start                   # starts; no 1069, because it was checked
fleet-agent service status                  # visible or hidden, depending on the profile

# 4. The unattended form, with no console at all. Run it from a non-interactive
#    session (a scheduled task, a remote PS session, or with stdin redirected):
'the password' | fleet-agent service install `
    --mechanism service --user "$env:COMPUTERNAME\build" --password-stdin
#   MUST complete without prompting.
'the password' | fleet-agent service install --mechanism service --password-stdin
#   MUST refuse, naming --user: stdin is the password, so there is nothing to
#   ask "which account" with.

# 5. The password is nowhere. After a successful install under a named account:
Get-CimInstance Win32_Process -Filter "Name='fleet-agent.exe'" |
    Select-Object CommandLine                       # no password
Get-WinEvent -LogName Application -MaxEvents 200 |
    Where-Object { $_.Message -match 'the password' }   # nothing
Select-String -Path C:\ProgramData\fleet\*,C:\ProgramData\fleet\logs\* `
    -Pattern 'the password' -ErrorAction SilentlyContinue   # nothing
sc.exe qc fleet-agent                       # the definition; no password in it

Restart-Computer                               # survives a reboot
fleet-agent service status
fleet-agent service uninstall
```

The task is registered through `schtasks.exe /Create /XML`, so the definition
above is what `schtasks /Query /TN fleet-agent /XML` prints back.

**Not verified anywhere.** `service stop` under the task mechanism ends the task,
and Task Scheduler terminates what the task started. Whether that reaches the
job objects the supervisor puts each background process in has not been checked
on a real Windows host.

The documentation states the conservative reading — supervised processes stop
with the agent — and that is the right thing to print.

It is the right thing because it is very probably the true thing, and the
argument does not depend on the supervisor's own job objects at all. **A Windows
process is a member of its parent's job unless it breaks away**, and nothing
here breaks away: `internal/platform` starts every supervised process without
`CREATE_BREAKAWAY_FROM_JOB`, and sets no `JOB_OBJECT_LIMIT_BREAKAWAY_OK` or
`SILENT_BREAKAWAY_OK` on the jobs it does create. So a process the agent
supervises is a member of whatever job the *agent* is in, whether or not the
supervisor also managed to put it in one of its own — and on this definition the
agent is in the task's job, because `UseUnifiedSchedulingEngine` has UBPM manage
each task instance through one. Ending the task terminates that job, which
terminates every process in it and in every job nested inside it. The
supervisor's nested-assignment failing (see the comment on `terminate` in
`internal/platform/group_windows.go`, which records that it does fail in the
field when the agent is already inside a job that forbids nesting) changes
nothing here: it removes the *inner* job, not the outer membership.

And it is the right thing to print even if that reasoning is wrong, because of
what being wrong costs. An operator who believes the warning and is wrong runs
`service start` again. An operator who believes the opposite and is wrong loses
every dev server in the fleet.
