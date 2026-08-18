# Security

## What this is

`fleet-agent` executes arbitrary commands and reads and writes arbitrary
files on the host it runs on, at the request of a remote caller. **It is a
remote code execution service.** That is the feature.

**`fleet` does not sandbox.** The name describes what you point it at, not
what it provides. The agent applies a path jail, command policy, and resource
caps, and those are worth having — but they are hardening, not isolation. A
process that can run arbitrary code on a host has that host. Real isolation is
whatever the host itself provides: a throwaway VM, a container, a machine you do
not mind losing.

Do not install the agent on a machine you would not hand to the model outright.

## Trust model

| Principal | Holds | Can do |
| --- | --- | --- |
| Control plane (`fleetctl`) | CA signing key | Issue identities for the whole fleet |
| MCP server (`fleet-mcp`) | Client cert | Full exec and filesystem access on every enrolled sandbox |
| Agent (`fleet-agent`) | Leaf cert + key | Serve requests from authenticated clients (or, with mTLS off, from whoever the network lets reach the port) |
| Model | Nothing directly | Whatever the MCP server exposes as tools |

The model is not a principal. It acts through the MCP server's identity, which
is why the CA lives in a separate binary: nothing a model can call should be
able to mint a credential.

## Transport

- **mTLS on every RPC, by default.** Both sides present certificates issued by
  the fleet CA. This is what `fleet-agent enroll` configures and what every
  enrolled agent keeps.
- **Client authorization** is by certificate, further constrained by an expected
  organisational unit. A leaf issued for an agent cannot be used to drive other
  agents.
- Agents with mTLS on accept connections only from the fleet CA. A publicly
  reachable agent port is still a listening service — bind it to a private
  interface where you can.
- **It can be turned off**, for a network that already authenticates its peers.
  That is a deliberate posture with a precondition, not a convenience toggle;
  it is described in full below.

## Running without mTLS

`tls.enabled: false` in the agent config turns mutual TLS off. The agent then
serves plaintext gRPC: it demands no client certificate, presents none, and
encrypts nothing.

**The precondition is that the network authenticates its peers.** A Tailscale
tailnet, a WireGuard mesh, a VPC with security groups that admit only the
control plane — on those, the identity check this product would perform has
already been performed, by something that also encrypts the traffic, and the
fleet CA is a second identity system for a property you already have. Its setup
cost — mint a token, distribute a fingerprint, keep leaves fresh, rotate the CA —
buys nothing there.

**If that precondition does not hold, this is unauthenticated remote code
execution on the host.** The agent's purpose is running commands; with mTLS off
there is nothing between a reachable port and a shell on that machine. There is
no half-way state: it is either true that the network authenticates every peer
that can reach the port, or the agent is open to whoever can.

The failure mode is silence. An agent that skipped the CA ceremony works
immediately and, from the outside, looks exactly like a secured one. So the
product will not let the posture be held by accident:

- **The daemon refuses to serve on an address that is neither loopback nor
  private.** `--listen 0.0.0.0:8722` with mTLS off does not start. Loopback,
  RFC 1918, unique-local and link-local addresses, and carrier-grade NAT space
  (100.64.0.0/10, where every Tailscale node lives) are permitted; a wildcard
  bind, a public address, and a hostname the agent cannot judge without asking
  DNS are not. `serve --allow-unauthenticated-public` overrides it, and is the
  only way to reach that state.
- **It says so at every start**, with the listen address, what it means, and
  the precondition — the same way an unrestricted SOCKS proxy is announced. If
  certificates are configured and being ignored, it says that too.
- **`fleetctl list`, `fleetctl info`, `fleet_list`, `fleet_select` and
  `fleet_info` show it per sandbox**, as `auth: none` against `auth: mtls`, with
  a line under the listing saying what "none" costs. A mixed fleet is normal and legible: the posture is
  recorded per sandbox in the registry, and the control plane dials each one the
  way its entry says.
- **The audit record says so.** See [Audit](#audit).

The client half is symmetrical and explicit. `fleet_add … insecure: true`
registers a sandbox the control plane will reach without mTLS; nothing infers
it, because an agent serving plaintext and one refusing a handshake are
indistinguishable to a dialer that has not been told. Registering it wrongly
costs a failed connection in either direction — never a silent downgrade. The
control plane announces every unauthenticated dial it makes.

### What enrollment means without a CA

Nothing is issued, and nothing is proved.

Enrollment does two things: it gives a host a name in the fleet registry, and it
gives that host a certificate binding the name to a keypair only that host holds.
Without mTLS the second half has no meaning — there is no CA to sign anything and
nothing on the wire to check a signature against — and it also has nothing to do:
`fleetctl serve` and `fleet-agent enroll` are the ceremony this posture exists to
skip.

The first half remains, and remains useful: a sandbox still has a name, an
address, labels and a registry entry, added with `fleet_add`. But that name is a
label this workstation assigned to an address, exactly as it is for a sandbox
enrolled without `--name`. **The host never proves it.** If something else
answers on that address, the fleet will call it by the name in the registry, and
the audit records it writes will be stamped with the name in *its* config. On a
tailnet that is fine, because the tailnet decides who can answer. It is the
whole of what the name means.

## Enrollment

```
operator                control plane              new host
   │                          │                        │
   ├─ fleetctl enroll mint ─►                        │
   ◄── token + CA fingerprint ┤                        │
   │                                                   │
   ├─────── token + fingerprint, out of band ─────────►│
   │                          │                        │
   │                          ◄── Enroll(token, CSR) ──┤  keypair generated here
   │                          ├── signed cert + CA ───►│
```

- Tokens are **single-use** and short-lived.
- **The token is spent last, not first.** Everything that can refuse an
  enrollment — the name, the addresses, the CSR, the SAN set the CA is asked to
  sign — is checked before the token is redeemed, so a request refused for a
  mistyped `--address` leaves the token spendable and the operator's corrected
  retry works. Redemption is still a single atomic check-and-mark under the
  store's lock, and it is still the only thing that grants the right to proceed:
  of any number of enrollments holding one token, exactly one wins it and the
  rest are refused as replays. The read that runs first claims nothing and is
  advisory — a token revoked or expired inside that window is refused by the
  redemption, not admitted on the strength of the earlier read. The redemption
  comes before the fleet registry write, because that write is the first thing
  that cannot be taken back: the loser of a race must be refused without leaving
  a fleet member behind.
- **A token authorizes an identity, not just admission.** The name and addresses
  given to `enroll mint` are the only ones the issued certificate carries — in
  its subject as much as in its subject alternative names, because an attacker
  does not care which field a name it chose ends up in. An enrolling host may
  decline to use them; it cannot widen them, and asking to be enrolled under a
  different name is refused. Otherwise one valid token yields a CA-signed leaf
  for any name in the fleet, and mTLS stops meaning anything.
- **A registry label is not an identity.** A token minted without `--name` lets
  the enrolling host pick what the fleet registry calls it. That name is a
  label: it is echoed back as `assigned_name` and printed by `fleetctl list`,
  and it appears nowhere in the certificate.
- Everything an enrolling host says about itself — its platform, its version,
  the addresses it names — is bounded in length and rejected if it contains
  anything but text. All of it is persisted in the registry and printed back to
  an operator, and a terminal escape in a fleet listing is a lie about the
  fleet.
- The host generates its own keypair and sends only a CSR. **The private key
  never crosses the network**, so neither a leaked token nor a compromised
  control plane yields an existing agent's key.
- `EnrollmentService` is the one endpoint an unauthenticated caller may reach,
  because the enrolling host has no certificate yet. It is server-authenticated
  TLS plus the bearer token.
- **Pin the CA fingerprint.** `enroll` requires `--ca-fingerprint` and refuses
  to run without it. Unpinned, enrollment would trust whatever certificate the
  control plane presents, and a network attacker who can answer on that address
  collects the token. The installers require it for the same reason, and refuse
  before they download anything.

## Rotating the CA

The fleet CA is the root of every identity in the system. Replacing it is
`fleetctl ca rotate`, and it is deliberately **three commands over three
sittings**, not one.

**Stop `fleetctl serve` before you start, and leave it stopped until you are
done.** It loads the CA and the bundle once, at startup, and keeps signing with
what it loaded: a host that enrolls through a `serve` started before a rotation
is issued a leaf under the outgoing CA and handed a bundle with no new root in
it — a fleet member built to break at step 3, created after you began the
rotation to avoid exactly that. `serve` is meant to be short-lived anyway; this
is one more reason.

The reason is the trust that runs in both directions. Each fleet member holds a
bundle of roots it trusts and a leaf signed by whichever root was issuing when
it enrolled. The control plane verifies an agent's leaf against its bundle; the
agent verifies the control plane's leaf against *its* bundle. Start signing
under a new root before every agent trusts that root and the second direction
breaks: every agent rejects the control plane, and an agent that has stopped
answering is one you can no longer reach over this transport to fix.

So trust is distributed first, issuers switch second, the old root is dropped
last — and the middle of that is you copying a file to machines this tool
cannot reach, which is why no single command claims to do the whole thing.

### 1. Stage

```sh
fleetctl ca rotate
```

Generates the next CA and adds it to `~/.config/fleet/ca/ca.crt`, which is a
bundle rather than a single certificate. Nothing is signed under the new root
yet — the old CA is still the issuer — so this step cannot invalidate anything.
`fleetctl ca fingerprint` keeps printing the old fingerprint, because that is
still the one an enrolling host must pin.

Now distribute the widened bundle. On each host, replace the file its
`agent.yaml` names as `tls.ca_bundle` (`/etc/fleet/ca.crt` on a Linux install)
with the control plane's `ca.crt`, then restart the agent:

```sh
scp ~/.config/fleet/ca/ca.crt build-box:/tmp/ca.crt
ssh build-box 'sudo install -m 0644 /tmp/ca.crt /etc/fleet/ca.crt && sudo fleet-agent service restart'
```

Restart `fleet-mcp` too — it reads the bundle at startup.

Re-enrolling a host achieves the same thing, since the enrollment response
carries the whole bundle. Copying the file is cheaper and does not spend a token.

**Do not go on until every agent has the new bundle.** This is the only step
where getting ahead of yourself breaks the fleet.

### 2. Activate

```sh
fleetctl ca rotate --activate
```

The staged CA becomes the issuer, and the outgoing private key is replaced
rather than kept — a spare CA signing key on disk is precisely what this
directory's handling exists to avoid.

Certificates issued by the old CA still verify, because the old root is still in
everyone's bundle. The fleet keeps working, and you re-issue leaves at your own
pace:

```sh
fleetctl ca sign --profile control                       # this workstation's own leaf
fleetctl ca sign --csr build-box.csr --subject build-box \
  --address build-box.internal:8722 --out build-box.crt  # a host that sent a CSR
```

or simply re-enroll a host, which issues it a fresh leaf under the new CA.

From here on, `fleetctl ca fingerprint` prints the **new** fingerprint. Hand
that one to every host enrolling from now on; the old one no longer names a CA
that signs anything. While both roots are trusted, `ca fingerprint` says so and
lists the others explicitly, so there is no guessing which to pin.

### 3. Retire

```sh
fleetctl ca rotate --retire
```

Drops every root but the issuer from the bundle. **This is the step that breaks
things** — anything still holding a certificate from the old CA stops verifying
the moment you distribute the narrowed bundle.

Run it only once nothing depends on the old root. `fleetctl list --json` shows
every sandbox and its health, and a host still on an old leaf will start failing
as soon as the retired root is gone from *its* bundle — so retire on the control
plane first, confirm the fleet is still healthy, and only then distribute the
narrowed `ca.crt` back out.

If in doubt, do not retire. A bundle holding one extra root is a small cost; a
fleet that cannot authenticate itself is an afternoon with a console on every
machine.

### If a step is interrupted

Each step writes more than one file, so a crash or a `^C` in the middle leaves a
CA directory part-way through. Every case is recoverable, and none of them needs
you to edit the directory by hand:

- **Interrupted stage** — `ca-next.crt` exists but is not yet in `ca.crt`.
  Nothing trusts the staged root, so nothing has changed for the fleet. Delete
  `ca-next.crt` and `ca-next.key` and run `fleetctl ca rotate` again; the
  commands that notice say exactly this.
- **Interrupted activation** — the incoming key has replaced `ca.key` but the
  bundle still names the outgoing CA as the issuer. Commands that need to sign
  refuse to run at all, and say so: a certificate and a key from different CAs
  is the shape of a half-restored backup, and this tool will not guess. Run
  `fleetctl ca rotate --activate` again. It reads the trust bundle rather than
  the mismatched pair, finishes the two writes, and the directory is whole.
- **Interrupted retirement** — `ca.crt` is written atomically, so it holds
  either the old bundle or the narrowed one. Re-run the step.

### What rotation does not fix

Rotation replaces the CA. It does not revoke anything. A leaf issued by the old
CA remains valid until the old root leaves every bundle — which is step 3, and
is why step 3 exists at all. If the concern is a *compromised* CA key rather
than an aging one, the overlap window is the window in which the attacker's
certificates are still honoured: rotate, distribute, activate, and retire as
fast as you can move, and treat every leaf issued by the old CA as suspect.

## The account the agent runs as

Every command the agent executes runs as the account the daemon runs as, and
every file it writes is owned by it. **Running the agent as root means every
sandbox command a model issues runs as root**, and the path jail is the only
thing between it and the rest of the machine.

So `service install` does not default to a superuser: a dedicated `fleet`
system account on Linux, and the invoking user on macOS and Windows. `--user
root` (or `--user LocalSystem`) is available, warns loudly, and is a decision
rather than a default. On the two platforms that default to the invoking user,
`install` refuses when the invoking user *is* the superuser — which, since
`install` needs elevation, is the common case — rather than quietly handing the
model root. See [docs/service.md](service.md).

The Windows default is a logon-triggered Scheduled Task in the operator's own
session, with `LogonType` `InteractiveToken` and `RunLevel` `LeastPrivilege`:
the operator's ordinary token, not their elevated one. It replaced `NT
AUTHORITY\NetworkService`, which was the more confined answer and produced an
agent that could not run anything — session 0 has no operator profile, so no
per-user toolchain and none of the credentials in `%APPDATA%`. That account is
still available for someone who wants a confined agent, and `service status`
now reports such an agent as **unusable** rather than as running.

The systemd unit sets `KillMode=process` and the launchd job sets
`AbandonProcessGroup`. Those are not hardening — they are what stops a routine
`systemctl restart` from killing every background process the agent supervises.

## Filesystem confinement

**The path jail and `exec` are mutually exclusive, and `exec` is on by
default.** An agent that can run commands is not confined by a path check:

```
argv: ["sh", "-c", "echo pwned > /etc/passwd"]
```

That is one `ExecService` call. It needs no `shell: true` — you exec `sh`
directly — and `tee`, `cp`, `dd` and `python -c` all do the same job. So with
exec enabled the jail stops **nothing** an attacker would do, while an operator
who reads `allowed_roots` in their config reasonably concludes the agent is
confined to them. A control that stops honest mistakes but not dishonest ones,
while looking like a security control, is worse than no control, because it is
what people plan around.

So:

| `exec.enabled` | `allowed_roots` | `GetHostInfo.allowed_roots` |
| --- | --- | --- |
| `true` (default) | ignored, with a warning at every start naming why | empty — the agent reports itself unconfined |
| `false` | enforced on every `FileService` path | the resolved roots |

The wire behaviour matters as much as the enforcement. `allowed_roots` is what
`fleet_info` and `fleet_select` show the model to tell it where it may
write; reporting roots that constrain nothing is the model-facing version of
the same lie.

When the jail *is* in force, paths are resolved to absolute form, symlinks are
resolved, and only then is containment under an allowed root checked. Doing it
in that order is the whole point: checking for `..` in the requested path before
resolution is a jail that any symlink inside it walks straight out of.

Resolving and then opening are two operations, and between them a component can
be replaced with a symlink pointing anywhere. On Linux the jail hands the check
to the kernel instead, opening through `openat2` with `RESOLVE_BENEATH`, so the
check and the use are one operation and no window exists. Everywhere else — and
on Linux kernels before 5.6, or under a seccomp filter that blocks the syscall —
it falls back to resolve-then-open and the window is real. The daemon logs which
one it got at startup rather than letting an operator assume the stronger of the
two.

An exec-disabled agent with no allowed roots has no jail either. It refuses to
start that way unless explicitly forced, and reports the condition in
`fleet_info`. It also refuses to start on an allowed root that does not exist:
a missing path can be created later, as a symlink to anywhere, and a jail that
had accepted it would then confine to whatever it pointed at.

If you want a filesystem boundary on an agent that runs commands, it has to come
from outside the agent: a container, a VM, a `ProtectSystem=strict` unit with
`ReadWritePaths` (see [docs/service.md](service.md)), or a user account that
cannot read what you care about. Those are enforced by something the agent
cannot talk its way past.

## Execution

- **argv, not a shell string.** Commands are exec'd directly. This removes a
  class of quoting and injection bugs, and it is the only thing that works
  uniformly across platforms — Windows has no `sh -c`. `shell: true` is opt-in.
- **The daemon's environment is not inherited.** A command starts from a
  documented base — `PATH`, `HOME`, `TMPDIR`, the locale, and on Windows the
  variables a process cannot start without plus `%APPDATA%` and
  `%LOCALAPPDATA%`, which name the account's own configuration directories and
  are what a session-0 agent has no useful version of — and the request's `env`
  is applied on top. The daemon's own environment holds whatever the thing that installed
  the service was holding: a CI runner's registry token, an operator's cloud
  credentials, a `GITHUB_TOKEN` from the shell that ran the installer. Handing
  that to every command a model asks for would be a credential leak with a
  remote trigger.
- **Caps.** Wall-clock timeout, maximum output bytes, maximum concurrent
  processes, enforced centrally so that no two services can disagree about them.
  `process.max_concurrent` is one agent-wide number, and both `ExecService` and
  the process supervisor take their slots from the single limiter built from it:
  a cap each service counted for itself would let an agent set to 32 run 32 of
  each.
  Exceeded caps are reported to the caller, never silently applied: truncated
  output is always marked as truncated, and a timeout above the agent's maximum
  is refused with the maximum named rather than quietly shortened.
- **Killing means killing the group.** On timeout or a caller hanging up, the
  agent signals the process group — a session on Unix, a job object on
  Windows — not the leader. `sh -c 'make -j8'` is nine processes, and
  signalling one of them leaves eight compilers running with nobody watching.
- **`exec.enabled: false` covers every way the agent runs a command**, not just
  `ExecService`. `ProcessService.StartProcess` and `RestartProcess` refuse on
  such an agent too. A supervised process is a command, and an agent that
  honoured the flag in one service and not the other would report itself
  confined through `GetHostInfo` while running
  `["sh","-c","cat /etc/shadow > /tmp/x"]` on request.
- **Command policy.** Optional per-agent allow and deny lists, matched on the
  resolved executable path rather than the string as given, so `/bin/../bin/sh`
  does not walk past a rule naming `sh`. The default is allow-all, which is
  honest about what the service is rather than implying a security boundary
  that a deny list does not actually provide.

  Judge these as operational guardrails, not as confinement. Two things they
  cannot do:

  - **A name is not an identity.** An allow list holding `python3` admits any
    file called `python3` anywhere on the host, including one the caller wrote a
    moment ago. Prefer absolute paths.
  - **An allowed interpreter allows everything it can run.** `python3`, `perl`,
    `node` and `make` on an allow list are each a shell by another name.

## The interactive shell

`fleetctl shell` opens a real terminal session on an enrolled host: a
pseudo-terminal on the sandbox, raw mode on the operator's own terminal, and
bytes in between over the same mTLS stream as everything else. **It is the most
direct remote-code-execution surface in the product**, and it belongs in this
document under that heading rather than in a list of conveniences.

It is not a new capability. Anyone who can call `fleet_exec` already runs
arbitrary commands as the agent's account, and every argument in
[Execution](#execution) applies here unchanged — there is no path jail, no
meaningful command policy, and no isolation that the host does not itself
provide. What it adds is convenience, and convenience is what decides how often
a capability is used and by whom. So:

- **`shell.enabled` turns it off on its own**, leaving exec on. That is a real
  configuration: an agent that runs commands for a model and hands nobody an
  interactive terminal.
- **`exec.enabled: false` turns it off too.** A terminal is a way to run a
  command, and it is the most direct one. An agent that honoured that setting for
  `ExecService` and not here would report itself confined through `GetHostInfo`,
  hand an operator a configured `allowed_roots` list, and then let them type
  `cat /etc/shadow`. It refuses the call outright, naming the setting.
- **Every session is recorded.** See below; this is the part that matters most.

### What the session is, mechanically

- **The session leads its own process group**, and on Windows its own job
  object. Ending the session ends the tree: the terminal is hung up first —
  which on Unix is a SIGHUP to its foreground process group, and is what makes
  an interactive shell pass the hangup on to its own jobs — and then the group
  is killed. A job the operator deliberately detached with `nohup`, `disown` or
  `setsid` survives, exactly as it does over `ssh`; that is a property of what
  they asked for rather than a gap.
- **A dropped connection ends the session.** There is no reattach, and nothing
  is left running on the host when the operator's terminal goes away.
- **`shell.idle_timeout` bounds an abandoned session**, measured from the last
  byte in either direction so that watching a long build does not count as
  idleness. It cannot be disabled, only lengthened: a session holds a
  pseudo-terminal, a process tree and one of the agent's concurrency slots.
- **Ctrl-C is a byte, not a signal.** The operator's terminal is in raw mode, so
  an interrupt never fires locally; it travels to the sandbox and its terminal
  turns it into a SIGINT for whatever is in the foreground there. That is what
  makes interrupting a remote command interrupt the command rather than the
  client carrying it.

### The record

Every session appends one line to the [audit log](#audit): the time it started,
the authenticated principal from the client certificate, the sandbox's own name,
the RPC, the command the session ran, the working directory, how long it lasted,
and how it ended — an exit status, a signal, or the idle timeout. The end of a
session is its start plus its duration, which is also how a forwarded connection
is recorded.

**The contents are never recorded, and no field may be added that could carry
them.** A session carries whatever the operator types and whatever the host
prints back: a password at a `sudo` prompt, a token pasted into a `curl`
command, a private key echoed by `cat`. An audit log holding that would be a
credential store nobody meant to build, on the least protected host in the
fleet, with weaker handling than whatever it copied the secrets out of — it gets
shipped off-box, read by people debugging something unrelated, and kept long
after the credential in it should have been rotated.

That is enforced by the shape of the code rather than by everyone remembering
it: the only value the audit path can see is a record type with no field capable
of holding a byte of a session, and the two functions that touch session bytes
are given neither it nor the log. `internal/agent/shell` says so in its package
comment, and a test drives a session carrying two distinct secrets — one typed,
one printed — and fails if either appears in the audit log or in the daemon's
own log.

The one thing that **is** recorded and could carry a secret is the command the
session was opened with: `fleetctl shell -- mysql -pHUNTER2` writes that
password into the file, for the same reason and with the same limitation as exec
argv. Open a shell and type it instead; what happens inside a session is never
written down.

### There is no shell tool

The MCP server deliberately exposes nothing that opens one, and should not grow
it. A model does not need an interactive terminal — `fleet_exec` and
`fleet_process_start` cover its use cases — and streaming raw terminal bytes
into a context window is a bad trade in every direction: expensive, unreadable
once escape sequences are in it, and impossible to bound. `fleetctl shell` is an
operator command, run by a person who already holds a control certificate.

## The pivot surface

Everything else in this document is about what a caller can do **to** the host
the agent runs on. This section is about what it can do **through** it.

`fleet_forward` is `ssh -L`: a local listener on the workstation, a socket on
the sandbox, and bytes in between. Forwarding to the sandbox's own loopback is
a convenience — it reaches a port on a machine the caller already has full
command execution on, and gives it nothing it did not already have. Forwarding
anywhere else is different in kind: it makes the agent a relay into whatever
network it sits in, usable by anyone who can reach the agent. On a fleet
spanning a laptop, a home lab and a cloud VPC, "anywhere else" spans all three.

`fleetctl socks` and `fleet_socks` are `ssh -D`, and they are that relay in its
general form: a SOCKS5 proxy whose destination is chosen by the client, one
connection at a time. Everything below applies to both, and the two settings
that gate them are separate on purpose.

So the pivot is off by default, and when an operator turns it on, it is
recorded.

### The default

- **The local listener binds `127.0.0.1` only**, for a forward and for a proxy
  alike. Binding every interface would publish a tunnel into the sandbox — or,
  for a proxy, an unauthenticated route into the sandbox's whole network — to
  everyone on the workstation's network, with nothing in front of it, including
  on a network the user did not choose. There is no flag to change it.
- **`remote_host` defaults to the sandbox's own loopback**, and a non-loopback
  target is refused unless the operator listed it in `forward.allowed_hosts`.
  Forwarding a dev server works identically without that capability, so an
  agent that never needs it never notices it is missing — which is exactly why
  the permissive version would go unnoticed too.

  The check resolves the requested host and requires **every** address it
  resolves to to be loopback or covered by the allow list, then dials the
  addresses that passed. Judging the string would be defeated by a name that
  resolves outward; judging one address would be defeated by a name that
  resolves to several; re-resolving at dial time would leave a window between
  the check and the connection.

  An entry is a hostname, an address, or a CIDR block. A hostname is matched
  literally, case-insensitively, and dialed **by name** — the operator listed a
  name because the name is what routes, and has already accepted wherever it
  points. An address or a block is matched against what the target resolves to.
- **`forward.socks_enabled` defaults to `false`**, and an agent that has not
  opted in refuses a proxied connection outright, naming the setting — including
  a proxied connection to a host its allow list permits, and including one to
  its own loopback. The refusal is about the capability, not the destination.

  It is a second setting rather than a wider reading of the first because they
  are different grants. A forward reaches a host and port the caller named up
  front; a proxy reaches whatever a client asks for. An agent with
  `allowed_hosts` set still forwards to exactly the hosts it always did, and
  serves no proxy at all, until this is turned on.
- **`socks_enabled: true` with an empty `allowed_hosts` means any host the
  machine can reach.** That is a legitimate choice for a throwaway lab box and
  the wrong one everywhere else, so the agent warns about it in its log at
  every start, `fleetctl socks` prints it in a banner an operator cannot miss,
  and `fleet_socks` refuses to open a proxy on those terms at all. See
  [the model's proxy](#the-models-proxy).

  **"Unrestricted" has a second spelling, and it is treated as the same thing.**
  An `allowed_hosts` of `["0.0.0.0/0"]` — or `["::/0"]` — has entries, reads as
  a narrowing, and permits every host of that family the machine can reach. It
  is also what an operator writes when they want the lab-box posture and have
  been told to list CIDR blocks, which is exactly what `fleet_socks`'s refusal
  tells them. So the agent judges the two together: a block covering its whole
  address family raises the same warning as an empty list, and is refused by
  `fleet_socks` the same way.

  The judgement is the agent's, reported as `ForwardPolicy.unrestricted` rather
  than re-derived on the workstation from the list — a caller re-deriving it
  would carry a copy of the rule, and the copy is what drifts. Blocks that add
  up to everything without any one of them covering everything (`0.0.0.0/1`
  and `128.0.0.0/1`) are not caught, deliberately: this names the plausible
  mistake rather than doing CIDR arithmetic that would still miss the next
  spelling. It is a description either way — what the agent will actually reach
  is decided per connection, from the same configuration.

An operator who lists a host has accepted that the agent will connect to it on
any caller's request. The agent says so in its log at every start, and warns
separately if it was told to do that with the audit log switched off — the two
settings are only dangerous together.

### How the agent tells the two apart

A proxied connection is marked as one on the wire: `ForwardOpen.socks`, on the
stream that already carries every forwarded connection. There is no second RPC
and no second byte-pump — a second one would be a second place to leak a
goroutine per connection — so the difference between the two features on the
agent is which policy applies.

That field is **not** a security boundary and does not need to be. Declaring it
can only ever make the policy applied to a connection *stricter*: a caller that
clears it gets the forward rules, which permit loopback and the explicit allow
list and nothing else. There is no value a caller can put there that reaches a
host the configuration does not already permit it to reach. What the field buys
is that an operator can grant "reach these three hosts" without also granting
"be a proxy", which no property of the destination alone could express.

### The model's proxy

`fleetctl socks` gives an operator a pivot they could have built with
`fleet_exec` and `curl`. `fleet_socks` gives a **model** one — and a model with
a SOCKS proxy can reach every host the sandbox's network reaches, which is a
larger blast radius than every other tool in the set combined. Every other tool
is bounded by the sandbox: its filesystem, its processes, its ports. A proxy is
bounded by the sandbox's *network*, which on a fleet spanning a laptop, a home
lab and a cloud VPC is a set nobody has enumerated.

`forward.allowed_hosts` is what makes it defensible: the operator decides the
reachable network once, and the model works inside it. So the two callers are
deliberately not symmetric:

| | `socks_enabled: false` | on, `allowed_hosts` narrows something | on, `allowed_hosts` empty or covering everything |
| --- | --- | --- | --- |
| `fleetctl socks` | refused, naming the setting | serves, listing the hosts | serves, with an unmissable banner |
| `fleet_socks` | refused, naming the setting | serves, reporting the hosts in its result | **refused** |

An operator running the CLI made the "any host" decision themselves, about a
machine they chose, at a moment they were thinking about it. A model reaching
the tool inherits that decision without anyone having made it about a model —
the config was very likely written for a lab box months earlier, and nothing
since has asked whether the same box should hand a general-purpose network
pivot to something that will use it autonomously. So `fleet_socks` requires the
operator to have narrowed it, and narrowing it is one line in the agent's
config, which the refusal quotes.

This is a guardrail on a model, not a boundary. It is enforced on the
workstation, from what the agent reports about its own configuration through
`GetHostInfo`. The boundary is the agent's, applied per connection on the far
side, where no caller can skip it.

### What a proxy does not implement

CONNECT only. BIND and UDP ASSOCIATE are refused with the code RFC 1928 has for
it. UDP would need a datagram path the transport does not have — `ForwardService`
carries a TCP connection — and half-implementing it would be worse than
refusing: a client whose UDP association appears to be accepted and then
silently carries nothing is a client debugging the wrong layer.

The proxy offers no authentication, because there is nobody to authenticate:
the listener is on loopback, so its reachable population is processes on this
machine, and a username and password in a file beside it would add a step
without adding a boundary.

Destination names are resolved **on the agent**, never on the workstation. That
is the whole point — `curl --socks5-hostname`, not `--socks5` — because a
private name means nothing to the workstation's resolver, and resolving it there
reaches the wrong host or fails outright. `fleetctl socks --allow` narrows
destinations on the workstation side as a convenience; it is not a boundary and
does not replace the agent's list, which is checked on every connection
regardless.

### The record

Every connection appends a line to the [audit log](#audit), whether it
succeeded, was refused, or failed — forwarded and proxied connections alike, in
the same fields. An operator asking "what did this machine reach, for whom, and
how much went through it" is asking one question, not two.

A **forward** to this machine's own loopback is the one exception: it reaches a
port on a host the caller already has command execution on, so it adds volume
without adding an answer, and volume is what makes the lines that matter hard to
find. **Every proxied connection is recorded, wherever it went**, including to
loopback. The two are not the same question: a forward's destination is in the
configuration, named up front and fixed for the life of the listener, while a
proxy's is chosen per connection by whoever holds the proxy. Dropping a proxy's
loopback connections would answer "where did this go" wrongly rather than
incompletely — an operator counting a proxy's connections would find three
hundred where there were five hundred, with nothing saying so.

One line per connection, not per listener — a forward or a proxy is a listener
that carries many connections over hours, and "a proxy was opened" answers
nothing about what went through it. Each line carries the time, the
authenticated principal from the client certificate, the sandbox's own name, the
requested `remote_host` and `remote_port`, the address actually dialed, the local
end of the agent's outbound socket, bytes in each direction, the duration, and
how it ended.

A pivot with no record of where it went is what turns an incident into an
unanswerable question, and that is sharpest for a proxy: the destination is
chosen per connection by whoever is using it, so the configuration alone cannot
tell anyone afterwards where it went.

Two of those are worth stating on their own:

- **The requested host and the resolved address are both recorded.** They are
  different facts. The name is what appeared in the caller's request and what
  an operator will search for; the address is where the packets went, and a
  name that resolved somewhere unexpected is precisely the case worth seeing.
  An empty resolved address means the connection never got that far.
- **Refusals are recorded, not just successes.** A request to reach somewhere
  the configuration does not permit is the single most useful line in this
  file: it is the one that says somebody asked. The same argument applies to
  denied commands on the exec path.

The record counts bytes and never holds them. A tunnelled connection carries
whatever the caller sends through it — a database password, a bearer token, a
private key on its way to a deploy — and a log that captured that would be a
credential store nobody meant to build, sitting on the least protected host in
the fleet. See the contract on `policy.Record`.

The line is written when the connection **ends**, because that is when the
volume and the outcome exist. A connection still open is not yet in the log.

`audit.required` applies here as it does to exec: with it set, a connection
whose record could not be written is reported to the caller as failed rather
than closing cleanly, because an agent configured to act only when it can
record what it did must not report success for an unrecorded pivot.

## Audit

Every exec, every interactive shell session, every forwarded connection that
leaves the machine — and, as they land, every write, edit, process start and
signal — appends one JSONL record: timestamp, principal, the sandbox's own name,
RPC, outcome, duration, and then whatever the operation has: argv and the
resolved executable and working directory for a command or a session, the
requested and dialed addresses and the byte counts for a connection.
Append-only, rotated by size with a configurable number of retained segments.

**The principal says how it was established.** On an agent using mTLS it is the
client certificate's common name, taken from the chain the agent verified, and
the record carries `"principal_source": "certificate"`. On an agent serving
without mTLS nothing was verified, and the record says so twice over: the
principal reads `unauthenticated:<peer address>` and `"principal_source"` is
`"network"`. The address is worth recording — it is what joins the line to a
tailnet's own access log, a firewall log or a conntrack entry, which on such an
agent is where the caller's identity actually lives.

A record with no `principal_source` at all was written before the field existed,
by an agent for which mTLS was mandatory, so absent means `certificate` and every
historical line still means exactly what it meant. What must never happen is a
principal nobody verified reading like one that was — an audit log where those
two are indistinguishable has quietly stopped being an audit log.

Every record names the sandbox it came from. That is redundant on the host that
wrote it and essential everywhere else: these files are shipped off-box and
read together, and a line that does not name its machine cannot be acted on.

**What it never contains.** There is no field for environment values, file
contents, stdin, command output, what a terminal session carried, forwarded
payload bytes or the enrollment token, and none may be added.
An audit log that captures secrets is a new place to steal them from, and one
with weaker handling than whatever it copied them out of: it gets shipped
off-box, read by people debugging something unrelated, and kept long after the
credential in it was supposed to have been rotated.

That rule is about the record, not only about its field list. An error message
is written into a field, and a caller chooses much of what goes into one — the
`PATH` a failed lookup searched, an environment entry quoted back at whoever
malformed it. Those are redacted in the record and left intact in the error the
caller receives: the caller sent them, and an exec caller can read the agent's
environment with a command in any case, so telling it costs nothing that
writing it down would not cost more.

**What it does contain, and the limitation that follows.** Argv is recorded, so
`mysql -pHUNTER2` writes that password into the file. The argument list is the
whole point of an exec record and there is no reliable way to tell a password
from a path, so this is a limitation to work with rather than a bug to fix: pass
credentials in the environment, which is never recorded.

See [the pivot surface](#the-pivot-surface) for which connections are recorded
and why loopback ones are not, and [the interactive shell](#the-interactive-shell)
for the record that matters most and the code shape that keeps a session's
contents out of it.

**`audit.required` is a real choice.** With it set, an RPC whose record could
not be written fails — an agent that must not act unrecorded. Without it, the
failure is logged and the call proceeds — an agent that must keep serving when
its log volume fills. Neither is guessed for you.

**It is forensic, not preventive.** A caller who can execute code on the host
can also reach the audit file: append to it, truncate it, or delete it. The log
is what you read afterwards to find out what happened, and it is only as
trustworthy as the host it sits on. Ship it off-host if it needs to survive the
host.

## Installer

`curl … | sh` is trust-on-first-use, and no amount of care inside the script
changes that. What the script does do:

- Verifies the artifact's SHA-256 against the checksum file published with the
  same release, and refuses to install on a mismatch.
- **Requires `--ca-fingerprint` alongside `--token`**, and refuses before it
  downloads anything. `enroll` has always refused to run unpinned, so an
  installer that warned and carried on could only fail later, after installing a
  binary on a host that never joined the fleet.
- Warns, every time, that `--root` is not a jail on an exec-enabled agent.

Releases carry build provenance attestations. To skip the pipe entirely,
download the archive, verify it against `checksums.txt`, and run the binary
yourself.

## Reporting a vulnerability

Open a GitHub security advisory on this repository rather than a public issue.
