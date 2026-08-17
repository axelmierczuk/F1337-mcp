# Security

## What this is

`sandboxd-agent` executes arbitrary commands and reads and writes arbitrary
files on the host it runs on, at the request of a remote caller. **It is a
remote code execution service.** That is the feature.

**`sandboxd` does not sandbox.** The name describes what you point it at, not
what it provides. The agent applies a path jail, command policy, and resource
caps, and those are worth having — but they are hardening, not isolation. A
process that can run arbitrary code on a host has that host. Real isolation is
whatever the host itself provides: a throwaway VM, a container, a machine you do
not mind losing.

Do not install the agent on a machine you would not hand to the model outright.

## Trust model

| Principal | Holds | Can do |
| --- | --- | --- |
| Control plane (`sandboxctl`) | CA signing key | Issue identities for the whole fleet |
| MCP server (`sandboxd-mcp`) | Client cert | Full exec and filesystem access on every enrolled sandbox |
| Agent (`sandboxd-agent`) | Leaf cert + key | Serve requests from authenticated clients |
| Model | Nothing directly | Whatever the MCP server exposes as tools |

The model is not a principal. It acts through the MCP server's identity, which
is why the CA lives in a separate binary: nothing a model can call should be
able to mint a credential.

## Transport

- **mTLS on every RPC.** Both sides present certificates issued by the fleet CA.
  There is no plaintext mode and no `--insecure` flag, including on loopback.
- **Client authorization** is by certificate, further constrained by an expected
  organisational unit. A leaf issued for an agent cannot be used to drive other
  agents.
- Agents accept connections only from the fleet CA. A publicly reachable agent
  port is still a listening service — bind it to a private interface where you
  can.

## Enrollment

```
operator                control plane              new host
   │                          │                        │
   ├─ sandboxctl enroll mint ─►                        │
   ◄── token + CA fingerprint ┤                        │
   │                                                   │
   ├─────── token + fingerprint, out of band ─────────►│
   │                          │                        │
   │                          ◄── Enroll(token, CSR) ──┤  keypair generated here
   │                          ├── signed cert + CA ───►│
```

- Tokens are **single-use** and short-lived.
- **A token authorizes an identity, not just admission.** The name and addresses
  given to `enroll mint` are the only ones the issued certificate carries — in
  its subject as much as in its subject alternative names, because an attacker
  does not care which field a name it chose ends up in. An enrolling host may
  decline to use them; it cannot widen them, and asking to be enrolled under a
  different name is refused. Otherwise one valid token yields a CA-signed leaf
  for any name in the fleet, and mTLS stops meaning anything.
- **A registry label is not an identity.** A token minted without `--name` lets
  the enrolling host pick what the fleet registry calls it. That name is a
  label: it is echoed back as `assigned_name` and printed by `sandboxctl list`,
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
- **Pin the CA fingerprint.** Without `--ca-fingerprint`, enrollment trusts
  whatever certificate the control plane presents, and a network attacker can
  impersonate it. The installer warns when you omit it.

## Filesystem confinement

Paths are resolved to absolute form, symlinks are resolved, and only then is
containment under an allowed root checked.

Doing it in that order is the whole point. Checking for `..` in the requested
path before resolution is a jail that any symlink inside it walks straight out
of.

An agent configured with no allowed roots has no jail. It refuses to start that
way unless explicitly forced, and reports the condition in `sandbox_info`.

## Execution

- **argv, not a shell string.** Commands are exec'd directly. This removes a
  class of quoting and injection bugs, and it is the only thing that works
  uniformly across platforms — Windows has no `sh -c`. `shell: true` is opt-in.
- **Caps.** Wall-clock timeout, maximum output bytes, maximum concurrent
  supervised processes. Exceeded caps are reported to the caller, never silently
  applied: output that was truncated is always marked as truncated.
- **Command policy.** Optional per-agent allow and deny lists. The default is
  allow-all, which is honest about what the service is rather than implying a
  security boundary that a deny list does not actually provide.

## Audit

Every exec and every write appends a JSONL record: timestamp, authenticated
principal, argv or path, working directory, exit status. Append-only, rotated by
size.

This is a forensic record, not an enforcement mechanism. A caller who can
execute code on the host can also reach the audit file. Ship it off-host if it
needs to survive the host.

## Installer

`curl … | sh` is trust-on-first-use, and no amount of care inside the script
changes that. What the script does do:

- Verifies the artifact's SHA-256 against the checksum file published with the
  same release, and refuses to install on a mismatch.
- Supports `--ca-fingerprint` to pin the control plane.
- Warns when it is enrolling without pinning, or installing without a path jail.

Releases carry build provenance attestations. To skip the pipe entirely,
download the archive, verify it against `checksums.txt`, and run the binary
yourself.

## Reporting a vulnerability

Open a GitHub security advisory on this repository rather than a public issue.
