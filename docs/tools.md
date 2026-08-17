# Tool reference

Nineteen tools. Conventions that apply to all of them:

- **Targeting.** Every tool below the Fleet group accepts an optional `sandbox`
  argument (name or handle) that overrides the sticky selection. With neither an
  argument nor a default, the call fails with a structured error listing the
  available sandboxes.
- **Echo.** Every result includes `sandbox`, the name of the host that actually
  served the call.
- **Truncation is explicit.** Any capped output carries
  `{truncated, bytes_omitted, lines_omitted}`. Output is never silently cut.
- **Paths** are absolute on the sandbox, or relative to its configured working
  directory. They are resolved through the path jail before use — on an agent
  with `exec.enabled: false`, which is the only configuration where the jail is
  wired in. With exec enabled, one `sandbox_exec` call reaches any path the
  agent's account can, so there are no allowed roots and the tools report none.
  See [security.md](security.md#filesystem-confinement).

---

## Fleet

### `sandbox_list`
Inventory of registered sandboxes.

| Argument | Type | Notes |
| --- | --- | --- |
| `refresh` | bool | Probe health live instead of returning cached status. |
| `label` | string | Filter by `key=value`. |

Returns name, platform, health, labels, agent version, last-seen time, and which
one is currently selected.

### `sandbox_select`
Choose the default target for subsequent calls.

| Argument | Type | Notes |
| --- | --- | --- |
| `name` | string | **Required.** Sandbox name. |

Returns a handle, plus the resolved host's platform and allowed roots — so the
model learns where it can write without a second call. An agent whose jail is
off returns no roots, which is the honest answer: it can write anywhere its
account can.

An agent that enforces no path jail returns `unconfined: true` and no
`allowed_roots`. That is "every path is writable", not "none is": the path jail
and `ExecService` are mutually exclusive, because a caller with exec can write
anywhere its user can regardless of the roots, so the jail is enforced only on
an agent with exec disabled. The flag is explicit rather than implied by an
absent list, which reads the wrong way round.

### `sandbox_add`
Register an already-enrolled agent that is not in the local registry.

| Argument | Type | Notes |
| --- | --- | --- |
| `name` | string | **Required.** |
| `address` | string | **Required.** `host:port`. |
| `labels` | object | Free-form `key=value`, bounded: at most 32, keys printable ASCII with no spaces. |

Does not enroll. Enrollment mints credentials and is an operator action via
`sandboxctl`.

Name, address and labels are all validated before the registry is touched, so a
rejected call leaves nothing behind. Labels are bounded because they are paid
for twice: in the registry file, and in every `sandbox_list` result.

### `sandbox_remove`
Deregister a sandbox locally. Does not uninstall the agent.

| Argument | Type | Notes |
| --- | --- | --- |
| `name` | string | **Required.** Sandbox name or handle. |

Clears the sticky selection of **every** client pointing at it, not just the
caller's — a selection left aimed at a sandbox that no longer exists is worse
than no selection.

### `sandbox_info`
Full detail for one sandbox: platform, kernel, CPU and memory, disk, detected
toolchains, allowed roots, agent version and uptime, running process count.
Reports `unconfined: true` for an agent with no path jail, on the same terms as
`sandbox_select`.

| Argument | Type | Notes |
| --- | --- | --- |
| `sandbox` | string | Name or handle. Defaults to the current selection. |
| `include_toolchains` | bool | Probes the filesystem; measurably slower. |

---

## Execute

### `sandbox_exec`
Run a command to completion.

| Argument | Type | Notes |
| --- | --- | --- |
| `argv` | string[] | **Required.** Executable and arguments. Not shell-parsed. |
| `working_dir` | string | Must resolve inside an allowed root. |
| `env` | string[] | `KEY=VALUE`. Applied over a documented base environment, not over the daemon's own. |
| `timeout_seconds` | int | SIGTERM on expiry, then SIGKILL after the grace period. |
| `max_output_bytes` | int | Beyond this, output is truncated and marked. |
| `shell` | bool | Run through the platform shell. Opt-in. |
| `stdin` | string | Written to stdin, which is then closed. |

Returns `exit_code`, `stdout`, `stderr`, `duration_ms`, `timed_out`,
`truncation`.

For anything that should keep running after the call returns, use
`sandbox_process_start`.

---

## Background processes

### `sandbox_process_start`
Spawn a supervised process.

| Argument | Type | Notes |
| --- | --- | --- |
| `argv` | string[] | **Required.** |
| `name` | string | **Required.** Label, e.g. `web-dev`. Must be unique among running processes unless `replace_existing`. |
| `working_dir` | string | |
| `env` | string[] | |
| `ready_probe` | object | One of `log_pattern`, `tcp_port`, `http_get_url`, `uptime_seconds`, plus `timeout_seconds`. |
| `wait_for_ready` | bool | Block until the probe passes, up to its timeout. |
| `restart_policy` | enum | `never` (default), `on_failure`, `always`. |
| `max_restarts` | int | |
| `replace_existing` | bool | Stop and replace a process with the same name. |

Returns the process status, and `ready_error` if the probe did not pass in time.
A process that fails its probe is left running so its logs can be read; stopping
it is the caller's decision.

**Use a ready probe.** Without one, "started" only means "spawned". A dev server
that needs eight seconds to bind will refuse the connection the model makes one
second later, and the model will conclude the server is broken.

### `sandbox_process_list`
All tracked processes, including exited ones not yet reaped.

| Argument | Type | Notes |
| --- | --- | --- |
| `states` | string[] | Filter by state. |
| `name_pattern` | string | RE2 filter on name. |

Each entry: `process_id`, `name`, `argv`, `state`, `pid`, `started_at`,
`exit_code`, `restart_count`, `last_log_line`, `listening_ports`, and
`adoption_note` when the agent had to reason about whether the process survived
a daemon restart.

### `sandbox_process_logs`
Buffered output, optionally following new output.

| Argument | Type | Notes |
| --- | --- | --- |
| `process_id` | string | **Required.** |
| `stream` | enum | `stdout`, `stderr`, or both interleaved. |
| `tail_lines` | int | |
| `since` | timestamp | |
| `filter_pattern` | string | RE2. |
| `follow` | bool | Stream new output after the replay. |
| `follow_seconds` | int | Bound on following. Clamped to the agent's maximum. |

Following is **always bounded**. A call that never returns cannot be
distinguished from a hung agent, and the model cannot recover from it.

Dropped lines are reported inline as `dropped_before`, so a gap in the log is
visible rather than silent. A line longer than the agent's per-line cap is split
rather than dropped, and every piece but the last carries `continued`.

Lines the supervisor itself wrote — a restart, a backoff, a decision to give up,
an adoption note — are tagged as neither `stdout` nor `stderr`, so asking for one
of those streams returns only what the process said.

### `sandbox_process_signal`
Signal or stop a process.

| Argument | Type | Notes |
| --- | --- | --- |
| `process_id` | string | **Required.** |
| `signal` | enum | `TERM`, `KILL`, `INT`, `HUP`, `USR1`, `USR2`. |
| `graceful_stop` | bool | TERM, wait, then KILL. Overrides `signal`. |
| `grace_seconds` | int | |
| `process_group` | bool | Default true. |
| `disable_restart` | bool | Stop the restart policy from undoing an intentional stop. |

`process_group` defaults to true because signalling only the leader routinely
leaves orphans behind — the bundler under `npm run dev` keeps the port. On
Windows the agent terminates the job object instead of delivering a POSIX
signal.

### `sandbox_process_restart`
Stop and start again from the same spec, optionally waiting for readiness.

---

## Files

### `sandbox_read`
| Argument | Type | Notes |
| --- | --- | --- |
| `path` | string | **Required.** |
| `offset` | int | Starting line, 1-based. |
| `limit` | int | Maximum lines. |
| `raw` | bool | Return bytes rather than text. Required for binaries. |

Returns line-numbered content plus metadata. Binary files are detected and
reported rather than mangled into text.

### `sandbox_write`
| Argument | Type | Notes |
| --- | --- | --- |
| `path` | string | **Required.** |
| `content` | string | **Required.** |
| `create_parents` | bool | |
| `fail_if_exists` | bool | |
| `append` | bool | |

Written to a temporary file and renamed into place, so an interrupted write
cannot leave a truncated file behind.

### `sandbox_edit`
| Argument | Type | Notes |
| --- | --- | --- |
| `path` | string | **Required.** |
| `old_string` | string | **Required.** Exact match; whitespace is significant. |
| `new_string` | string | **Required.** |
| `replace_all` | bool | |

With `replace_all` false, the edit **fails unless `old_string` matches exactly
once**. This mirrors the contract of the agent's built-in edit tool, which is
what makes the remote version feel native — and the uniqueness requirement is
what stops an ambiguous match from quietly editing the wrong line. Returns a
unified diff.

### `sandbox_ls`
`path`, `recursive`, `include_hidden`, `limit`.

### `sandbox_glob`
`pattern` (e.g. `**/*.go`), `root`, `limit`, `respect_gitignore`.

### `sandbox_grep`
`pattern` (RE2), `root`, `include_glob`, `case_insensitive`, `context_lines`,
`max_matches`, `files_only`, `respect_gitignore`.

Executed on the agent, so searching a large tree does not stream the tree across
the network first.

---

## Bridge

### `sandbox_transfer`
Move files and directories between the workstation and a sandbox.

| Argument | Type | Notes |
| --- | --- | --- |
| `direction` | enum | **Required.** `push` (local → sandbox) or `pull`. |
| `source` | string | **Required.** |
| `destination` | string | **Required.** |
| `recursive` | bool | |
| `exclude` | string[] | Glob patterns to skip. |

This is how a local repository gets onto a sandbox in the first place.

### `sandbox_forward`
Forward a sandbox port to the workstation.

| Argument | Type | Notes |
| --- | --- | --- |
| `remote_port` | int | **Required.** |
| `local_port` | int | 0 picks a free port. |
| `remote_host` | string | Defaults to loopback on the sandbox. |
| `stop` | bool | Tear down an existing forward. |

Returns the local address. Defaulting `remote_host` to loopback keeps the agent
from being turned into a general-purpose network pivot by accident.

Closes the remote dev loop: start a server with `sandbox_process_start`, forward
its port, then reach it over `localhost` exactly as if it were local.
