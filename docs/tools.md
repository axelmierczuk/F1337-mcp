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
| `argv` | string[] | **Required.** Executable and arguments. Not shell-parsed. `argv[0]` is looked up in the effective `PATH` — the one the command will run with, not the daemon's — and never in the working directory. |
| `working_dir` | string | An ordinary path: exec and the path jail are mutually exclusive, so there are no roots to resolve it against. Must exist and be a directory. Defaults to the agent account's home directory. |
| `env` | string[] | `KEY=VALUE`. Applied over a documented base environment, not over the daemon's own. An entry replaces the base entry with the same name. |
| `timeout_seconds` | int | SIGTERM to the process **group** on expiry, then SIGKILL after the grace period. On Windows there is no catchable equivalent, so the job object is terminated at the first step. Defaults to 120s, matching the agent's own default so that a timeout report names the limit that actually bit. Above the agent's `exec.max_timeout` the call is refused, naming the maximum, rather than quietly shortened. On a saturated agent the timeout bounds the wait for a free process slot and then the command itself, so a queued call can take up to twice it — the RPC deadline allows for that, so a hung agent still cannot hold the call open. Anything over a week is refused by the tool before the call is made: the deadline is derived from this number, and a large enough one wraps it into a deadline that has already passed. |
| `max_output_bytes` | int | Beyond this, output is truncated and marked. Defaults to 128 KiB: the agent's ceiling is sized for a program reading output, this default for a model reading it in context. Above the agent's `exec.max_output_bytes` it is clamped to it — the truncation in the result is what reports that. The MCP server keeps its own 8 MiB ceiling on one result whatever this says, and when that is the cap that bit the truncation note says so rather than pointing at this argument. |
| `shell` | bool | Run through the platform shell (`sh -c`, or `cmd /c` on Windows). Opt-in, because it reintroduces shell parsing of untrusted strings. The command policy then sees the shell, not the command inside it. |
| `stdin` | string | Written to stdin, which is then closed. |

Returns `exit_code`, `stdout`, `stderr`, `duration_ms`, `timed_out`, `signal`,
`truncation` and `note`. The exit code leads, before either stream, because it
decides what the rest of the result means. stdout and stderr stay separate:
merging them makes the model hunt for the one sentence that matters. A command
that wrote to neither is reported as having produced no output, in words —
a blank result is otherwise indistinguishable from a hung call.

**A command that fails is a successful call.** A non-zero exit is reported in
`exit_code`; the tool errors for a request the agent would not run at all — an
`argv[0]` that names nothing executable, a working directory that is not one, a
cap exceeded, or a command the agent's policy refuses.

**An error does not always mean nothing ran.** Two of them arrive after the
command has already done its work, and a caller that reads every error as "the
request was rejected" will retry something that ran: the agent could not write
the call's audit record while `audit.required` is set, so the result is
withheld rather than reported unrecorded; and the caller stopped reading its
own output stream, so the agent killed the command and ended the call rather
than holding the RPC open. Both say which they are in the error message. Treat
either as "this may well have run".

**Output over the cap does not stop the command.** The agent keeps reading and
discarding, so a command that produces a gigabyte finishes and reports what it
exited with, rather than blocking on a full pipe until the timeout.

For anything that should keep running after the call returns, use
`sandbox_process_start`. Exec takes its process tree with it: descendants still
running when the command exits are killed with it.

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
| `ready_probe` | object | Exactly one of `log_pattern`, `tcp_port`, `http_get_url`, `uptime_seconds`, plus `timeout_seconds`. |
| `wait_for_ready` | bool | Block until the probe passes. Defaults to **true whenever `ready_probe` is set**. |
| `restart_policy` | enum | `never` (default), `on_failure`, `always`. |
| `max_restarts` | int | |
| `replace_existing` | bool | Stop and replace a process with the same name. |

Returns the process status, and `ready_error` **plus `recent_logs`** if the probe
did not pass in time. A process that fails its probe is left running so its logs
can be read; stopping it is the caller's decision. The logs come back with the
failure because otherwise the model's next move is always another tool call.

Refused with `PermissionDenied` on an agent configured with
`exec.enabled: false`: starting a supervised process runs a command, and that
is the one configuration where `allowed_roots` is a real boundary.

**Use a ready probe.** Without one, "started" only means "spawned". A dev server
that needs eight seconds to bind will refuse the connection the model makes one
second later, and the model will conclude the server is broken.

`ready_probe` is a flat object with one condition set and no discriminator to
get wrong. Setting none, or setting two, is refused with a message naming the
four. It is the highest-leverage schema in this group: a model that cannot
construct the probe omits it, and omitting it is the failure the feature exists
to prevent. `wait_for_ready` defaults to true when a probe is present for the
same reason — a probe that is configured and not waited on is no probe at all.

### `sandbox_process_list`
All tracked processes, including exited ones not yet reaped.

| Argument | Type | Notes |
| --- | --- | --- |
| `states` | string[] | Filter by state. |
| `name_pattern` | string | RE2 filter on name. |

Returns `table`, the listing rendered as fixed-width columns, plus `processes`,
the same listing structured. The table is the field to read: twenty processes
are legible in it in a way twenty JSON objects are not, and staying legible at
twenty is the point — a listing that needs a follow-up call to understand has
failed.

```
STATE       NAME     PID    UPTIME  RST  PORTS      LAST LOG
ready       web-dev  41221  3m12s   0    3000       ready in 812ms - http://localhost:3000
ready       api      41230  3m10s   2    8080,9229  listening on :8080
running     worker   41244  2m58s   0    -          picked up job 4471
crashed(1)  migrate  -      41s     0    -          relation "users" does not exist
```

Each structured entry: `process_id`, `name`, `command`, `state`, `pid`,
`started_at`, `uptime`, `exit_code`, `restart_count`, `last_log_line`,
`listening_ports`, and `adoption_note` when the agent had to reason about
whether the process survived a daemon restart. The process id is not a column —
it is long, uniform, and would cost more than the rest of the table put
together; the name is what a reader scans by. A process that has exited reports
no pid, because something else owns that number now.

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
| `follow_seconds` | int | Bound on following, default 20. Clamped to the agent's maximum. |

Following is **always bounded**. A call that never returns cannot be
distinguished from a hung agent, and the model cannot recover from it. A process
producing no output at all still returns at the deadline, with
`follow_deadline_reached` set.

Returns `logs`, one rendered block, plus `lines_returned`, `lines_dropped`,
`follow_deadline_reached`, `state` and `truncation`. In the block:

```
> vite dev
  VITE v5.4.2  ready in 812 ms
E| warn: 'sass' is deprecated, use 'sass-embedded'
--- 1834 line(s) dropped: the process outran the log buffer ---
hmr update /src/App.tsx
S| supervisor: restarting in 1s (restart 1 of 5)
```

stdout is unprefixed, because it is the common case and a prefix on it is paid
for on every line. stderr is `E| `. Lines the supervisor itself wrote — a
restart, a backoff, a decision to give up, an adoption note — are neither
`stdout` nor `stderr` and are marked `S| `, so asking for one of those streams
returns only what the process said.

Dropped lines are marked **inline, in sequence**, so a gap in the log is visible
rather than silent: two lines that were never adjacent must not read as though
they were. A line longer than the agent's per-line cap is split rather than
dropped, and every piece but the last ends in ` [+]`.

The block is capped. Past the cap the oldest lines go and the omission is stated
at the top of what is left, as well as in `truncation`.

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

A graceful stop returns `escalated_to_kill`: true means the process did not exit
within `grace_seconds` of SIGTERM and was killed, so it flushed nothing. Signal
and restart calls against a `process_id` the agent does not have fail with the
ids it does have, each with its name and state — an error the model can act on
rather than one that costs it a list call.

### `sandbox_process_restart`
Stop and start again from the same spec, optionally waiting for readiness.

| Argument | Type | Notes |
| --- | --- | --- |
| `process_id` | string | **Required.** |
| `grace_seconds` | int | |
| `wait_for_ready` | bool | Defaults to true. |

The `process_id` is preserved and so is the log history: a restart is the same
process, not a similar one. `restart_count` is deliberately **not** incremented
— it is the supervisor's automatic-restart budget, and restarting by hand must
not spend the recovery the policy is holding in reserve.

---

## Files

### `sandbox_read`
| Argument | Type | Notes |
| --- | --- | --- |
| `path` | string | **Required.** |
| `offset` | int | Starting line, 1-based. |
| `limit` | int | Maximum lines. Defaults to 2000, and the result says so whenever the file continues past the window. |
| `raw` | bool | Return the bytes, base64-encoded, rather than text. Required for binaries. |

Returns line-numbered content plus metadata, in the shape of the built-in Read:
the line number right-aligned in six columns, a tab, then the line. Binary
files are detected and reported rather than mangled into text.

`total_lines` is exact only when `total_lines_exact` is set. Counting lines
means reading every byte, so the agent stops at a size bound rather than reading
a gigabyte to answer a windowed read; past that bound the number reports how far
the count got. Do not render "line 40 of N" without checking the flag.

Line endings are never rewritten. A CRLF file reads back with its CRLF intact,
on every platform. The numbered rendering drops the carriage return, since a
stray one mid-result is noise a model will either ignore or copy into its next
argument, and the result says the file uses CRLF instead — which is what an
exact-match `sandbox_edit` afterwards has to account for.

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
unified diff, trimmed to a few lines of context around each change, and a line
too long to print is trimmed around the change rather than shown whole — the
diff is bounded so that editing a minified file returns something a model can
read rather than the file twice.

The **result** is bounded too, not only the file. `replace_all` with a
`new_string` longer than `old_string` multiplies, so an edit whose output would
exceed the agent's edit ceiling is refused before anything is written; rewrite
the file with `sandbox_write`, which streams.

Line endings are preserved. A `new_string` whose endings disagree with the
file's is refused rather than mixed in, and an `old_string` that fails to match
only because of them says so.

### `sandbox_ls`
`path`, `recursive`, `include_hidden`, `limit` (default 500).

Directories come back as a list of names and files as name, size and age, in
that order — two short lists rather than one table of mostly-empty columns.
Names are relative to the directory listed, which is named once.

### `sandbox_glob`
`pattern` (e.g. `**/*.go`), `root`, `limit` (default 300), `respect_gitignore`,
`include_default_ignored`.

The pattern is anchored at `root`: `*.go` does not recurse and `**/*.go` does.
Results are files, sorted by modification time, newest first, and given as
absolute paths so they can be passed straight to `sandbox_read`. `.git`,
`node_modules`, `vendor` and `target` are skipped unless
`include_default_ignored` is set.

### `sandbox_grep`
`pattern` (RE2), `root`, `include_glob`, `case_insensitive`, `context_lines`,
`max_matches`, `files_only`, `respect_gitignore`, `include_default_ignored`.

Matches are rendered one per line in grep's own shape — `path:line: text` for a
match, `path-line- text` for a context line, which is the only thing telling
the two apart once they are in a flat list.

`include_glob` uses gitignore semantics rather than the anchored ones of
`sandbox_glob`: `*.go` matches at any depth. `max_matches` defaults to 100 and
stops the walk rather than truncating a finished search, so the summary's
`files_searched` reports how little of the tree was read, and the truncation
note says so rather than letting "truncated" be read as "that is all of them".

A matched line that is not valid UTF-8 comes back with the offending bytes shown
as U+FFFD rather than failing the search: the binary check reads only the head of
a file, so a log with one stray byte in the middle of it is still a text file.

Executed on the agent, so searching a large tree does not stream the tree across
the network first.

---

## Bridge

### `sandbox_transfer`
Move files and directories between the workstation and a sandbox.

| Argument | Type | Notes |
| --- | --- | --- |
| `direction` | enum | **Required.** `push` (local → sandbox) or `pull`. |
| `source` | string | **Required.** Local for `push`, on the sandbox for `pull`. |
| `destination` | string | **Required.** An existing directory receives the source under its own name, as `cp` does. |
| `recursive` | bool | Required to transfer a directory rather than a single file. |
| `exclude` | string[] | Extra glob patterns, added to the defaults. Matched against each path segment and against the path relative to `source`. A pattern that cannot be evaluated is refused rather than silently matching nothing. |
| `force` | bool | Re-send files the unchanged check would skip. |
| `allow_outside_working_dir` | bool | Permit a `pull` to write outside this workstation's working directory. |

This is how a local repository gets onto a sandbox in the first place.

**The local side has no jail.** The sandbox has an agent deciding what a caller
may touch; this side has nothing but the user's own filesystem, so a `pull`
writes only under the working directory of the process serving these tools
unless `allow_outside_working_dir` says otherwise. Containment is decided on
the resolved path, so a symlink inside the working directory pointing at `/` is
not a way out of it. A `push` **source** is not confined: a caller that can
reach this tool can already read any local file with its own built-in tools, so
confining reads would add friction and no safety.

**Symlinks are never followed out of the tree.** On a push, a link resolving
inside `source` is followed — a repository full of them would otherwise
transfer as a tree of holes — and one resolving outside is skipped and named in
the result. On a pull every link is skipped and named, because `ReadFile`
follows links agent-side and deciding whether the target is inside the tree
would mean resolving a remote path from here. A pull whose `source` *is* a link
is refused for the same reason, naming what it points at: the metadata
describing a link is the link's own, so following it would land the target's
contents under the link's name, with the link's size and the link's mode.

**A pulled name cannot leave the destination.** The names in a pulled tree come
from the sandbox, and `..\..\x` is an ordinary filename on Linux — the
normalisation that lets a Windows sandbox's `cmd\app\main.go` mean
`cmd/app/main.go` would otherwise turn it into a way out of the directory the
caller named, and past two levels out of the working directory. Every entry is
checked three ways: the name **as written** must stay under the destination
root, and the path it **resolves to** must stay under that root *and* under the
working directory. So a subdirectory of the destination that is a symlink is not
a way out either — neither one pointing out of the working directory, nor one
pointing at a sibling inside it, which would otherwise land the file somewhere
the result then reported it had not gone. Entries that fail any of the three are
skipped and reported; the rest arrive.

**Defaults, caps and repeats.** `.git`, `.hg`, `.svn`, `node_modules`,
`vendor`, `target`, `dist`, `build`, virtualenv and cache directories are
excluded by default, applied only *below* the source root so naming `.git` as
the source still transfers it; the result reports how many entries were
excluded, so it is never silent. One call moves at most 5000 files or 256 MiB,
refused up front naming the limit rather than abandoned half way — including a
single file over the byte cap, which is the shape with no walk to accumulate it.
A file whose
size matches and whose destination is no older is skipped as unchanged — rsync's
quick check, minus the modification time this protocol has no field to preserve
— which makes push, edit, push again cost only what changed. `force` overrides
it. Executable bits are preserved in both directions. A pull writes through a
temporary file and renames, so an interrupted transfer leaves nothing at the
destination rather than a partial file every later reader treats as whole. A
read the sandbox cut short, or one that ends without saying whether it finished,
fails the transfer rather than committing the prefix under the real name.

Each file's own RPC deadline scales with its size rather than using the deadline
sized for a question, so the cap above is a size a transfer can actually reach
on a link slower than a laboratory's. The same applies to `sandbox_write`.

### `sandbox_forward`
Forward a sandbox port to the workstation. **This is `ssh -L`.**

```
sandbox_forward(remote_port=3000, local_port=3000)
  ==  ssh -L 3000:localhost:3000 sandbox
```

| Argument | Type | Notes |
| --- | --- | --- |
| `remote_port` | int | **Required.** Port on the sandbox. |
| `local_port` | int | 0 (the default) picks a free port and reports it. |
| `remote_host` | string | Defaults to loopback on the sandbox. |
| `stop` | bool | Tear down the forward for this `remote_port`. |

Returns `local_address`, plus `active_forwards`: every forward this MCP server
holds, on every sandbox, in the result of **every** call — so the model can see
what is already open without a tool that does nothing else.

Closes the remote dev loop: start a server with `sandbox_process_start`, forward
its port, then reach it over `localhost` exactly as if it were local.

**Not implemented, deliberately.** There is no reverse forward (`ssh -R`) and no
dynamic SOCKS proxy (`ssh -D`). The `ssh -L` framing above is the right mental
model precisely because it is exact, and it would stop being useful if the two
modes it does not cover were left ambiguous.

**Lifetime is owned by the MCP server, not by the call.** A forward stays open
across unrelated tool calls until `stop: true` or the MCP server exits; the
server releases every local listener on the way out, so a port cannot be held
by a process that is gone.

**Loopback on both ends.**

- The **local** listener binds `127.0.0.1` only. Binding every interface would
  publish a tunnel into the sandbox to everyone on the workstation's network.
- `remote_host` defaults to the sandbox's own loopback, and anything else is
  refused unless the operator listed it in `forward.allowed_hosts` in the agent
  config. An agent that will connect anywhere on request is a general-purpose
  pivot into whatever network it sits in, usable by anyone who can reach it —
  and forwarding a dev server works identically without that capability, so
  nothing legitimate notices the restriction. The check resolves the requested
  host and requires *every* address it resolves to to be loopback, then dials
  the address that passed.

**Non-loopback connections are audited.** Every connection to a target that is
not the sandbox's own loopback appends a line to the agent's audit log —
succeeded, refused, or failed — carrying the principal, the requested host and
port, the address actually dialed, and the bytes each way. Never the bytes
themselves. Loopback forwards are not recorded. See
[security.md](security.md#the-pivot-surface).

The sandbox-side port is checked before a local listener is opened, so a
forward pointed at a port nothing is serving fails with an error naming it,
rather than leaving a local port that accepts connections and then drops them.
