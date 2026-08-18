# End-to-end suite

Runs the product: a real CA, a real enrollment exchange over TLS, real mTLS
gRPC, two `fleet-agent` daemons in their own processes on different ports, and
`fleet-mcp` driven over stdio JSON-RPC the way an agent CLI drives it.

Every other test in this repository stops at a seam. This one crosses them.

```sh
make test-integration          # everything below that does not need Docker
make test-integration-docker   # the one scenario that does
```

Or directly:

```sh
go test -tags integration -race -count=1 ./test/...
go test -tags integration -count=1 -v -run TestTwoSandboxesTargeting ./test/e2e/
```

`make test-integration` passes `-race`: the product runs in its own processes,
so the detector never sees inside it, but the harness is concurrent code too and
should not be the one package here that races unwatched.

The suite is behind `//go:build integration`, so `go test ./...` never picks it
up. `make vet` and `make lint` do build it, under all three GOOSes — a tag that
hides a package from the test runner should not hide it from the checkers.
`make vet` names `testdata/helpers` explicitly for the same reason: the go tool
skips every directory under `testdata`, so no `./...` pattern had ever compiled
it, and the one file in it that exists purely for Windows was checked by nothing.

## What it needs

A Go toolchain, a loopback interface, and `curl`. No Docker, no root, no
network, no `sudo`: the workloads the scenarios run on a sandbox are built from
`testdata/helpers` at startup rather than borrowed from whatever `python3`
happens to be present.

`curl` is the one exception to "nothing installed beyond the toolchain", and it
is deliberate. The SOCKS proxy's acceptance criterion is written in terms of
`curl --socks5-hostname`, and a Go SOCKS client agreeing with a Go SOCKS server
proves considerably less than the client the criterion names. The scenarios that
use it **fail rather than skip** when it is absent, because a skip would report
success for a run that proved nothing. It ships on both platforms this suite
supports and on both CI runners it runs on.

The shell scenarios additionally need a pseudo-terminal, because they drive
`fleetctl shell` the way an operator does — the test allocates a terminal,
starts the command attached to it, and types into it. Every developer machine
and CI runner has one; a container built without `/dev/pts` does not, and those
scenarios skip there rather than failing.

It takes about twenty-five seconds.

## What runs without a container

Everything except one scenario.

| Scenario | What it proves |
| --- | --- |
| `TestEnrollConnectExecReadBack` | A host joins a fleet, is selected, answers `GetHostInfo`, runs a command, and the file that command wrote reads back through `FileService`. |
| `TestWriteEditReadRoundTrip` | Content survives write → edit → read unchanged, bytes included. |
| `TestToolSurfaceOverStdio` | All nineteen tools are visible to a client that speaks the protocol. |
| `TestTwoSandboxesTargeting` | A call runs on the sandbox that was selected, an explicit `sandbox` argument overrides it for that call only, and a handle resolves to the same host as its name. |
| `TestSelectionIsPerClientIdentity` | Two client identities hold different targets against one server at the same time. |
| `TestSelectionSurvivesAServerRestart` | The sticky default is persisted, not held in memory. |
| `TestDevServerReadinessForwardAndFetch` | The whole remote dev loop: readiness probe, port forward, HTTP GET over `localhost`. |
| `TestForwardRefusesAPortNothingIsServing` | A forward to a dead port is refused by the sandbox rather than opening a local listener that resets every connection. |
| `TestSocksProxyCarriesCurlThroughTheSandbox` | `fleetctl socks` + real `curl --socks5-hostname`: a fetch by a name the agent resolved, the audit record proving it crossed the wire unresolved, a destination outside `allowed_hosts` refused and recorded, and the listener unreachable from another machine. |
| `TestSocksIsRefusedByAnAgentThatDidNotOptIn` | Proxying is off until an operator turns it on, and the refusal names `forward.socks_enabled`. |
| `TestFleetSocksRefusesAnUnrestrictedAgent` | The same agent configuration that `fleetctl socks` serves, `fleet_socks` refuses — and the narrowed agent serves both. |
| `TestSocksProxyIsReleasedWithItsSandbox` | Deregistering a sandbox closes the proxy reaching through it, with the MCP server still running. |
| `TestProcessRestartKeepsItsIdentityAndComesBackReady` | A restart keeps the process id, passes its log-pattern probe again, serves again, keeps both runs' logs, and leaves the restart policy's budget alone. |
| `TestALogPatternProbeWatchesTheRunItIsProbing` | A restarted run that never prints the pattern is reported as not ready, rather than matching the previous run's announcement out of the retained log (#57). |
| `TestAReadoptedProcessIsReadyOnTheAnnouncementItAlreadyMade` | The other side of the same rule: a process re-adopted while it was still being probed is ready on the announcement it made to the agent that is gone, read out of the retained log rather than waited for again. |
| `TestAnAgentKilledWhileProbingHandsTheRunOver` | The same handover from an agent that was SIGKILLed rather than stopped, while a probe was outstanding and nothing since the spawn had written the record. |
| `TestProcessLogsFollowReturnsAtItsDeadline` | A following read of a process's logs is bounded. |
| `TestSupervisedProcessSurvivesAndIsReadoptedAfterAnAgentCrash` | A supervised process outlives a SIGKILLed agent, the next agent re-adopts it, its logs survive, capture resumes, and a stop still reaches it. |
| `TestStaleRecordIsOrphanedRatherThanSignalled` | A record whose pid exists but whose start identity does not match is orphaned, never signalled. |
| `TestExecTimeoutKillsTheWholeProcessTree` | A timed-out command's whole process group is gone, and a process outside it is untouched. |
| `TestExecTimeoutReportsWhatItDid` | A killed command comes back saying so, with the output it produced first. |
| `TestJailedAgentRejectsTraversal` | On an agent with exec disabled, a symlink out of the jail, a `..` traversal and an absolute path are all refused — and a refused write creates nothing. |
| `TestAgentRejectsForeignAndWrongProfileClientCertificates` | A leaf from another CA is refused, and so is an agent's own leaf used as a client certificate. |
| `TestEnrollmentRefusesWhatTheTokenDoesNotAuthorize` | A host cannot enroll as a name or an address its token does not authorize, and a spent token cannot be replayed. |
| `TestEnrollmentRequiresThePinnedFingerprint` | Enrollment refuses to proceed unpinned, and a wrong pin fails the handshake before the token is sent. |
| `TestARefusedEnrollmentKeepsItsToken` | A wrong `--name` and a mistyped `--address` are each refused on what they name, and the corrected command enrolls on the same token; single-use still holds afterwards. |
| `TestARefusedEnrollmentKeepsItsTokenWhenTheAgentAddsALoopbackName` | A loopback SAN the agent adds takes the leaf one name over the CA's limit; the refusal is correct and costs no token. |
| `TestARefusedEnrollmentKeepsItsTokenWhenACollisionLengthensTheName` | Collision resolution offers `<name>-2`, two bytes past the DNS label limit; the refusal is correct and costs no token. |
| `TestTheSANLimitThisSuiteAssumesIsTheOneTheCAEnforces` | Pins this suite's `maxLeafSANs` to the product through `enroll mint`, so raising `ca.MaxSANs` cannot leave the loopback scenario passing on an enrollment that was never refused. |
| `TestConcurrentCallsKeepTheirTargets` | Two dozen calls in flight across both sandboxes each run where they were aimed. |
| `TestListReportsAnUnreachableSandboxWithoutWaitingForIt` | A dead sandbox is reported dead in the same listing that still reports its neighbour live. |
| `TestFileSearchToolsWalkTheSandbox` | `fleet_ls`, `fleet_glob` and `fleet_grep` — the last of which is a server stream — over a real tree. |
| `TestExecIsAudited` | The exec reaches the audit log, attributed to the authenticated principal, with no output in it. |
| `TestShellRunsOnTheSelectedSandboxAndReturnsItsExitCode` | `fleetctl select`, then `fleetctl shell` on a real pseudo-terminal: the session runs on the selected host, and the remote shell's exit code becomes the CLI's own. |
| `TestShellSessionIsAuditedWithoutItsContents` | The session reaches the audit log with its principal, sandbox, start, duration and exit status — and neither what was typed nor what was printed appears there or in the agent's own log. |
| `TestShellCtrlCInterruptsTheRemoteProgramRatherThanTheClient` | Ctrl-C reaches the remote foreground process; the client survives it and the session keeps answering. |
| `TestShellResizeReflowsTheRemoteProgram` | Resizing the local terminal changes the size a program *inside* the session reads. |
| `TestShellClosingTheClientKillsTheRemoteTree` | Killing the client leaves no member of the session's process group alive, and does not touch a bystander. |
| `TestShellRefusesWhenStdinIsNotATerminal` | An interactive command run from a script is refused, with the tool that does the job named. |
| `TestShellCarriesTheOperatorsTerminalType` | The `TERM` the operator's shell has is the one a full-screen program inside the session reads. |
| `TestLargeFileTransferRoundTrips` | 24 MiB pushed and pulled back with matching digests, and a repeat push that moves nothing. |
| `TestTransferTreeRoundTrips` | A directory transfer with the default exclusions applied. |
| `TestTUIDrawsTheFleetAndGivesTheTerminalBack` | `fleetctl tui` on a real pseudo-terminal: both sandboxes and a supervised process drawn, one machine going away re-probed and drawn unreachable without blanking the view, and the terminal put back on quit. |
| `TestTUIGivesTheTerminalBackOnSIGTERM` | The same restoration on the exit path nobody chooses, reaching the view through the pid the operator's shell knows about. |
| `TestTUIWithoutATerminalSaysWhatToUseInstead` | A full-screen command whose stdout is a pipe is refused, naming the scriptable view. |
| `TestTheHandOffKeepsTheCommandLineAndTheProcess` | `fleetctl tui` reaches its helper as an exec — same pid the shell was given, the helper's own exit status — carrying the operator's flags verbatim, argument by argument. |
| `TestWithoutTheHelperTuiSaysWhatToInstallAndTheRestIsUnaffected` | An install with `fleetctl` alone: `tui` refuses naming the binary, where it looked and the line that installs it, `list` still works, and redirected output is still answered with the terminal refusal. |
| `TestAFleetctlInstalledAsItsOwnHelperRefusesInsteadOfLooping` | A fleetctl installed under its helper's name refuses, naming the mistake, instead of exec'ing itself for ever. |
| `TestAFleetctlCopiedToItsHelpersNameRefusesInsteadOfLooping` | The same mistake made with `cp` rather than a link — two files, nothing to compare in one process — refused after one hand-off rather than looping. |
| `TestNoCommandInterrogatesTheTerminalAtStartup` | On a pseudo-terminal that answers nothing, `fleetctl version` and `fleetctl list` write no background-colour query and no cursor-position request, and a line typed while they start is still in the input queue afterwards (#73). |

## What needs a container

One scenario: `TestExecTimeoutKillsTheWholeProcessTreeInContainer`. It skips
unless `FLEET_E2E_DOCKER=1`.

Outside a container, "the timeout left no survivors" is asserted against the
command's process group — the enumerable namespace available on a shared
machine. That is the right question and not quite the whole one: a process that
escaped its group by calling `setsid` would pass it. Inside a container the
claim is absolute, because the PID namespace holds nothing but this scenario:
every `/proc` entry is enumerated and none of them is running the workload.

The outer test runs `docker run` with the repository and the module cache
mounted, and re-enters this same suite inside the container to run the inner
half. Nothing here needs a published image or a Dockerfile.

It asserts on the inner run's `--- PASS: <scenario>` line, not on the word
`PASS`: `go test` prints a bare `PASS` and exits zero both for a run that
skipped everything and for a `-run` pattern that matched nothing, so the
cheaper check would report success for a container that ran no scenario at all.

The same hole exists one level up, and the assertion above cannot see it:
`make test-integration-docker` selects the outer scenario with `-run
InContainer`, free text that duplicates a test name with nothing tying the two
together, and an unmatched `-run` exits zero. `TestMain` closes it — with
`FLEET_E2E_DOCKER=1` set, a run in which no container scenario reported itself
fails. That is the only place it can be closed, because by the time any test
body runs the pattern has already decided which bodies there are.

## What is not covered

- **Windows sandboxes.** Every scenario skips on Windows: the workloads are
  POSIX (`sh -c`, `cat`, a process tree killed by group). The Windows-specific
  behaviour — job objects, `TerminateJobObject`, ConPTY sessions, path handling
  — has unit tests and runs on the CI matrix, but no scenario here drives a
  Windows agent. A run
  on Windows says so on stderr before it starts, because `go test` reports a
  package whose every test skipped as `ok` and an `ok` that ran nothing is worth
  more noise than that.
- **Two machines.** Both agents run on this machine, on different ports, with
  different `HOME` directories. That is what makes "it ran *there*" assertable
  at all: `fleet_exec` with no `working_dir` runs in the agent account's home
  directory, so identical argv reads a different file depending on which daemon
  forked it. A hostname would prove nothing when both daemons share one.
- **Real network conditions.** Everything is loopback: no latency, no packet
  loss, no severed connection mid-stream.
- **A host only the sandbox can see.** One machine, so the SOCKS scenarios
  cannot produce one. What they assert instead is the property that difference
  turns on: *where the destination name is resolved*. A proxy that resolved on
  the client would send an address in its CONNECT request, and the agent's audit
  record — written on the far side of a gRPC stream — would say `127.0.0.1`
  where the scenario requires `localhost`. Reverting the proxy to resolve
  locally turns it red.
- **A listener released by process exit.** "The MCP server or CLI exiting
  releases every listener" cannot fail here: a process that exits releases its
  listeners whether or not any code asked it to. `TestSocksProxyIsReleasedWithItsSandbox`
  asserts the half this suite can break — a listener released while the server
  keeps running — and `TestSocks_ServerCloseReleasesEveryListener` in
  `internal/mcpserver` pins the teardown itself, in-process, before the exit.
