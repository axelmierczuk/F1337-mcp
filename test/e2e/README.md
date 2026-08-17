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

## What it needs

A Go toolchain and a loopback interface. No Docker, no root, no network, no
`sudo`, nothing installed on the machine beyond the toolchain: the workloads
the scenarios run on a sandbox are built from `testdata/helpers` at startup
rather than borrowed from whatever `python3` happens to be present.

It takes about twenty seconds.

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
| `TestProcessRestartKeepsItsIdentityAndComesBackReady` | A restart keeps the process id, passes its log-pattern probe again, serves again, keeps both runs' logs, and leaves the restart policy's budget alone. |
| `TestALogPatternProbeMatchesThePreviousRunsOutput` | Records a defect, not a requirement. See the comment on the test. |
| `TestProcessLogsFollowReturnsAtItsDeadline` | A following read of a process's logs is bounded. |
| `TestSupervisedProcessSurvivesAndIsReadoptedAfterAnAgentCrash` | A supervised process outlives a SIGKILLed agent, the next agent re-adopts it, its logs survive, capture resumes, and a stop still reaches it. |
| `TestStaleRecordIsOrphanedRatherThanSignalled` | A record whose pid exists but whose start identity does not match is orphaned, never signalled. |
| `TestExecTimeoutKillsTheWholeProcessTree` | A timed-out command's whole process group is gone, and a process outside it is untouched. |
| `TestExecTimeoutReportsWhatItDid` | A killed command comes back saying so, with the output it produced first. |
| `TestJailedAgentRejectsTraversal` | On an agent with exec disabled, a symlink out of the jail, a `..` traversal and an absolute path are all refused — and a refused write creates nothing. |
| `TestAgentRejectsForeignAndWrongProfileClientCertificates` | A leaf from another CA is refused, and so is an agent's own leaf used as a client certificate. |
| `TestEnrollmentRefusesWhatTheTokenDoesNotAuthorize` | A host cannot enroll as a name or an address its token does not authorize, and a spent token cannot be replayed. |
| `TestEnrollmentRequiresThePinnedFingerprint` | Enrollment refuses to proceed unpinned, and a wrong pin fails the handshake before the token is sent. |
| `TestARefusedEnrollmentSpendsItsToken` | Records a defect, not a requirement. See the comment on the test. |
| `TestNoShippedCommandIssuesTheControlLeaf` | Records a defect, not a requirement: no command produces the control certificate `fleet-mcp` presents, so a server built by the documented flow reaches no agent. Pins the workaround this suite uses. See the comment on the test. |
| `TestConcurrentCallsKeepTheirTargets` | Two dozen calls in flight across both sandboxes each run where they were aimed. |
| `TestListReportsAnUnreachableSandboxWithoutWaitingForIt` | A dead sandbox is reported dead in the same listing that still reports its neighbour live. |
| `TestFileSearchToolsWalkTheSandbox` | `fleet_ls`, `fleet_glob` and `fleet_grep` — the last of which is a server stream — over a real tree. |
| `TestExecIsAudited` | The exec reaches the audit log, attributed to the authenticated principal, with no output in it. |
| `TestLargeFileTransferRoundTrips` | 24 MiB pushed and pulled back with matching digests, and a repeat push that moves nothing. |
| `TestTransferTreeRoundTrips` | A directory transfer with the default exclusions applied. |

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
  behaviour — job objects, `TerminateJobObject`, path handling — has unit tests
  and runs on the CI matrix, but no scenario here drives a Windows agent. A run
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
- **The MCP server's own credentials, end to end.** `fleetctl ca sign --profile
  control` signs the control leaf, but nothing in the product produces the CSR
  it signs, so the harness builds that one artifact itself. See the PR body
  for #28.
