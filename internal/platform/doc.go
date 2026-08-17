// Package platform isolates the OS-specific behaviour the agent depends on:
// process groups versus Windows job objects, PTY allocation, signal
// translation, process introspection, path normalisation, and resource
// reporting.
//
// Everything here is selected by //go:build file suffix rather than by a
// runtime.GOOS branch. That is deliberate: a runtime branch still has to
// compile on every platform, so the syscall and x/sys imports it needs leak
// into builds that cannot use them, and the Windows build breaks on a change
// that only touched Linux. The exported surface is identical on every
// platform; operations with no meaning on a platform return ErrUnsupported
// rather than silently doing nothing.
//
// # What the agent uses this for
//
//   - Spawning a child that can be killed as a tree, via [ProcessGroup].
//   - Deciding whether a recorded pid still refers to the process the agent
//     started, via [StatProcess] and [SameProcess] — see the start-identity
//     discussion on [ProcessInfo].
//   - Reporting host capacity that respects container limits, via
//     [ReadResources].
//   - Comparing and normalising paths under the platform's own rules, which
//     is what internal/security/jail builds its containment check on.
//
// Nothing in this package imports the generated protobuf types. [Info] and
// [Resources] mirror the shapes of sandboxd.v1.Platform and
// sandboxd.v1.Resources; the service layer copies fields across.
package platform
