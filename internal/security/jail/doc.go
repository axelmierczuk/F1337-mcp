// Package jail confines filesystem access to a sandbox's allowed roots.
//
// Every path in every FileService and ExecService call passes through
// [Jail.Resolve] before a syscall touches it.
//
// # Order of operations
//
// Containment is checked after symlink resolution, never before:
//
//  1. Make the requested path absolute, against the jail's working directory.
//  2. Clean it lexically. This is what removes "..", and it is a normalisation
//     step, not a security check.
//  3. Resolve symlinks fully, walking up to the nearest existing ancestor when
//     the path itself does not exist yet.
//  4. Check the *resolved* result for containment under a root that was
//     itself resolved at construction.
//
// Rejecting ".." in the requested string is the classic way to build a jail
// that a symlink walks straight out of: /root/link -> /etc contains no "..",
// and /root/link/passwd passes a lexical check and reads /etc/passwd. The only
// path a containment check may be applied to is one the kernel has already
// finished resolving.
//
// # The race this does not close
//
// Resolve returns a path, and the caller then opens it. Those are two
// operations, and between them a component can be replaced with a symlink
// pointing anywhere. Nothing in the resolve-then-open shape can prevent that;
// a jail that claims otherwise is claiming an atomicity the syscalls do not
// have.
//
// [Jail.OpenFile] closes it where the kernel allows. On Linux it opens through
// openat2 with RESOLVE_BENEATH, which makes the kernel itself refuse to
// traverse out of the root, so no window exists between the check and the
// open. Everywhere else — and on Linux kernels before 5.6, or under a seccomp
// filter that blocks the syscall — it falls back to Resolve followed by an
// ordinary open, and the window is real. [Jail.Atomic] reports which of the
// two the caller got.
//
// The window is small and requires an attacker who can already create symlinks
// inside the jail. It is documented rather than closed because the alternative
// is a portable reimplementation of path resolution over openat, which trades
// a narrow race for a wide surface of subtle bugs.
//
// # No jail
//
// An empty root list is not "allow everything". [New] refuses it, the zero
// value of Jail refuses every path, and a nil *Jail refuses every path. The
// only way to run without confinement is [Unconfined], which an operator must
// ask for explicitly and which the agent reports in fleet_info.
//
// # What this cannot do
//
// The jail decides which paths may be used. It does not, and cannot, decide
// which bytes are reachable, because the filesystem has ways of putting
// outside content at an inside path that no amount of path resolution
// distinguishes from ordinary files:
//
//   - A hard link inside a root to a file outside it is the same inode. There
//     is no path to resolve; the file simply is in both places.
//   - A bind mount, or any mount, grafts another filesystem in at a path
//     inside a root, and every path under it resolves to something contained.
//   - Anything running under the agent's own uid can reach the same files
//     directly, without going through the jail at all.
//
// None of these is a bug to be fixed here. They are the reason docs/security.md
// says the agent is hardening rather than isolation, and the reason the jail's
// roots should be directories the operator controls.
package jail
