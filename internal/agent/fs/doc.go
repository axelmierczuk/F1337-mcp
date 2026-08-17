// Package fs implements FileService: read, write, edit, list, stat, glob,
// grep, and the three path-management RPCs — make directory, remove and move.
//
// # Confinement
//
// Every path this package touches goes through the [jail.Jail] handed to [New],
// and that jail is the only thing deciding what is reachable. It is a single
// injected dependency rather than a flag threaded through the handlers: an
// agent with no confinement is built with [jail.Unconfined], which normalises
// paths and permits all of them, so no handler here asks whether a jail exists
// and none of them can be wrong about the answer.
//
// Whether the jail confines anything is the daemon's decision, not this
// package's. An agent with ExecService enabled — the default — hands out an
// unconfined jail, because a caller who can run `sh -c 'echo x > /etc/passwd'`
// reaches any path without FileService, and a path check that stops nobody
// while looking like a security control is worse than no check. See
// internal/agent.jailFor and docs/security.md. Nothing in this package claims
// confinement it does not have: an unconfined jail returns no rejection, so no
// handler here can report one.
//
// A path-management RPC acts on the path itself rather than on what it points
// at, so RemovePath and MovePath resolve only the *parent* through the jail and
// leave the last component exactly as the caller wrote it. Removing a symlink
// unlinks the symlink; it never follows one to delete the file at the other
// end, which is the classic way a delete leaves its confinement.
//
// # Writes
//
// Every write in this package — WriteFile and EditFile alike — goes through
// [atomicFile]: a temp file in the same directory as the target, fsynced, then
// renamed over it. The temp file is a sibling rather than a file in the system
// temp directory because rename is only atomic within a filesystem; across one,
// it is a copy, and a copy interrupted halfway is exactly the truncated file
// this exists to prevent. An interrupted transfer removes the temp file and
// leaves the original untouched.
//
// # Streaming
//
// ReadFile and WriteFile stream in bounded chunks and never hold a whole file
// in memory; a 100 MB transfer costs a chunk buffer, not 100 MB of heap.
// EditFile is the exception and has to be — an exact-match replacement needs
// the whole file — so it refuses files over [DefaultMaxEditBytes].
package fs
