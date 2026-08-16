// Package jail confines filesystem access to a sandbox's allowed roots.
//
// Containment is checked after symlink resolution, not before: rejecting ".."
// in the requested path is the classic way to build a jail that a symlink walks
// straight out of.
//
// Implemented by milestone M1.
package jail
