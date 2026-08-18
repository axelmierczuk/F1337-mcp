package platform

import "golang.org/x/sys/unix"

// See terminal_linux.go: the same two ioctls, under the BSD names.
//
// TIOCSETA rather than TIOCSETAF or TIOCSETAW: it applies the new settings
// immediately, where the other two drain or flush the terminal's queues first.
// Draining would make entering raw mode wait on output nobody is reading yet,
// and flushing would discard whatever the operator typed while the session was
// being set up.
const (
	ioctlReadTermios  = unix.TIOCGETA
	ioctlWriteTermios = unix.TIOCSETA
)
