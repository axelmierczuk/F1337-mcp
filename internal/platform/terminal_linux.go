package platform

import "golang.org/x/sys/unix"

// The termios ioctls, which are spelled differently on Linux and on the BSDs
// macOS descends from. They are the only part of the Unix terminal handling
// that is not shared; see terminal_unix.go for the rest.
const (
	ioctlReadTermios  = unix.TCGETS
	ioctlWriteTermios = unix.TCSETS
)
