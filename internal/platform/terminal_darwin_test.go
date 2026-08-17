package platform_test

import "golang.org/x/sys/unix"

// testReadTermios is the BSD spelling of "read a terminal's settings". See
// terminal_unix_test.go.
const testReadTermios = uint(unix.TIOCGETA)
