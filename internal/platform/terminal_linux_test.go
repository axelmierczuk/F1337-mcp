package platform_test

import "golang.org/x/sys/unix"

// testReadTermios is the Linux spelling of "read a terminal's settings". See
// terminal_unix_test.go.
const testReadTermios = uint(unix.TCGETS)
