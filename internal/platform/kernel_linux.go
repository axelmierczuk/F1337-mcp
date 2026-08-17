package platform

import (
	"strings"

	"golang.org/x/sys/unix"
)

// kernelVersion reports the release string from uname(2), for example
// "6.8.0-45-generic".
func kernelVersion() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return ""
	}
	return strings.TrimRight(string(u.Release[:]), "\x00")
}
