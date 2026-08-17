package host

import (
	"bytes"

	"golang.org/x/sys/unix"
)

// kernelVersion returns the running kernel's release string, e.g. "6.8.0-45-generic".
func kernelVersion() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return ""
	}
	return string(bytes.TrimRight(uts.Release[:], "\x00"))
}
