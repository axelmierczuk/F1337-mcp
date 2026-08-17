package host

import "golang.org/x/sys/unix"

// kernelVersion returns the Darwin kernel release, e.g. "24.5.0". It is the
// kernel version rather than the marketing version because that is what the
// proto documents the field as, and it is the one available without shelling
// out to sw_vers.
func kernelVersion() string {
	release, err := unix.Sysctl("kern.osrelease")
	if err != nil {
		return ""
	}
	return release
}
