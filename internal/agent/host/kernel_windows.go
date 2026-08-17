package host

import (
	"strconv"

	"golang.org/x/sys/windows"
)

// kernelVersion returns the OS version as major.minor.build.
//
// RtlGetVersion is used rather than GetVersionEx because the latter lies to
// processes without a matching compatibility manifest, reporting 6.2 on every
// Windows newer than 8.
func kernelVersion() string {
	v := windows.RtlGetVersion()
	if v == nil {
		return ""
	}
	return strconv.FormatUint(uint64(v.MajorVersion), 10) + "." +
		strconv.FormatUint(uint64(v.MinorVersion), 10) + "." +
		strconv.FormatUint(uint64(v.BuildNumber), 10)
}
