package platform

import (
	"strconv"

	"golang.org/x/sys/windows"
)

// kernelVersion reports the OS version as "major.minor.build", for example
// "10.0.22631". RtlGetVersion is used rather than GetVersionEx because the
// latter lies to processes without a matching compatibility manifest.
func kernelVersion() string {
	v := windows.RtlGetVersion()
	if v == nil {
		return ""
	}
	return strconv.FormatUint(uint64(v.MajorVersion), 10) + "." +
		strconv.FormatUint(uint64(v.MinorVersion), 10) + "." +
		strconv.FormatUint(uint64(v.BuildNumber), 10)
}
