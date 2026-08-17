package platform

import (
	"os"
	"runtime"
)

// Info describes the host the agent runs on. It mirrors the
// sandboxd.v1.Platform message field for field; the host service copies across
// rather than having this package depend on generated code.
type Info struct {
	// OS is the GOOS-style identifier: "linux", "darwin", "windows".
	OS string
	// Arch is the GOARCH-style identifier: "amd64", "arm64".
	Arch string
	// KernelVersion is best-effort and free-form. It is empty when the
	// platform read failed; that is not treated as an error, because a missing
	// kernel string is never a reason to refuse to serve.
	KernelVersion string
	// Hostname is the host-reported name, empty if the lookup failed.
	Hostname string
	// PathSeparator is "/" or "\\".
	PathSeparator string
}

// Describe returns the host description. It never fails: fields that could not
// be read are left empty.
func Describe() Info {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}
	return Info{
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		KernelVersion: kernelVersion(),
		Hostname:      hostname,
		PathSeparator: PathSeparator,
	}
}
