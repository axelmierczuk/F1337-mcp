package sandboxdagent

import (
	"os/exec"
	"strconv"
	"strings"
)

// servicePID reads the job's PID from launchctl.
//
// `launchctl list <label>` prints a plist-ish block whose PID key is present
// only while the job is running.
func servicePID(name string) (int, bool) {
	out, err := exec.Command("launchctl", "list", name).Output()
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(out), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(strings.Trim(key, "\t \"")) != "PID" {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(strings.Trim(value, " ;")))
		if err != nil || pid <= 0 {
			return 0, false
		}
		return pid, true
	}
	return 0, false
}
