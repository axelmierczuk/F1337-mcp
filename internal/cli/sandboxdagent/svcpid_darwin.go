package sandboxdagent

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
)

// servicePID reads the job's PID from launchctl.
//
// `launchctl list <label>` prints a plist-ish block whose PID key is present
// only while the job is running. The label is the package constant, not a
// parameter: there is one job this command may ask about, and that is the one
// it registered.
func servicePID() (int, bool) {
	// Bounded for the same reason as the systemd query: `service status` must
	// answer even when the service manager does not.
	ctx, cancel := context.WithTimeout(context.Background(), servicePIDTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "launchctl", "list", ServiceName).Output()
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
