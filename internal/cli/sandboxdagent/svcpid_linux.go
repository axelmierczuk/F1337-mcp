package sandboxdagent

import (
	"os/exec"
	"strconv"
	"strings"
)

// servicePID asks systemd for the unit's main PID.
//
// kardianos/service reports only running or stopped, so the PID comes from the
// service manager directly. A zero MainPID means systemd knows the unit but is
// not running it.
func servicePID(name string) (int, bool) {
	out, err := exec.Command("systemctl", "show", "-p", "MainPID", "--value", name+".service").Output()
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}
