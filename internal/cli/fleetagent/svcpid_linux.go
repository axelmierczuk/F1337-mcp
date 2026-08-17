package fleetagent

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
)

// systemdUnitName is the unit this binary asks systemd about.
//
// It is a constant rather than a parameter because there is exactly one unit
// this command can legitimately query: its own. Taking a name would mean the
// argv handed to systemctl depended on something a caller chose, and the only
// honest way to keep that safe would be to validate it back down to this. The
// constant is the constraint, expressed where it cannot drift.
const systemdUnitName = ServiceName + ".service"

// servicePID asks systemd for the unit's main PID.
//
// kardianos/service reports only running or stopped, so the PID comes from the
// service manager directly. A zero MainPID means systemd knows the unit but is
// not running it.
func servicePID() (int, bool) {
	// Bounded: `service status` is what an installer script branches on, and a
	// systemd or D-Bus that has stopped answering must make the PID unavailable
	// rather than make the command hang.
	ctx, cancel := context.WithTimeout(context.Background(), servicePIDTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "systemctl", "show", "-p", "MainPID", "--value", systemdUnitName).Output()
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}
