//go:build windows

package fleetctl

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
)

// execHelper runs the helper as a child and reports its status as this
// command's own.
//
// Windows has no exec, so unlike every other platform there is a second process
// here, and the two things that costs have to be paid explicitly. The first is
// the exit code, carried out through [exitStatus] the way `fleetctl shell`
// carries a remote shell's. The second is Ctrl-C: a console delivers it to
// every process attached to it, so without the Ignore below this process would
// end on the first Ctrl-C and hand the console back to the shell while a
// full-screen program was still drawing on it. The helper installs its own
// handler and puts the terminal back; this process's job is to wait until it
// has.
func execHelper(path string, args []string) error {
	cmd := exec.Command(path, args...) //nolint:gosec // path is fleetctl's own helper, located by findHelper
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	signal.Ignore(os.Interrupt)

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return &exitStatus{what: helperName, code: exitErr.ExitCode()}
		}
		return fmt.Errorf("run %s: %w", path, err)
	}
	return nil
}
