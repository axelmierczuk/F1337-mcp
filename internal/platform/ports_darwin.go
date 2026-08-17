package platform

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"time"
)

// lsofTimeout bounds the subprocess. A hung lsof must not hang a status call.
const lsofTimeout = 3 * time.Second

// listeningPorts shells out to lsof.
//
// The in-process alternative is proc_pidinfo with PROC_PIDFDSOCKETINFO, which
// lives in libproc and needs cgo. The agent builds with CGO_ENABLED=0 so it
// can be cross-compiled and dropped onto a host with no toolchain, and that
// trade is worth more than an exact port list. When lsof is missing the result
// is empty, which the doc comment on ListeningPorts says callers must tolerate.
func listeningPorts(pid int) ([]uint32, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("platform: invalid pid %d", pid)
	}
	if _, err := StatProcess(pid); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), lsofTimeout)
	defer cancel()

	// #nosec G204 -- the binary is a fixed literal and the only interpolated
	// value is a pid formatted from an int.
	cmd := exec.CommandContext(ctx, "lsof",
		"-nP", "-iTCP", "-sTCP:LISTEN", "-a", "-p", strconv.Itoa(pid), "-Fn")
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		// lsof exits 1 when the filter matched nothing, which is the common
		// case for a process that is not a server.
		if errors.As(err, &exitErr) {
			return parseLsofPorts(string(out)), nil
		}
		// Missing binary, or the timeout fired. Best effort: report nothing.
		return nil, nil
	}
	return parseLsofPorts(string(out)), nil
}
