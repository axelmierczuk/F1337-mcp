//go:build linux || darwin

package fleetagent

import "time"

// servicePIDTimeout bounds the query `status` makes of the platform's service
// manager.
//
// Linux and macOS answer it by running systemctl or launchctl, which is the one
// thing `status` does that leaves this process. A wedged service manager or a
// D-Bus that stopped answering must make the PID unavailable, not make the
// command hang: `status` is what an operator runs to find out what is wrong, and
// what an installer script branches on.
//
// It lives here rather than beside the other timeouts because Windows queries
// the SCM through an API instead and has no use for it.
const servicePIDTimeout = 5 * time.Second
