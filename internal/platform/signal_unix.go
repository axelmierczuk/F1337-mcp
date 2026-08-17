//go:build unix

package platform

import (
	"os"
	"syscall"
)

var unixSignals = map[Signal]syscall.Signal{
	SignalTerm: syscall.SIGTERM,
	SignalKill: syscall.SIGKILL,
	SignalInt:  syscall.SIGINT,
	SignalHup:  syscall.SIGHUP,
	SignalUSR1: syscall.SIGUSR1,
	SignalUSR2: syscall.SIGUSR2,
}

func (s Signal) osSignal() (os.Signal, error) {
	sig, ok := unixSignals[s]
	if !ok {
		return nil, ErrSignalUnsupported
	}
	return sig, nil
}
