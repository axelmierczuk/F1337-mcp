package platform

import (
	"fmt"
	"os"
	"strings"
)

// Signal is the portable signal vocabulary the agent exposes. It mirrors
// sandboxd.v1.SignalProcessRequest.Signal so the service layer can translate
// with a switch and nothing else.
//
// Only SignalTerm, SignalKill and SignalInt have a Windows meaning. The rest
// return ErrSignalUnsupported there rather than being quietly mapped onto a
// termination, because a caller asking for SIGHUP wants a reload, and killing
// the process instead is the worst possible interpretation of that request.
type Signal uint8

const (
	// SignalUnspecified is the zero value and is never valid to send.
	SignalUnspecified Signal = iota
	// SignalTerm asks a process to shut down. On Windows it terminates the
	// job, because there is nothing to ask.
	SignalTerm
	// SignalKill compels termination and cannot be caught.
	SignalKill
	// SignalInt is an interrupt. On Windows it becomes CTRL_BREAK_EVENT.
	SignalInt
	// SignalHup is the reload convention. Unix only.
	SignalHup
	// SignalUSR1 is application-defined. Unix only.
	SignalUSR1
	// SignalUSR2 is application-defined. Unix only.
	SignalUSR2
)

var signalNames = map[Signal]string{
	SignalUnspecified: "UNSPECIFIED",
	SignalTerm:        "TERM",
	SignalKill:        "KILL",
	SignalInt:         "INT",
	SignalHup:         "HUP",
	SignalUSR1:        "USR1",
	SignalUSR2:        "USR2",
}

// String returns the bare signal name without the "SIG" prefix, matching the
// spelling used in ProcessStatus.signal.
func (s Signal) String() string {
	if name, ok := signalNames[s]; ok {
		return name
	}
	return fmt.Sprintf("Signal(%d)", uint8(s))
}

// Valid reports whether s is a signal that can be sent.
func (s Signal) Valid() bool {
	_, ok := signalNames[s]
	return ok && s != SignalUnspecified
}

// ParseSignal accepts "TERM", "SIGTERM" or "term" and returns the
// corresponding Signal.
func ParseSignal(name string) (Signal, error) {
	upper := strings.ToUpper(strings.TrimSpace(name))
	upper = strings.TrimPrefix(upper, "SIG")
	for sig, n := range signalNames {
		if n == upper && sig != SignalUnspecified {
			return sig, nil
		}
	}
	return SignalUnspecified, fmt.Errorf("platform: unknown signal %q", name)
}

// OSSignal translates s into the os.Signal to pass to os.Process.Signal.
//
// On Windows this always fails: os/exec cannot deliver POSIX signals there, and
// pretending otherwise produces a call that silently does nothing. Use
// ProcessGroup.Signal, which terminates the job object instead.
func (s Signal) OSSignal() (os.Signal, error) { return s.osSignal() }
