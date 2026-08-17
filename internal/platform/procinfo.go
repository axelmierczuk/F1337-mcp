package platform

import (
	"fmt"
	"time"
)

// ProcessInfo identifies a process that currently exists on this host.
type ProcessInfo struct {
	PID int

	// StartTime is the wall-clock instant the process started. It is for
	// display: on Linux it is derived from the boot time in /proc/stat, which
	// the kernel recomputes from the current wall clock, so an NTP step moves
	// it by however much the clock moved. Do not compare it for equality.
	StartTime time.Time

	// StartID is an opaque, platform-native encoding of the same instant, and
	// is the value to persist and compare.
	//
	// This distinction is the whole point of the type. The supervisor uses
	// start identity to decide whether a recorded pid still belongs to the
	// process it recorded, and adopting the wrong process means later
	// signalling something the agent does not own. A comparison that a clock
	// adjustment can break is not good enough for that.
	//
	// The encodings, all stable for the life of the process:
	//
	//   linux:<boot_id>:<jiffies>   field 22 of /proc/<pid>/stat, ticks since
	//                               boot, plus the kernel's boot id so a
	//                               record cannot survive a reboot and match a
	//                               new process by coincidence.
	//   darwin:<sec>.<usec>         kp_proc.p_starttime from
	//                               sysctl kern.proc.pid, recorded at exec and
	//                               never recomputed.
	//   windows:<filetime>          the creation FILETIME from
	//                               GetProcessTimes.
	//
	// Treat it as opaque: compare with SameProcess, never parse it.
	StartID string
}

// StatProcess returns identity for pid.
//
// It returns an error wrapping ErrProcessNotFound when no such process exists.
// A process that has exited but not been reaped still exists for this purpose
// — it still holds the pid, so it can still be confused with a later one.
func StatProcess(pid int) (ProcessInfo, error) { return statProcess(pid) }

// ProcessExists reports whether pid names a live process. Any failure to tell
// reads as false.
func ProcessExists(pid int) bool {
	_, err := StatProcess(pid)
	return err == nil
}

// SameProcess reports whether pid still refers to the process that produced
// startID.
//
// This is the pid-reuse guard. It is deliberately fail-closed: a read error, a
// missing process, or an empty startID all return false, because the cost of a
// wrong "yes" is the supervisor signalling an unrelated process — a database,
// on a host that runs one — and the cost of a wrong "no" is a supervised
// process marked ORPHANED and left alone.
func SameProcess(pid int, startID string) bool {
	if startID == "" {
		return false
	}
	info, err := StatProcess(pid)
	if err != nil {
		return false
	}
	return info.StartID == startID
}

// notFound wraps ErrProcessNotFound with the pid, for the per-platform
// implementations.
func notFound(pid int) error {
	return fmt.Errorf("platform: pid %d: %w", pid, ErrProcessNotFound)
}
