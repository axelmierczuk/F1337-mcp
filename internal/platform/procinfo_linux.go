package platform

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

// defaultClockTicks is the value of _SC_CLK_TCK on every Linux port Go
// supports. It is the fallback when /proc/self/auxv cannot be read or the port
// is not 64-bit.
const defaultClockTicks = 100

var (
	bootIDOnce sync.Once
	bootID     string

	clockTicksOnce sync.Once
	clockTicks     uint64

	bootTimeOnce sync.Once
	bootTime     time.Time
	bootTimeErr  error
)

func statProcess(pid int) (ProcessInfo, error) {
	if pid <= 0 {
		return ProcessInfo{}, fmt.Errorf("platform: invalid pid %d", pid)
	}

	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ProcessInfo{}, notFound(pid)
		}
		return ProcessInfo{}, fmt.Errorf("platform: reading /proc/%d/stat: %w", pid, err)
	}

	ticks, err := parseProcStatStartTicks(data)
	if err != nil {
		return ProcessInfo{}, err
	}

	info := ProcessInfo{
		PID:     pid,
		StartID: fmt.Sprintf("linux:%s:%d", readBootID(), ticks),
	}

	// The wall-clock conversion is best-effort and only feeds display. A
	// failure to read the boot time must not make the process unidentifiable.
	if boot, err := readBootTime(); err == nil {
		hz := readClockTicks()
		info.StartTime = boot.Add(time.Duration(float64(ticks) / float64(hz) * float64(time.Second)))
	}
	return info, nil
}

// readBootID returns the kernel's per-boot random identifier, so a persisted
// start id from before a reboot can never match a process after one. Ticks
// since boot restart from zero at every boot, and a low-pid process on a
// freshly booted machine can otherwise collide with a record from the previous
// boot exactly.
func readBootID() string {
	bootIDOnce.Do(func() {
		data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
		if err != nil {
			return
		}
		bootID = strings.TrimSpace(string(data))
	})
	return bootID
}

func readClockTicks() uint64 {
	clockTicksOnce.Do(func() {
		clockTicks = defaultClockTicks
		// The auxv reader assumes 8-byte words. Every Linux target the agent
		// ships for is 64-bit, and a 32-bit build takes the default rather
		// than misreading the vector.
		if unsafe.Sizeof(uintptr(0)) != 8 {
			return
		}
		data, err := os.ReadFile("/proc/self/auxv")
		if err != nil {
			return
		}
		if hz, ok := parseAuxvClockTicks(data); ok {
			clockTicks = hz
		}
	})
	return clockTicks
}

func readBootTime() (time.Time, error) {
	bootTimeOnce.Do(func() {
		data, err := os.ReadFile("/proc/stat")
		if err != nil {
			bootTimeErr = fmt.Errorf("platform: reading /proc/stat: %w", err)
			return
		}
		secs, err := parseProcStatBtime(data)
		if err != nil {
			bootTimeErr = err
			return
		}
		bootTime = time.Unix(secs, 0)
	})
	return bootTime, bootTimeErr
}
