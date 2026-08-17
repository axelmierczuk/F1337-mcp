package platform

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// This file holds the /proc parsers as pure functions over bytes. They are
// only reachable in a Linux build, but keeping them free of syscalls means
// their tests run on every platform in CI rather than only on the Linux
// runner — and these parsers are where the interesting mistakes live.

// auxvClockTick is AT_CLKTCK.
const auxvClockTick = 17

// parseProcStatStartTicks extracts field 22 of /proc/<pid>/stat, the process
// start time in clock ticks since boot.
//
// Field 2 is the executable name in parentheses, and it is not escaped: a
// process named "foo (bar) baz" produces "1234 (foo (bar) baz) S 1 ...".
// Splitting the line on spaces and indexing is the classic way to read a
// completely wrong number here, and the number in question is what stops the
// supervisor from killing an unrelated process. Scan back from the last ')'
// instead.
func parseProcStatStartTicks(data []byte) (uint64, error) {
	commEnd := bytes.LastIndexByte(data, ')')
	if commEnd < 0 {
		return 0, errors.New("platform: /proc stat line has no comm field")
	}
	if !bytes.ContainsRune(data[:commEnd], '(') {
		return 0, errors.New("platform: /proc stat line has an unopened comm field")
	}

	// Fields after the comm start at field 3 (state), so field N is at index
	// N-3 of what follows.
	fields := strings.Fields(string(data[commEnd+1:]))
	const startTimeField = 22
	idx := startTimeField - 3
	if len(fields) <= idx {
		return 0, fmt.Errorf("platform: /proc stat line has %d fields after comm, need %d", len(fields), idx+1)
	}

	ticks, err := strconv.ParseUint(fields[idx], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("platform: parsing /proc stat start time %q: %w", fields[idx], err)
	}
	return ticks, nil
}

// parseProcStatBtime extracts the "btime" line from /proc/stat: the wall-clock
// second at which the system booted.
func parseProcStatBtime(data []byte) (int64, error) {
	for line := range strings.SplitSeq(string(data), "\n") {
		rest, ok := strings.CutPrefix(line, "btime ")
		if !ok {
			continue
		}
		secs, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("platform: parsing /proc/stat btime %q: %w", rest, err)
		}
		return secs, nil
	}
	return 0, errors.New("platform: /proc/stat has no btime line")
}

// parseAuxvClockTicks pulls AT_CLKTCK out of /proc/self/auxv, which is an
// array of native-word key/value pairs terminated by a zero key. Reading it
// avoids sysconf(3), which would mean cgo, and the agent builds with
// CGO_ENABLED=0.
//
// Words are 8 bytes and native-endian. Every Linux target in the agent's build
// matrix is 64-bit; the caller checks that before getting here, so a 32-bit
// port falls back to the default rather than reading this wrongly.
func parseAuxvClockTicks(data []byte) (uint64, bool) {
	const wordSize = 8
	const pair = wordSize * 2

	for off := 0; off+pair <= len(data); off += pair {
		key := binary.NativeEndian.Uint64(data[off : off+wordSize])
		val := binary.NativeEndian.Uint64(data[off+wordSize : off+pair])
		if key == 0 {
			return 0, false
		}
		if key == auxvClockTick && val > 0 {
			return val, true
		}
	}
	return 0, false
}

// parseMeminfo reads the /proc/meminfo keys the agent reports. Values are in
// kibibytes in the file and bytes in the result.
func parseMeminfo(data []byte) map[string]uint64 {
	out := make(map[string]uint64, 4)
	for line := range strings.SplitSeq(string(data), "\n") {
		key, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		v, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		if len(fields) > 1 && strings.EqualFold(fields[1], "kB") {
			v *= 1024
		}
		out[key] = v
	}
	return out
}

// parseLoadAverage1m reads the first field of /proc/loadavg.
func parseLoadAverage1m(data []byte) (float64, error) {
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, errors.New("platform: /proc/loadavg is empty")
	}
	load, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, fmt.Errorf("platform: parsing /proc/loadavg %q: %w", fields[0], err)
	}
	return load, nil
}
