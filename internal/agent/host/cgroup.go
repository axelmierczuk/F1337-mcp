package host

// The cgroup and /proc parsing the Linux resource probe is built on.
//
// It lives outside resources_linux.go, and outside a build tag, because it is
// pure file parsing: three formats across two cgroup hierarchies, with no
// syscall in any of it. Tagged for Linux it could only be exercised on the
// Linux runner, and there the real /sys/fs/cgroup cannot be made to report a
// limit from inside a test — so the parsing that decides what every
// container-confined agent advertises about itself would go untested
// everywhere. Untagged, a fixture tree exercises it on all three runners.

import (
	"bufio"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The kernel interfaces this file reads. They are variables rather than
// constants so the parsing — three file formats across two cgroup hierarchies,
// none of which exist on the macOS and Windows runners, and none of which can
// be provoked into reporting a limit on the Linux one — can be exercised
// against a fixture tree.
var (
	// cgroupRoot is where the unified hierarchy is mounted on every
	// distribution that has moved to cgroup v2, and where v1 controllers live
	// as subdirectories.
	cgroupRoot = "/sys/fs/cgroup"
	// procSelfCgroup names the cgroup this process is in, which is where a
	// systemd slice's limits live on a host that is not itself containerised.
	procSelfCgroup = "/proc/self/cgroup"
	procMeminfo    = "/proc/meminfo"
)

// unlimited is the floor above which a memory limit is a "no limit" sentinel
// rather than a machine.
//
// cgroup v1 spells "unlimited" as a number: PAGE_COUNTER_MAX scaled by the page
// size, which is 0x7FFFFFFFFFFFF000 on a 4 KiB-page host and
// 0x7FFFFFFFFFFF0000 on a 64 KiB-page arm64 one. Both are *just below* half of
// MaxUint64, so a threshold of MaxUint64/2 — the obvious one — lets them
// through and reports nine exabytes of RAM as the host's capacity. 4 EiB is
// four orders of magnitude above the largest machine anyone will run an agent
// on and far below either sentinel.
const unlimited = uint64(1) << 62

// cgroupCPUQuota returns the tightest CPU quota applying to this process, in
// cores, from either cgroup hierarchy.
func cgroupCPUQuota() (float64, bool) {
	best, found := math.Inf(1), false

	for _, dir := range cgroupDirs() {
		// v2: "cpu.max" holds "<quota> <period>", or "max <period>" when
		// unlimited.
		if fields, ok := readFields(filepath.Join(dir, "cpu.max")); ok && len(fields) == 2 && fields[0] != "max" {
			quota, qerr := strconv.ParseFloat(fields[0], 64)
			period, perr := strconv.ParseFloat(fields[1], 64)
			if qerr == nil && perr == nil && period > 0 && quota > 0 {
				if cores := quota / period; cores < best {
					best, found = cores, true
				}
			}
		}
		// v1: separate quota and period files under the cpu controller. A
		// quota of -1 means unlimited.
		quota, qok := readInt(filepath.Join(dir, "cpu.cfs_quota_us"))
		period, pok := readInt(filepath.Join(dir, "cpu.cfs_period_us"))
		if qok && pok && quota > 0 && period > 0 {
			if cores := float64(quota) / float64(period); cores < best {
				best, found = cores, true
			}
		}
	}
	return best, found
}

// readMeminfo reads the machine's memory totals. MemAvailable is the kernel's
// own estimate of what a new allocation could get, which is a far better
// answer than MemFree — page cache is reclaimable, and reporting it as used
// makes a healthy box look full.
func readMeminfo() (total, available uint64) {
	f, err := os.Open(procMeminfo) //nolint:gosec // a fixed kernel-provided path, indirected only for tests
	if err != nil {
		return 0, 0
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), ":")
		if !found {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		kb, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		switch key {
		case "MemTotal":
			total = kb * 1024
		case "MemAvailable":
			available = kb * 1024
		}
	}
	return total, available
}

// cgroupMemoryLimit returns the tightest memory limit applying to this
// process and the current usage under it.
func cgroupMemoryLimit() (limit, usage uint64, ok bool) {
	limit = math.MaxUint64

	for _, dir := range cgroupDirs() {
		for _, files := range [][2]string{
			{"memory.max", "memory.current"},                   // v2
			{"memory.limit_in_bytes", "memory.usage_in_bytes"}, // v1
		} {
			raw, found := readTrimmed(filepath.Join(dir, files[0]))
			if !found || raw == "max" {
				continue
			}
			value, err := strconv.ParseUint(raw, 10, 64)
			// v1 writes a sentinel rather than a word for "no limit", and
			// reporting that as the host's memory would be worse than
			// reporting nothing. See unlimited for why the threshold is not
			// the obvious MaxUint64/2.
			if err != nil || value == 0 || value >= unlimited {
				continue
			}
			if value < limit {
				limit, ok = value, true
				usage, _ = readUint(filepath.Join(dir, files[1]))
			}
		}
	}
	if !ok {
		return 0, 0, false
	}
	return limit, usage, true
}

// cgroupDirs returns the directories a limit for this process could be
// written in: the mount root, which is what a container namespace exposes, and
// the path named in /proc/self/cgroup, which is where a systemd slice's limits
// actually live on a host that is not itself containerised.
func cgroupDirs() []string {
	dirs := []string{cgroupRoot, filepath.Join(cgroupRoot, "cpu"), filepath.Join(cgroupRoot, "memory")}

	data, err := os.ReadFile(procSelfCgroup) //nolint:gosec // a fixed kernel-provided path, indirected only for tests
	if err != nil {
		return dirs
	}
	for _, line := range strings.Split(string(data), "\n") {
		// "hierarchy-id:controllers:path"; the unified hierarchy uses an empty
		// controller list and id 0.
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[2] == "" || parts[2] == "/" {
			continue
		}
		rel := strings.TrimPrefix(parts[2], "/")
		if parts[1] == "" {
			dirs = append(dirs, filepath.Join(cgroupRoot, rel))
			continue
		}
		for _, controller := range strings.Split(parts[1], ",") {
			if controller == "cpu" || controller == "memory" {
				dirs = append(dirs, filepath.Join(cgroupRoot, controller, rel))
			}
		}
	}
	return dirs
}

func readTrimmed(path string) (string, bool) {
	data, err := os.ReadFile(path) //nolint:gosec // fixed kernel-provided paths
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(data)), true
}

func readFields(path string) ([]string, bool) {
	text, ok := readTrimmed(path)
	if !ok {
		return nil, false
	}
	return strings.Fields(text), true
}

func readInt(path string) (int64, bool) {
	text, ok := readTrimmed(path)
	if !ok {
		return 0, false
	}
	value, err := strconv.ParseInt(text, 10, 64)
	return value, err == nil
}

func readUint(path string) (uint64, bool) {
	text, ok := readTrimmed(path)
	if !ok {
		return 0, false
	}
	value, err := strconv.ParseUint(text, 10, 64)
	return value, err == nil
}
