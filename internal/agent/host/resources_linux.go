package host

import (
	"bufio"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// cgroupRoot is where the unified hierarchy is mounted on every distribution
// that has moved to cgroup v2, and where v1 controllers live as
// subdirectories.
const cgroupRoot = "/sys/fs/cgroup"

func platformResources(diskPath string) Resources {
	res := Resources{
		CPUCores:      cpuCores(),
		LoadAverage1m: loadAverage1m(),
	}
	res.MemoryTotalBytes, res.MemoryAvailableBytes = memory()
	res.DiskTotalBytes, res.DiskAvailableBytes = disk(diskPath)
	return res
}

// cpuCores returns the effective core count: the smaller of the machine's
// visible CPUs and any cgroup CPU quota in force.
//
// runtime.NumCPU is a floor, not the answer. A container limited to 0.5 CPU
// still sees every core on the host, and an agent that advertises them will be
// handed a parallel build that thrashes for the whole quota period.
func cpuCores() uint32 {
	cores := float64(runtime.NumCPU())
	if quota, ok := cgroupCPUQuota(); ok && quota < cores {
		cores = quota
	}
	// Round up: a 0.5-CPU quota is still a host that can run one thing at a
	// time, and reporting zero cores would read as "cannot run anything".
	rounded := math.Ceil(cores)
	if rounded < 1 {
		rounded = 1
	}
	return uint32(rounded)
}

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

// memory returns total and available bytes, clamped by any cgroup memory
// limit.
func memory() (total, available uint64) {
	total, available = procMeminfo()

	if limit, usage, ok := cgroupMemoryLimit(); ok {
		if limit < total || total == 0 {
			total = limit
		}
		// Headroom inside the cgroup is the limit minus what the cgroup is
		// already using, which is a tighter and more truthful bound than the
		// kernel's host-wide MemAvailable.
		var headroom uint64
		if limit > usage {
			headroom = limit - usage
		}
		if headroom < available || available == 0 {
			available = headroom
		}
	}
	return total, available
}

// procMeminfo reads the machine's memory totals. MemAvailable is the kernel's
// own estimate of what a new allocation could get, which is a far better
// answer than MemFree — page cache is reclaimable, and reporting it as used
// makes a healthy box look full.
func procMeminfo() (total, available uint64) {
	f, err := os.Open("/proc/meminfo")
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
			// v1 writes a sentinel close to the 64-bit maximum for "no limit"
			// rather than a word, and reporting that as the host's memory
			// would be worse than reporting nothing.
			if err != nil || value == 0 || value >= math.MaxUint64/2 {
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

	data, err := os.ReadFile("/proc/self/cgroup")
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

func disk(path string) (total, available uint64) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, 0
	}
	size := uint64(stat.Bsize) //nolint:gosec // block size is a small positive value
	return stat.Blocks * size, stat.Bavail * size
}

func loadAverage1m() float64 {
	fields, ok := readFields("/proc/loadavg")
	if !ok || len(fields) == 0 {
		return 0
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return value
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
