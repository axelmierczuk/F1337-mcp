package platform

import (
	"io/fs"
	"math"
	"path"
	"strconv"
	"strings"
)

// cgroupRoot is where the unified hierarchy is mounted on any distribution
// that uses systemd, which is all of them that matter here.
const cgroupRoot = "sys/fs/cgroup"

// cgroupLimits holds the effective cgroup v2 limits for a process: the
// smallest limit set anywhere between its own cgroup and the root.
type cgroupLimits struct {
	// MemoryMax is the memory ceiling in bytes, or zero for "max".
	MemoryMax uint64
	// MemoryCurrent is current charged usage in bytes, valid only when
	// MemoryMax is non-zero.
	MemoryCurrent uint64
	// CPUQuota and CPUPeriod come from cpu.max. Both zero means "max".
	CPUQuota  uint64
	CPUPeriod uint64
}

// EffectiveCores converts a CPU quota into a whole number of cores, rounding
// up: a 1.5-core quota is reported as 2, because a build that wants two
// parallel jobs can usefully run them, just slower. Zero means unlimited.
func (l cgroupLimits) EffectiveCores() uint32 {
	if l.CPUQuota == 0 || l.CPUPeriod == 0 {
		return 0
	}
	cores := math.Ceil(float64(l.CPUQuota) / float64(l.CPUPeriod))
	if cores < 1 {
		return 1
	}
	if cores > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(cores)
}

// readCgroupLimits walks from the process's own cgroup up to the root of the
// unified hierarchy, taking the tightest limit found at any level.
//
// Walking up is not optional. cgroup v2 limits are enforced hierarchically, so
// a container whose own memory.max says "max" can still be capped by its
// parent slice, and an agent that reads only its own leaf will happily accept
// a build that the kernel then OOM-kills.
//
// fsys is rooted at "/". Everything is best effort: a host with no cgroup v2,
// or a v1-only host, yields a zero cgroupLimits and no error, because "no
// limits found" and "limits are unlimited" produce the same behaviour.
func readCgroupLimits(fsys fs.FS) cgroupLimits {
	rel, ok := readSelfCgroup(fsys)
	if !ok {
		return cgroupLimits{}
	}

	var out cgroupLimits
	for dir := rel; ; dir = path.Dir(dir) {
		full := path.Join(cgroupRoot, dir)

		if limit, current, ok := readMemoryLimit(fsys, full); ok {
			if out.MemoryMax == 0 || limit < out.MemoryMax {
				out.MemoryMax = limit
				out.MemoryCurrent = current
			}
		}
		if quota, period, ok := readCPULimit(fsys, full); ok {
			if out.CPUQuota == 0 || quota*out.CPUPeriod < out.CPUQuota*period {
				out.CPUQuota, out.CPUPeriod = quota, period
			}
		}

		if dir == "/" || dir == "." || dir == "" {
			break
		}
	}
	return out
}

// applyCgroupLimits narrows res to the container's allowance. It only ever
// tightens: a cgroup cannot grant more memory than the machine has, so a limit
// above physical memory is ignored rather than reported.
//
// It lives here, away from the Linux-only reader, so its tests run everywhere.
func applyCgroupLimits(res *Resources, limits cgroupLimits) {
	if cores := limits.EffectiveCores(); cores > 0 && cores < res.CPUCores {
		res.CPUCores = cores
		res.CPUQuotaLimited = true
	}
	if limits.MemoryMax > 0 && (res.MemoryTotalBytes == 0 || limits.MemoryMax < res.MemoryTotalBytes) {
		res.MemoryTotalBytes = limits.MemoryMax
		res.MemoryLimited = true

		var avail uint64
		if limits.MemoryCurrent < limits.MemoryMax {
			avail = limits.MemoryMax - limits.MemoryCurrent
		}
		if res.MemoryAvailableBytes == 0 || avail < res.MemoryAvailableBytes {
			res.MemoryAvailableBytes = avail
		}
	}
	if res.CPUCores == 0 {
		res.CPUCores = 1
	}
}

// readSelfCgroup returns the process's path within the unified hierarchy.
//
// /proc/self/cgroup holds one line per hierarchy; the v2 line is the one with
// an empty controller list, "0::/path". Inside a cgroup namespace the path is
// "/" and the limits sit at the mount root, which the caller's path join
// handles without a special case.
func readSelfCgroup(fsys fs.FS) (string, bool) {
	data, err := fs.ReadFile(fsys, "proc/self/cgroup")
	if err != nil {
		return "", false
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "0::"); ok {
			if rest == "" {
				rest = "/"
			}
			return rest, true
		}
	}
	return "", false
}

func readMemoryLimit(fsys fs.FS, dir string) (limit, current uint64, ok bool) {
	limit, ok = readCgroupUint(fsys, path.Join(dir, "memory.max"))
	if !ok || limit == 0 {
		return 0, 0, false
	}
	current, _ = readCgroupUint(fsys, path.Join(dir, "memory.current"))
	return limit, current, true
}

// readCPULimit parses cpu.max, which is "$QUOTA $PERIOD" with QUOTA either a
// number of microseconds or the literal "max".
func readCPULimit(fsys fs.FS, dir string) (quota, period uint64, ok bool) {
	data, err := fs.ReadFile(fsys, path.Join(dir, "cpu.max"))
	if err != nil {
		return 0, 0, false
	}
	fields := strings.Fields(string(data))
	if len(fields) != 2 || fields[0] == "max" {
		return 0, 0, false
	}
	quota, err = strconv.ParseUint(fields[0], 10, 64)
	if err != nil || quota == 0 {
		return 0, 0, false
	}
	period, err = strconv.ParseUint(fields[1], 10, 64)
	if err != nil || period == 0 {
		return 0, 0, false
	}
	return quota, period, true
}

// readCgroupUint reads a single-value cgroup file. The literal "max" means no
// limit and is reported as zero, not as a parse failure.
func readCgroupUint(fsys fs.FS, name string) (uint64, bool) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return 0, false
	}
	text := strings.TrimSpace(string(data))
	if text == "max" || text == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
