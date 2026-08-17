package platform

import (
	"io/fs"
	"math"
	"path"
	"strconv"
	"strings"
)

// cgroupRoot is where the unified hierarchy is mounted, and where each v1
// hierarchy is mounted as a subdirectory named after its controller set.
const cgroupRoot = "sys/fs/cgroup"

// cgroupLimits holds the effective cgroup limits for a process: the smallest
// limit set anywhere between its own cgroup and the root, in whichever
// hierarchy carries the controller.
type cgroupLimits struct {
	// MemoryMax is the memory ceiling in bytes, or zero for no limit.
	MemoryMax uint64
	// MemoryCurrent is current charged usage in bytes, valid only when
	// MemoryMax is non-zero.
	MemoryCurrent uint64
	// CPUQuota and CPUPeriod are a quota and the period it applies over. Both
	// zero means no limit.
	CPUQuota  uint64
	CPUPeriod uint64
}

// tightenWith narrows l to whichever of the two limits binds first.
//
// A controller lives on exactly one hierarchy at a time, so on a real host only
// one side of each comparison is ever set. Taking the tighter of the two costs
// nothing and means a hybrid host — v1 for memory, v2 for cpu, or the reverse —
// needs no special case.
func (l *cgroupLimits) tightenWith(other cgroupLimits) {
	if other.MemoryMax > 0 && (l.MemoryMax == 0 || other.MemoryMax < l.MemoryMax) {
		l.MemoryMax = other.MemoryMax
		l.MemoryCurrent = other.MemoryCurrent
	}
	if other.CPUQuota > 0 && other.CPUPeriod > 0 &&
		(l.CPUQuota == 0 || other.CPUQuota*l.CPUPeriod < l.CPUQuota*other.CPUPeriod) {
		l.CPUQuota, l.CPUPeriod = other.CPUQuota, other.CPUPeriod
	}
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

// readCgroupLimits reports the limits in force for this process, from whichever
// cgroup hierarchy carries each controller.
//
// Which hierarchy that is, is read rather than assumed. /proc/self/cgroup names
// every hierarchy the process is in: a "0::" line for the unified hierarchy and
// one "id:controllers:path" line per v1 hierarchy. A host may be v2-only,
// v1-only, or hybrid with memory on one and cpu on the other, and all three
// fall out of reading that file and then reading only the files that exist.
//
// fsys is rooted at "/". Everything is best effort: a host with no cgroups at
// all yields a zero cgroupLimits and no error, because "no limits found" and
// "limits are unlimited" produce the same behaviour.
func readCgroupLimits(fsys fs.FS) cgroupLimits {
	out := readCgroupLimitsV2(fsys)
	out.tightenWith(readCgroupLimitsV1(fsys))
	return out
}

// readCgroupLimitsV2 walks from the process's own cgroup up to the root of the
// unified hierarchy, taking the tightest limit found at any level.
//
// Walking up is not optional. cgroup limits are enforced hierarchically, so a
// container whose own memory.max says "max" can still be capped by its parent
// slice, and an agent that reads only its own leaf will happily accept a build
// that the kernel then OOM-kills.
func readCgroupLimitsV2(fsys fs.FS) cgroupLimits {
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

// readCgroupLimitsV1 does the same for the v1 hierarchies.
//
// v1 limits are inherited down the tree exactly as v2's are — a parent's
// memory.limit_in_bytes caps every descendant — so the walk up is the same, and
// omitting it would miss the common case of a container whose own leaf sets
// nothing under a slice that does.
//
// What differs is where the files are, what they are called, and how each
// spells "no limit". A v1 hierarchy is mounted at a directory named after its
// controller set, so a process on line "3:cpu,cpuacct:/foo" reads
// sys/fs/cgroup/cpu,cpuacct/foo — with sys/fs/cgroup/cpu the conventional
// symlink to it, tried as a fallback because a container image may present only
// one of the two.
func readCgroupLimitsV1(fsys fs.FS) cgroupLimits {
	controllers := readSelfCgroupV1(fsys)

	var out cgroupLimits
	for _, mount := range controllers["memory"] {
		for dir := mount.rel; ; dir = path.Dir(dir) {
			if limit, current, ok := readMemoryLimitV1(fsys, path.Join(mount.dir, dir)); ok {
				if out.MemoryMax == 0 || limit < out.MemoryMax {
					out.MemoryMax = limit
					out.MemoryCurrent = current
				}
			}
			if dir == "/" || dir == "." || dir == "" {
				break
			}
		}
	}
	for _, mount := range controllers["cpu"] {
		for dir := mount.rel; ; dir = path.Dir(dir) {
			if quota, period, ok := readCPULimitV1(fsys, path.Join(mount.dir, dir)); ok {
				if out.CPUQuota == 0 || quota*out.CPUPeriod < out.CPUQuota*period {
					out.CPUQuota, out.CPUPeriod = quota, period
				}
			}
			if dir == "/" || dir == "." || dir == "" {
				break
			}
		}
	}
	return out
}

// implausibleMemory is the ceiling above which a memory limit is a sentinel
// rather than a machine.
//
// cgroup v2 spells "no limit" as the word "max", which readCgroupUint already
// reports as no limit. A runtime translating a v1 hierarchy writes v1's
// spelling instead: PAGE_COUNTER_MAX scaled by the page size, which is
// 0x7FFFFFFFFFFFF000 on a 4 KiB-page host and 0x7FFFFFFFFFFF0000 on a 64
// KiB-page arm64 one. Where physical memory is known the "only tighten" rule
// below discards such a value on its own; where /proc/meminfo could not be read
// there is nothing to tighten against, and the agent would advertise eight
// exabytes. 4 EiB is four orders of magnitude above the largest machine anyone
// will run an agent on and far below either sentinel.
const implausibleMemory = uint64(1) << 62

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
	if limits.MemoryMax > 0 && limits.MemoryMax < implausibleMemory &&
		(res.MemoryTotalBytes == 0 || limits.MemoryMax < res.MemoryTotalBytes) {
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

// cgroupV1Mount is one v1 hierarchy the process belongs to: the directory it is
// mounted under, relative to cgroupRoot, and the process's path within it.
type cgroupV1Mount struct {
	dir string
	rel string
}

// readSelfCgroupV1 maps each v1 controller to the mounts that could carry it.
//
// A v1 line is "id:controllers:path", where controllers is the comma-joined set
// the hierarchy was mounted with. The directory under sys/fs/cgroup is
// conventionally named after that whole set, with a symlink per member — so
// both spellings are offered and whichever exists is the one that reads.
//
// The "0::" unified line and systemd's "name=systemd" bookkeeping hierarchy
// carry no limits and are skipped: the first is v2's, handled by its own
// reader, and the second has no limit files to read.
func readSelfCgroupV1(fsys fs.FS) map[string][]cgroupV1Mount {
	data, err := fs.ReadFile(fsys, "proc/self/cgroup")
	if err != nil {
		return nil
	}

	out := map[string][]cgroupV1Mount{}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(fields) != 3 || fields[1] == "" {
			continue
		}
		set, rel := fields[1], fields[2]
		if rel == "" {
			rel = "/"
		}
		for _, controller := range strings.Split(set, ",") {
			if controller == "" || strings.Contains(controller, "=") {
				continue
			}
			out[controller] = append(out[controller],
				cgroupV1Mount{dir: path.Join(cgroupRoot, set), rel: rel})
			if set != controller {
				out[controller] = append(out[controller],
					cgroupV1Mount{dir: path.Join(cgroupRoot, controller), rel: rel})
			}
		}
	}
	return out
}

// readMemoryLimitV1 reads memory.limit_in_bytes, whose "no limit" is a number
// rather than a word.
//
// The kernel writes PAGE_COUNTER_MAX scaled by the page size: 0x7FFFFFFFFFFFF000
// on a 4 KiB-page host and 0x7FFFFFFFFFFF0000 on a 64 KiB-page arm64 one. Both
// sit *just below* half of MaxUint64 — 4095 and 65535 below it — so the obvious
// guard of "at least MaxUint64/2" misses both and reports eight exabytes of RAM
// as the container's ceiling. implausibleMemory is the threshold that does not.
func readMemoryLimitV1(fsys fs.FS, dir string) (limit, current uint64, ok bool) {
	limit, ok = readCgroupUint(fsys, path.Join(dir, "memory.limit_in_bytes"))
	if !ok || limit == 0 || limit >= implausibleMemory {
		return 0, 0, false
	}
	current, _ = readCgroupUint(fsys, path.Join(dir, "memory.usage_in_bytes"))
	return limit, current, true
}

// readCPULimitV1 reads the quota and period from their separate files.
//
// v1's "no limit" here is a third spelling again: cpu.cfs_quota_us holds -1,
// which is why the value is parsed as signed. Reading it unsigned would fail to
// parse and happen to give the right answer, until a kernel wrote 0 instead.
func readCPULimitV1(fsys fs.FS, dir string) (quota, period uint64, ok bool) {
	signed, ok := readCgroupInt(fsys, path.Join(dir, "cpu.cfs_quota_us"))
	if !ok || signed <= 0 {
		return 0, 0, false
	}
	period, ok = readCgroupUint(fsys, path.Join(dir, "cpu.cfs_period_us"))
	if !ok || period == 0 {
		return 0, 0, false
	}
	return uint64(signed), period, true
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

// readCgroupInt reads a single-value cgroup file that may be negative. v1 uses
// -1 for "no limit" where v2 uses the word "max".
func readCgroupInt(fsys fs.FS, name string) (int64, bool) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
