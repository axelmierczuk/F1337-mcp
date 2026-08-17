package platform

// Resources summarises what this host can actually give a job. It mirrors the
// sandboxd.v1.Resources message.
//
// "Actually" is the operative word on Linux: an agent in a container that
// reports the host's 256 GB will be handed work that its 2 GB cgroup cannot
// run, and the model will read the resulting OOM kill as a broken build rather
// than a full sandbox. Every figure below is the effective one — the cgroup
// limit where a tighter one exists, the machine's otherwise.
type Resources struct {
	// CPUCores is the number of cores the agent may use, rounded up from a
	// fractional cgroup quota. Never zero.
	CPUCores uint32
	// MemoryTotalBytes is the memory ceiling: the cgroup limit if one is set,
	// otherwise physical memory.
	MemoryTotalBytes uint64
	// MemoryAvailableBytes is what could be allocated now without swapping,
	// as far as the platform will say. It is an estimate everywhere and a
	// conservative one on macOS.
	MemoryAvailableBytes uint64
	// DiskTotalBytes and DiskAvailableBytes describe the filesystem holding
	// the path passed to ReadResources.
	DiskTotalBytes     uint64
	DiskAvailableBytes uint64
	// LoadAverage1m is zero on Windows, which has no equivalent metric.
	LoadAverage1m float64
	// CPUQuotaLimited and MemoryLimited record that the figures above came
	// from a cgroup rather than from the machine, so the host service can say
	// so instead of leaving an operator to wonder why a 64-core box reports
	// two cores.
	CPUQuotaLimited bool
	MemoryLimited   bool
}

// ReadResources reports host capacity. diskPath selects the filesystem to
// measure and should be the agent's state or working directory; an empty
// string measures the filesystem holding the current working directory.
//
// Individual readings that fail are left at zero rather than failing the whole
// call. An error is returned only when nothing could be read at all, because
// half a resource report is more useful to a scheduler than none.
func ReadResources(diskPath string) (Resources, error) { return readResources(diskPath) }
