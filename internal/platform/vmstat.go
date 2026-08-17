package platform

import (
	"strconv"
	"strings"
)

// vmStatAvailablePages sums the page counts from `vm_stat` output that
// represent memory a new allocation could take: free pages, plus the inactive,
// speculative and purgeable pages the kernel will reclaim before it swaps.
//
// Counting free pages alone is the obvious reading and a badly wrong one.
// macOS deliberately keeps free pages near zero and holds the rest as cache,
// so a 64 GB machine with 50 GB reclaimable reports about 500 MB available and
// the scheduler concludes it cannot build anything.
//
// The first line carries the page size — "(page size of 16384 bytes)" — which
// is read rather than assumed, because it is 4096 on Intel and 16384 on Apple
// silicon.
//
// Parsing is separated from running the subprocess so it can be tested on any
// platform.
func vmStatAvailablePages(out string) (pages uint64, pageSize uint64, ok bool) {
	wanted := map[string]bool{
		"Pages free":        true,
		"Pages inactive":    true,
		"Pages speculative": true,
		"Pages purgeable":   true,
	}

	for line := range strings.SplitSeq(out, "\n") {
		if pageSize == 0 {
			if size, found := parseVMStatPageSize(line); found {
				pageSize = size
				continue
			}
		}
		key, value, found := strings.Cut(line, ":")
		if !found || !wanted[strings.TrimSpace(key)] {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(value), "."), 10, 64)
		if err != nil {
			continue
		}
		pages += v
		ok = true
	}
	return pages, pageSize, ok && pageSize > 0
}

// parseVMStatPageSize pulls 16384 out of
// "Mach Virtual Memory Statistics: (page size of 16384 bytes)".
func parseVMStatPageSize(line string) (uint64, bool) {
	_, rest, ok := strings.Cut(line, "page size of ")
	if !ok {
		return 0, false
	}
	digits, _, ok := strings.Cut(rest, " ")
	if !ok {
		return 0, false
	}
	size, err := strconv.ParseUint(digits, 10, 64)
	if err != nil || size == 0 {
		return 0, false
	}
	return size, true
}
