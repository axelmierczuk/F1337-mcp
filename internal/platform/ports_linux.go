package platform

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"strconv"
)

// listeningPorts joins the listening sockets in /proc/net/tcp{,6} to the
// descriptors pid holds. There is no per-pid view of the socket table on
// Linux, so the join is the only way across.
func listeningPorts(pid int) ([]uint32, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("platform: invalid pid %d", pid)
	}

	// The descriptor list is read first so that a pid that does not exist
	// reports ErrProcessNotFound, the same as on the other two platforms,
	// rather than an empty list that happens to be produced by a host with no
	// listening sockets at all.
	fdDir := "/proc/" + strconv.Itoa(pid) + "/fd"
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, notFound(pid)
		}
		// Permission denied on another user's process is a legitimate
		// best-effort miss, not a failure to report.
		if errors.Is(err, fs.ErrPermission) {
			return nil, nil
		}
		return nil, fmt.Errorf("platform: reading %s: %w", fdDir, err)
	}

	// The two socket tables, opened by literal name rather than through a
	// loop variable. This reader takes a pid, never a path, and spelling the
	// only two files it can ever open directly at the call site is what makes
	// that visible — to gosec, which flags a variable reaching os.ReadFile,
	// and to a reader wondering whether a caller can steer it.
	//
	// A missing table is not an error: IPv6 is routinely absent.
	byInode := make(map[uint64]uint32)
	if data, err := os.ReadFile("/proc/net/tcp"); err == nil {
		maps.Copy(byInode, parseProcNetTCP(data))
	}
	if data, err := os.ReadFile("/proc/net/tcp6"); err == nil {
		maps.Copy(byInode, parseProcNetTCP(data))
	}
	if len(byInode) == 0 {
		return nil, nil
	}

	var ports []uint32
	for _, entry := range entries {
		target, err := os.Readlink(fdDir + "/" + entry.Name())
		if err != nil {
			continue // the descriptor closed under us
		}
		inode, ok := parseSocketInode(target)
		if !ok {
			continue
		}
		if port, ok := byInode[inode]; ok {
			ports = append(ports, port)
		}
	}
	return ports, nil
}
