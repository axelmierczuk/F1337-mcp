package platform

import (
	"errors"
	"fmt"
	"io/fs"
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

	byInode := make(map[uint64]uint32)
	for _, name := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(name)
		if err != nil {
			// IPv6 is routinely absent; a missing table is not an error.
			continue
		}
		for inode, port := range parseProcNetTCP(data) {
			byInode[inode] = port
		}
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
