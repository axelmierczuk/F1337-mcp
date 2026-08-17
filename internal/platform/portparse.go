package platform

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// The listening-port readers differ completely per platform, but each one ends
// in a parse. Those parses live here, untagged and free of I/O, so their tests
// run on every runner instead of only the one whose format they describe.

// tcpListenState is TCP_LISTEN as /proc/net/tcp spells it.
const tcpListenState = "0A"

// parseProcNetTCP maps socket inode to local port for every listening socket
// in a /proc/net/tcp or /proc/net/tcp6 dump.
//
// The columns are aligned but not fixed-width, so the line is split on
// whitespace. Both files share a layout; only the width of the address halves
// differs, and that is not read here.
func parseProcNetTCP(data []byte) map[uint64]uint32 {
	const (
		localAddrField = 1
		stateField     = 3
		inodeField     = 9
	)

	out := make(map[uint64]uint32)
	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 {
			continue // header
		}
		fields := strings.Fields(line)
		if len(fields) <= inodeField {
			continue
		}
		if !strings.EqualFold(fields[stateField], tcpListenState) {
			continue
		}

		_, portHex, ok := strings.Cut(fields[localAddrField], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil || port == 0 {
			continue
		}
		inode, err := strconv.ParseUint(fields[inodeField], 10, 64)
		if err != nil || inode == 0 {
			continue
		}
		out[inode] = uint32(port)
	}
	return out
}

// parseSocketInode extracts 42 from the "socket:[42]" target of a
// /proc/<pid>/fd symlink. Descriptors that are not sockets return false.
func parseSocketInode(target string) (uint64, bool) {
	rest, ok := strings.CutPrefix(target, "socket:[")
	if !ok {
		return 0, false
	}
	rest, ok = strings.CutSuffix(rest, "]")
	if !ok {
		return 0, false
	}
	inode, err := strconv.ParseUint(rest, 10, 64)
	if err != nil {
		return 0, false
	}
	return inode, true
}

// parseLsofPorts reads lsof's field output (-F) and returns the local port of
// every listed socket.
//
// Field output is one field per line, tagged by its first byte: 'p' for a pid,
// 'f' for a descriptor, 'n' for the name. Names look like "*:8080",
// "127.0.0.1:8080" or "[::1]:8080", so the port follows the last colon. The
// tagged form is used rather than the default columns because the default
// output aligns columns by content width and is not safely splittable.
func parseLsofPorts(out string) []uint32 {
	var ports []uint32
	for line := range strings.SplitSeq(out, "\n") {
		name, ok := strings.CutPrefix(strings.TrimSpace(line), "n")
		if !ok {
			continue
		}
		idx := strings.LastIndex(name, ":")
		if idx < 0 {
			continue
		}
		port, err := strconv.ParseUint(name[idx+1:], 10, 16)
		if err != nil || port == 0 {
			continue
		}
		ports = append(ports, uint32(port))
	}
	return ports
}

// Windows address families, as GetExtendedTcpTable wants them.
const (
	afInet  = 2  // AF_INET
	afInet6 = 23 // AF_INET6

	// MIB_TCPROW_OWNER_PID is six DWORDs with no padding: state, local addr,
	// local port, remote addr, remote port, owning pid.
	tcpRow4Size = 24
	tcpRow4Port = 8
	tcpRow4PID  = 20

	// MIB_TCP6ROW_OWNER_PID is a 16-byte address, scope id and port, then the
	// same again for the remote end, then state and owning pid.
	tcpRow6Size = 56
	tcpRow6Port = 20
	tcpRow6PID  = 52
)

// listenerPorts walks a MIB_TCPTABLE_OWNER_PID or MIB_TCP6TABLE_OWNER_PID and
// returns the local ports owned by owner.
//
// Both tables begin with a DWORD row count followed by packed, 4-byte-aligned
// rows. The local port is a DWORD holding a network-byte-order port number in
// its low half, so it is read as a big-endian uint16 from the first two bytes
// rather than as a little-endian number — reading it the obvious way yields
// 20480 for port 80.
//
// This is offset arithmetic against a struct layout, which is the part of the
// Windows reader most likely to be silently wrong, so it is kept free of
// syscalls and tested against synthetic tables on every platform.
func listenerPorts(table []byte, family uint32, owner uint32) []uint32 {
	if len(table) < 4 {
		return nil
	}
	rowSize, portOff, pidOff := tcpRow4Size, tcpRow4Port, tcpRow4PID
	if family == afInet6 {
		rowSize, portOff, pidOff = tcpRow6Size, tcpRow6Port, tcpRow6PID
	}

	count := int(binary.LittleEndian.Uint32(table[:4]))
	rows := table[4:]
	if avail := len(rows) / rowSize; count > avail {
		count = avail
	}

	var ports []uint32
	for i := range count {
		row := rows[i*rowSize : (i+1)*rowSize]
		if binary.LittleEndian.Uint32(row[pidOff:pidOff+4]) != owner {
			continue
		}
		if port := uint32(binary.BigEndian.Uint16(row[portOff : portOff+2])); port != 0 {
			ports = append(ports, port)
		}
	}
	return ports
}
