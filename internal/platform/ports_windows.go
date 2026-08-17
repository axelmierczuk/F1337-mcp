package platform

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modiphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable = modiphlpapi.NewProc("GetExtendedTcpTable")
)

// tcpTableOwnerPIDListener is TCP_TABLE_OWNER_PID_LISTENER: rows for listening
// sockets, each carrying the owning pid.
const tcpTableOwnerPIDListener = 3

// listeningPorts reads the TCP tables from iphlpapi and keeps the rows owned
// by pid.
//
// GetExtendedTcpTable is called twice: once with a zero-length buffer to learn
// the size, once to fill it. The table can grow between the two calls, so the
// size probe is retried.
func listeningPorts(pid int) ([]uint32, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("platform: invalid pid %d", pid)
	}
	if _, err := StatProcess(pid); err != nil {
		return nil, err
	}
	owner := uint32(pid) //nolint:gosec // pid is positive, checked above

	var ports []uint32
	for _, family := range []uint32{afInet, afInet6} {
		table, err := extendedTCPTable(family)
		if err != nil {
			// One family missing (IPv6 disabled) must not lose the other.
			continue
		}
		ports = append(ports, listenerPorts(table, family, owner)...)
	}
	return ports, nil
}

func extendedTCPTable(family uint32) ([]byte, error) {
	var size uint32
	for range 4 {
		var buf []byte
		var first *byte
		if size > 0 {
			buf = make([]byte, size)
			first = &buf[0]
		}

		// The pointer conversions stay inside the call expression, and buf is
		// kept alive across it, so the buffer cannot be collected or moved
		// between taking its address and the kernel writing into it.
		ret, _, _ := procGetExtendedTCPTable.Call(
			uintptr(unsafe.Pointer(first)),
			uintptr(unsafe.Pointer(&size)),
			0, // bOrder: sorting is irrelevant, skip the work
			uintptr(family),
			uintptr(tcpTableOwnerPIDListener),
			0,
		)
		runtime.KeepAlive(buf)

		switch windows.Errno(ret) {
		case windows.ERROR_SUCCESS:
			if buf == nil {
				return nil, nil
			}
			return buf[:size], nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			continue // size now holds what is needed; go round again
		default:
			return nil, fmt.Errorf("platform: GetExtendedTcpTable: %w", windows.Errno(ret))
		}
	}
	return nil, errors.New("platform: GetExtendedTcpTable: table kept growing")
}
