package platform

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseProcNetTCP(t *testing.T) {
	t.Parallel()

	const table = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 918273 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1538 0100007F:C350 01 00000000:00000000 00:00000000 00000000  1000        0 918274 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 918275 1 0000000000000000 100 0 0 10 0
   3: 00000000:0000 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0      0 1 0000000000000000 100 0 0 10 0
`

	got := parseProcNetTCP([]byte(table))
	require.Equal(t, map[uint64]uint32{
		918273: 8080, // 0x1F90
		918275: 3000, // 0x0BB8
	}, got, "only listening sockets (state 0A) with a real inode and port are kept")
}

func TestParseProcNetTCP_Malformed(t *testing.T) {
	t.Parallel()

	require.Empty(t, parseProcNetTCP(nil))
	require.Empty(t, parseProcNetTCP([]byte("header only\n")))
	require.Empty(t, parseProcNetTCP([]byte("header\n   0: garbage\n")))
	require.Empty(t, parseProcNetTCP([]byte("header\n   0: 00000000:ZZZZ 00000000:0000 0A 0 0 0 0 0 0 918273\n")))
}

func TestParseSocketInode(t *testing.T) {
	t.Parallel()

	inode, ok := parseSocketInode("socket:[918273]")
	require.True(t, ok)
	require.Equal(t, uint64(918273), inode)

	for _, target := range []string{
		"/dev/null", "pipe:[12345]", "socket:[]", "socket:[abc]", "socket:12345", "", "anon_inode:[eventpoll]",
	} {
		_, ok := parseSocketInode(target)
		require.Falsef(t, ok, "target %q", target)
	}
}

func TestParseLsofPorts(t *testing.T) {
	t.Parallel()

	const out = `p4211
f5
n*:8080
f6
n127.0.0.1:3000
f7
n[::1]:9229
f8
n*:0
`
	require.Equal(t, []uint32{8080, 3000, 9229}, parseLsofPorts(out))
	require.Empty(t, parseLsofPorts(""))
	require.Empty(t, parseLsofPorts("p4211\nf5\n"))
}

// TestListenerPorts checks the Windows table walk against synthetic tables.
// The offsets it encodes are the part of the Windows reader that cannot be
// eyeballed, and the byte-order trap in the port field turns 80 into 20480 if
// it is read the obvious way.
func TestListenerPorts(t *testing.T) {
	t.Parallel()

	t.Run("ipv4", func(t *testing.T) {
		t.Parallel()

		table := make([]byte, 4+3*tcpRow4Size)
		binary.LittleEndian.PutUint32(table, 3)
		putRow4(table[4+0*tcpRow4Size:], 8080, 4211)
		putRow4(table[4+1*tcpRow4Size:], 3000, 9999)
		putRow4(table[4+2*tcpRow4Size:], 80, 4211)

		require.Equal(t, []uint32{8080, 80}, listenerPorts(table, afInet, 4211))
		require.Equal(t, []uint32{3000}, listenerPorts(table, afInet, 9999))
		require.Empty(t, listenerPorts(table, afInet, 1))
	})

	t.Run("ipv6", func(t *testing.T) {
		t.Parallel()

		table := make([]byte, 4+2*tcpRow6Size)
		binary.LittleEndian.PutUint32(table, 2)
		putRow6(table[4+0*tcpRow6Size:], 9229, 4211)
		putRow6(table[4+1*tcpRow6Size:], 443, 4211)

		require.Equal(t, []uint32{9229, 443}, listenerPorts(table, afInet6, 4211))
	})

	t.Run("a count larger than the buffer is clamped", func(t *testing.T) {
		t.Parallel()

		table := make([]byte, 4+tcpRow4Size)
		binary.LittleEndian.PutUint32(table, 99)
		putRow4(table[4:], 8080, 4211)

		require.Equal(t, []uint32{8080}, listenerPorts(table, afInet, 4211))
	})

	t.Run("degenerate input", func(t *testing.T) {
		t.Parallel()

		require.Nil(t, listenerPorts(nil, afInet, 1))
		require.Nil(t, listenerPorts([]byte{0, 0}, afInet, 1))
		require.Nil(t, listenerPorts([]byte{0, 0, 0, 0}, afInet, 1))
	})
}

// putRow4 writes a MIB_TCPROW_OWNER_PID. The port is stored network order in
// the low half of a little-endian DWORD, which is exactly what makes it easy
// to read wrong.
func putRow4(row []byte, port uint16, pid uint32) {
	binary.LittleEndian.PutUint32(row[0:], 2) // dwState: MIB_TCP_STATE_LISTEN
	binary.LittleEndian.PutUint32(row[4:], 0) // dwLocalAddr
	binary.BigEndian.PutUint16(row[tcpRow4Port:], port)
	binary.LittleEndian.PutUint32(row[tcpRow4PID:], pid)
}

func putRow6(row []byte, port uint16, pid uint32) {
	binary.BigEndian.PutUint16(row[tcpRow6Port:], port)
	binary.LittleEndian.PutUint32(row[tcpRow6PID:], pid)
}
