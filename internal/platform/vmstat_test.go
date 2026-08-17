package platform

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const vmStatSample = `Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                               34414.
Pages active:                           1898738.
Pages inactive:                         1889291.
Pages speculative:                        10241.
Pages throttled:                              0.
Pages wired down:                        223371.
Pages purgeable:                          44903.
"Translation faults":                 3512345678.
Pages copy-on-write:                   87654321.
Pages zero filled:                   2345678901.
`

func TestVMStatAvailablePages(t *testing.T) {
	t.Parallel()

	pages, pageSize, ok := vmStatAvailablePages(vmStatSample)
	require.True(t, ok)
	require.Equal(t, uint64(16384), pageSize)

	// free + inactive + speculative + purgeable. Active, wired and throttled
	// pages are in use and must not be counted.
	require.Equal(t, uint64(34414+1889291+10241+44903), pages)
}

func TestVMStatAvailablePages_IntelPageSize(t *testing.T) {
	t.Parallel()

	const sample = `Mach Virtual Memory Statistics: (page size of 4096 bytes)
Pages free:                               1000.
Pages inactive:                           2000.
`
	pages, pageSize, ok := vmStatAvailablePages(sample)
	require.True(t, ok)
	require.Equal(t, uint64(4096), pageSize, "page size is read, not assumed; it differs between Intel and Apple silicon")
	require.Equal(t, uint64(3000), pages)
}

func TestVMStatAvailablePages_Malformed(t *testing.T) {
	t.Parallel()

	_, _, ok := vmStatAvailablePages("")
	require.False(t, ok)

	// Counts with no page size are unusable.
	_, _, ok = vmStatAvailablePages("Pages free: 1000.\n")
	require.False(t, ok)

	// A page size with no counts is not a zero-byte answer, it is no answer.
	_, _, ok = vmStatAvailablePages("Mach Virtual Memory Statistics: (page size of 4096 bytes)\n")
	require.False(t, ok)

	_, _, ok = vmStatAvailablePages("Mach Virtual Memory Statistics: (page size of zero bytes)\nPages free: 10.\n")
	require.False(t, ok)
}

func TestParseVMStatPageSize(t *testing.T) {
	t.Parallel()

	size, ok := parseVMStatPageSize("Mach Virtual Memory Statistics: (page size of 16384 bytes)")
	require.True(t, ok)
	require.Equal(t, uint64(16384), size)

	_, ok = parseVMStatPageSize("Pages free: 100.")
	require.False(t, ok)

	_, ok = parseVMStatPageSize("page size of 0 bytes")
	require.False(t, ok)
}
