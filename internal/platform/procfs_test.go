package platform

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// These parsers are Linux-only in use and untagged in source, so their tests
// run on all three runners. The /proc formats do not change per host, and the
// mistakes they invite are textual.

func TestParseProcStatStartTicks(t *testing.T) {
	t.Parallel()

	// A real line, truncated after the field this reads. Fields 3..22 follow
	// the comm: state ppid pgrp session tty tpgid flags minflt cminflt majflt
	// cmajflt utime stime cutime cstime priority nice threads itrealvalue
	// starttime.
	const tail = " S 1 4211 4211 0 -1 4194304 512 0 3 0 7 11 0 0 20 0 1 0 987654 " +
		"4276224 512 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0"

	tests := []struct {
		name    string
		line    string
		want    uint64
		wantErr bool
	}{
		{
			name: "ordinary command name",
			line: "4211 (node)" + tail,
			want: 987654,
		},
		{
			name: "command name containing spaces",
			line: "4211 (Web Content)" + tail,
			want: 987654,
		},
		{
			name: "command name containing a close paren",
			line: "4211 (weird)name)" + tail,
			want: 987654,
		},
		{
			name: "command name that is entirely parens and spaces",
			line: "4211 (foo (bar) baz)" + tail,
			want: 987654,
		},
		{
			name:    "no comm field",
			line:    "4211 node S 1",
			wantErr: true,
		},
		{
			name:    "unopened comm field",
			line:    "4211 node)" + tail,
			wantErr: true,
		},
		{
			name:    "truncated before field 22",
			line:    "4211 (node) S 1 4211 4211 0 -1",
			wantErr: true,
		},
		{
			name:    "start time is not a number",
			line:    "4211 (node) S 1 4211 4211 0 -1 4194304 512 0 3 0 7 11 0 0 20 0 1 0 notanumber 4276224",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseProcStatStartTicks([]byte(tc.line))
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestParseProcStatStartTicks_CommWithSpacesIsNotSplit is the same hazard
// stated as a property: the value must not shift when the command name gains a
// word. Splitting the line on whitespace and indexing gives 987654 for "node"
// and a completely different number for "Web Content", and the number in
// question is what stops the supervisor signalling a process it does not own.
func TestParseProcStatStartTicks_CommWithSpacesIsNotSplit(t *testing.T) {
	t.Parallel()

	const tail = " S 1 4211 4211 0 -1 4194304 512 0 3 0 7 11 0 0 20 0 1 0 987654 4276224"

	plain, err := parseProcStatStartTicks([]byte("4211 (node)" + tail))
	require.NoError(t, err)
	spaced, err := parseProcStatStartTicks([]byte("4211 (Web Content (private))" + tail))
	require.NoError(t, err)

	require.Equal(t, plain, spaced)
}

func TestParseProcStatBtime(t *testing.T) {
	t.Parallel()

	const stat = `cpu  1 2 3 4 5 6 7 8 9 10
cpu0 1 2 3 4 5 6 7 8 9 10
intr 12345
ctxt 987654
btime 1700000000
processes 4321
procs_running 2
`
	got, err := parseProcStatBtime([]byte(stat))
	require.NoError(t, err)
	require.Equal(t, int64(1700000000), got)

	_, err = parseProcStatBtime([]byte("cpu 1 2 3\nintr 5\n"))
	require.Error(t, err)

	_, err = parseProcStatBtime([]byte("btime notanumber\n"))
	require.Error(t, err)
}

func TestParseAuxvClockTicks(t *testing.T) {
	t.Parallel()

	put := func(pairs ...uint64) []byte {
		out := make([]byte, 8*len(pairs))
		for i, v := range pairs {
			binary.NativeEndian.PutUint64(out[i*8:], v)
		}
		return out
	}

	// AT_PAGESZ, AT_CLKTCK, AT_NULL.
	got, ok := parseAuxvClockTicks(put(6, 4096, auxvClockTick, 100, 0, 0))
	require.True(t, ok)
	require.Equal(t, uint64(100), got)

	// A non-default value, since 100 is also the fallback and would hide a
	// parser that always failed.
	got, ok = parseAuxvClockTicks(put(6, 4096, auxvClockTick, 250, 0, 0))
	require.True(t, ok)
	require.Equal(t, uint64(250), got)

	// Terminated before AT_CLKTCK appears.
	_, ok = parseAuxvClockTicks(put(6, 4096, 0, 0, auxvClockTick, 100))
	require.False(t, ok)

	_, ok = parseAuxvClockTicks(nil)
	require.False(t, ok)

	// A zero value is not a usable tick rate.
	_, ok = parseAuxvClockTicks(put(auxvClockTick, 0, 0, 0))
	require.False(t, ok)
}

func TestParseMeminfo(t *testing.T) {
	t.Parallel()

	const meminfo = `MemTotal:       16316412 kB
MemFree:          254128 kB
MemAvailable:    9876543 kB
Buffers:          123456 kB
HugePages_Total:       0
`
	got := parseMeminfo([]byte(meminfo))
	require.Equal(t, uint64(16316412)*1024, got["MemTotal"])
	require.Equal(t, uint64(9876543)*1024, got["MemAvailable"])
	require.Equal(t, uint64(0), got["HugePages_Total"], "a count without a unit is not multiplied")
	require.NotContains(t, got, "Nonexistent")
}

func TestParseLoadAverage1m(t *testing.T) {
	t.Parallel()

	got, err := parseLoadAverage1m([]byte("0.52 0.58 0.59 2/1234 5678\n"))
	require.NoError(t, err)
	require.InDelta(t, 0.52, got, 1e-9)

	_, err = parseLoadAverage1m([]byte(""))
	require.Error(t, err)

	_, err = parseLoadAverage1m([]byte("notanumber 0.5 0.5\n"))
	require.Error(t, err)
}
