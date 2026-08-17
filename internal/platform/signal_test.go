package platform_test

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/sandboxd-mcp/internal/platform"
)

func TestSignalString(t *testing.T) {
	t.Parallel()

	// The spelling is what lands in ProcessStatus.signal, so it is pinned.
	require.Equal(t, "TERM", platform.SignalTerm.String())
	require.Equal(t, "KILL", platform.SignalKill.String())
	require.Equal(t, "INT", platform.SignalInt.String())
	require.Equal(t, "HUP", platform.SignalHup.String())
	require.Equal(t, "USR1", platform.SignalUSR1.String())
	require.Equal(t, "USR2", platform.SignalUSR2.String())
	require.Equal(t, "UNSPECIFIED", platform.SignalUnspecified.String())
	require.Equal(t, "Signal(200)", platform.Signal(200).String())
}

func TestParseSignal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in      string
		want    platform.Signal
		wantErr bool
	}{
		{in: "TERM", want: platform.SignalTerm},
		{in: "SIGTERM", want: platform.SignalTerm},
		{in: "term", want: platform.SignalTerm},
		{in: "sigterm", want: platform.SignalTerm},
		{in: "  KILL  ", want: platform.SignalKill},
		{in: "usr1", want: platform.SignalUSR1},
		{in: "UNSPECIFIED", wantErr: true},
		{in: "", wantErr: true},
		{in: "SIGSEGV", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got, err := platform.ParseSignal(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestSignalValid(t *testing.T) {
	t.Parallel()

	require.False(t, platform.SignalUnspecified.Valid(), "the zero value must never be sendable")
	require.False(t, platform.Signal(200).Valid())
	for _, sig := range []platform.Signal{
		platform.SignalTerm, platform.SignalKill, platform.SignalInt,
		platform.SignalHup, platform.SignalUSR1, platform.SignalUSR2,
	} {
		require.Truef(t, sig.Valid(), "%s", sig)
	}
}

func TestSignalOSSignal(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		// Every translation fails on Windows by design: os.Process.Signal
		// there accepts only os.Kill, and a caller that got a plausible
		// os.Signal back would assume delivery it is not going to get.
		for _, sig := range []platform.Signal{platform.SignalTerm, platform.SignalKill, platform.SignalInt} {
			_, err := sig.OSSignal()
			require.ErrorIsf(t, err, platform.ErrSignalUnsupported, "%s", sig)
		}
		return
	}

	for _, sig := range []platform.Signal{
		platform.SignalTerm, platform.SignalKill, platform.SignalInt,
		platform.SignalHup, platform.SignalUSR1, platform.SignalUSR2,
	} {
		got, err := sig.OSSignal()
		require.NoErrorf(t, err, "%s", sig)
		require.NotNil(t, got)
	}

	_, err := platform.SignalUnspecified.OSSignal()
	require.ErrorIs(t, err, platform.ErrSignalUnsupported)
}
