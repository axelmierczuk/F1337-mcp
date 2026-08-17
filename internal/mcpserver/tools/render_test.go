package tools

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/registry"
)

func TestHealthString(t *testing.T) {
	for status, want := range map[sandboxdv1.HealthResponse_Status]string{
		sandboxdv1.HealthResponse_STATUS_SERVING:     healthServing,
		sandboxdv1.HealthResponse_STATUS_DEGRADED:    healthDegraded,
		sandboxdv1.HealthResponse_STATUS_DRAINING:    healthDraining,
		sandboxdv1.HealthResponse_STATUS_UNSPECIFIED: healthUnknown,
	} {
		assert.Equal(t, want, healthString(status))
	}
}

// TestPlatformString: a sandbox that has never been probed has no platform,
// and rendering "/" for it would read as a path.
func TestPlatformString(t *testing.T) {
	assert.Equal(t, "linux/amd64", platformString(registry.Platform{OS: "linux", Arch: "amd64"}))
	assert.Equal(t, "linux", platformString(registry.Platform{OS: "linux"}))
	assert.Equal(t, "amd64", platformString(registry.Platform{Arch: "amd64"}))
	assert.Empty(t, platformString(registry.Platform{}))
}

func TestRelativeTime(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

	assert.Equal(t, "never", relativeTime(time.Time{}, now))
	assert.Equal(t, "30s ago", relativeTime(now.Add(-30*time.Second), now))
	assert.Equal(t, "5m ago", relativeTime(now.Add(-5*time.Minute), now))
	assert.Equal(t, "3h ago", relativeTime(now.Add(-3*time.Hour), now))
	assert.Equal(t, "2d ago", relativeTime(now.Add(-48*time.Hour), now))

	// A sandbox whose clock runs ahead of ours must not report a negative
	// age, which reads as a bug in the tool rather than in the clock.
	assert.Equal(t, "0s ago", relativeTime(now.Add(time.Minute), now))
}

func TestHumanBytes(t *testing.T) {
	assert.Empty(t, humanBytes(0), "an unreported size is omitted, not rendered as zero")
	assert.Equal(t, "512 B", humanBytes(512))
	assert.Equal(t, "1.0 KiB", humanBytes(1024))
	assert.Equal(t, "16.0 GiB", humanBytes(16<<30))
	assert.Equal(t, "2.0 TiB", humanBytes(2<<40))
}

func TestHumanDuration(t *testing.T) {
	assert.Empty(t, humanDuration(0))
	assert.Empty(t, humanDuration(-time.Hour))
	assert.Equal(t, "45s", humanDuration(45*time.Second))
	assert.Equal(t, "5m30s", humanDuration(5*time.Minute+30*time.Second))
	assert.Equal(t, "2h15m", humanDuration(2*time.Hour+15*time.Minute))
	assert.Equal(t, "3d4h", humanDuration(76*time.Hour))
}

func TestParseLabelFilter(t *testing.T) {
	key, value, err := parseLabelFilter(" arch = arm64 ")
	require.NoError(t, err)
	assert.Equal(t, "arch", key)
	assert.Equal(t, "arm64", value)

	// An empty value is a legitimate filter: "the label is set to nothing".
	key, value, err = parseLabelFilter("gpu=")
	require.NoError(t, err)
	assert.Equal(t, "gpu", key)
	assert.Empty(t, value)

	for _, bad := range []string{"arm64", "", "=arm64"} {
		_, _, err := parseLabelFilter(bad)
		require.Errorf(t, err, "%q should be rejected", bad)
		assert.Contains(t, err.Error(), "key=value")
	}
}

// TestCheckAddress_RejectsWhatCannotBeDialed. The host half becomes the TLS
// server name the agent's certificate is verified against, so an address that
// is not host:port fails later as a handshake error naming neither.
func TestCheckAddress_RejectsWhatCannotBeDialed(t *testing.T) {
	for _, good := range []string{"build-box:8722", "build-box.internal:8722", "127.0.0.1:8722", "[::1]:8722", "host:65535"} {
		assert.NoErrorf(t, checkAddress(good), "%q should be accepted", good)
	}
	for _, bad := range []string{"", "build-box", "build-box:", ":8722", "build-box:0", "build-box:65536", "build-box:-1", "https://build-box:8722", "build/box:8722", "build box:8722"} {
		assert.Errorf(t, checkAddress(bad), "%q should be rejected", bad)
	}
}

func TestCheckSandboxName(t *testing.T) {
	for _, good := range []string{"build-box", "gpu_01", "a", "host.internal"} {
		assert.NoErrorf(t, checkSandboxName(good), "%q should be accepted", good)
	}
	for _, bad := range []string{"", " ", "build box", "build\tbox", "café", "sbx_deadbeef"} {
		assert.Errorf(t, checkSandboxName(bad), "%q should be rejected", bad)
	}
}

// TestShortDetail keeps one unreachable sandbox from turning a twenty-machine
// listing into a wall of text, and keeps gRPC's envelope out of what the model
// reads.
func TestShortDetail(t *testing.T) {
	assert.Empty(t, shortDetail(nil))
	assert.Equal(t, "connection refused", shortDetail(errors.New("connection refused")))

	long := shortDetail(errors.New(strings.Repeat("x", 400)))
	assert.LessOrEqual(t, len(long), 164)
	assert.Contains(t, long, "…")

	// A gRPC status renders as its message, not as the wire envelope. This is
	// the whole reason it goes through mcperr rather than calling Error().
	detail := shortDetail(status.Error(codes.Unavailable, "connection refused"))
	assert.Equal(t, "connection refused", detail)
	assert.NotContains(t, detail, "rpc error: code =")

	// Truncation cuts on a rune boundary. An agent's message is not
	// guaranteed to be ASCII, and half a rune is invalid UTF-8 in a JSON
	// result.
	multibyte := shortDetail(errors.New(strings.Repeat("é", 200)))
	assert.True(t, utf8.ValidString(multibyte), "truncation produced invalid UTF-8: %q", multibyte)
	assert.Contains(t, multibyte, "…")
}

// TestCompact covers the bound every agent-supplied field in a listing row
// shares. An agent writes the failure message when a probe fails, the status
// message when it reports itself degraded, and the platform and version cached
// from its last GetHostInfo; only the first used to be bounded, and the listing
// they all land in is paid for on every fleet check.
func TestCompact(t *testing.T) {
	assert.Empty(t, compact(""))
	assert.Empty(t, compact("   \n "))
	assert.Equal(t, "disk 94% full", compact("  disk 94% full  "))

	long := compact(strings.Repeat("x", 400))
	assert.LessOrEqual(t, len(long), 164)
	assert.Contains(t, long, "…")

	multibyte := compact(strings.Repeat("é", 200))
	assert.True(t, utf8.ValidString(multibyte), "truncation produced invalid UTF-8: %q", multibyte)
}

// TestCheckLabels guards the free-form half of a sandbox_add call: the model
// supplies it, the registry stores it, and every sandbox_list result carries it.
func TestCheckLabels(t *testing.T) {
	assert.NoError(t, checkLabels(nil))
	assert.NoError(t, checkLabels(map[string]string{"arch": "arm64", "owner": "platform team", "empty": ""}))

	tooMany := map[string]string{}
	for i := range maxLabels + 1 {
		tooMany[strconv.Itoa(i)] = "v"
	}
	for name, labels := range map[string]map[string]string{
		"too many":          tooMany,
		"empty key":         {"": "v"},
		"key with a space":  {"data centre": "west"},
		"non-ASCII key":     {"café": "v"},
		"oversized key":     {strings.Repeat("k", maxLabelKeyLength+1): "v"},
		"oversized value":   {"k": strings.Repeat("v", maxLabelValueLength+1)},
		"value with a tab":  {"k": "a\tb"},
		"value with a line": {"k": "a\nb"},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkLabels(labels)
			require.Error(t, err)
			assert.Contains(t, strings.ToLower(err.Error()), "label")
			assert.Less(t, len(err.Error()), 512, "the rejection must not echo the input back whole")
		})
	}
}
