package sandboxctl

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/axelmierczuk/fleet-mcp/internal/registry"
	"github.com/axelmierczuk/fleet-mcp/internal/security/enroll"
)

// enroll.Service retries with the next free name when a Recorder reports
// ErrNameTaken, and gives up with an Internal error on anything else. The
// wiring between the registry's own "already exists" and that contract is what
// decides which of those two a host enrolling into a name race gets, so it is
// asserted here rather than assumed.
func TestFleetRecorder_DuplicateNameIsReportedAsTaken(t *testing.T) {
	fleet, err := registry.Open(filepath.Join(t.TempDir(), "registry.yaml"))
	require.NoError(t, err)

	rec := fleetRecorder{registry: fleet}
	require.NoError(t, rec.Record(enroll.EnrolledSandbox{Name: "build-box", Address: "build-box:8722"}))

	err = rec.Record(enroll.EnrolledSandbox{Name: "build-box", Address: "other:8722"})
	require.ErrorIs(t, err, enroll.ErrNameTaken)
}

// Anything that is not a name collision must stay a real failure: enrolling
// past a broken registry would hand out a certificate for a fleet member that
// was never recorded.
func TestFleetRecorder_OtherFailuresAreNotNameCollisions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.yaml")
	fleet, err := registry.Open(path)
	require.NoError(t, err)

	// A directory where the registry file belongs: every read-modify-write
	// fails, and none of those failures means "pick another name".
	require.NoError(t, os.Mkdir(path, 0o700))

	err = fleetRecorder{registry: fleet}.Record(enroll.EnrolledSandbox{Name: "build-box"})
	require.Error(t, err)
	require.NotErrorIs(t, err, enroll.ErrNameTaken)
}
