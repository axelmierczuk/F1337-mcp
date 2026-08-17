package tools

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCheckFileCap_AppliesTheByteCapToOneFile.
//
// The tree walks check this limit as they accumulate. A single-file transfer
// has no walk, and until this existed it had no check either — which made the
// documented cap true of every shape of transfer except the simplest one.
func TestCheckFileCap_AppliesTheByteCapToOneFile(t *testing.T) {
	assert.NoError(t, checkFileCap("/srv/app/x.bin", MaxTransferBytes),
		"the limit itself is allowed; it is passing it that is not")

	err := checkFileCap("/srv/app/x.bin", MaxTransferBytes+1)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "256.0 MiB", "the refusal names the limit")
		assert.Contains(t, err.Error(), "/srv/app/x.bin", "and the file it is about")
	}
}

// TestAddBytes_SaturatesRatherThanWrapping. A plan's byte total is a sum of
// numbers the far side chose, and a sum that wraps is a cap check that passes.
func TestAddBytes_SaturatesRatherThanWrapping(t *testing.T) {
	assert.Equal(t, uint64(300), addBytes(100, 200))
	assert.Equal(t, uint64(math.MaxUint64), addBytes(math.MaxUint64, 1))
	assert.Equal(t, uint64(math.MaxUint64), addBytes(math.MaxUint64/3*2, math.MaxUint64/3*2))
	assert.Greater(t, addBytes(math.MaxUint64/3*2, math.MaxUint64/3*2), uint64(MaxTransferBytes),
		"a wrapped sum would land under the cap, which is the whole failure")
}

// TestClampCount_DoesNotWrapAHugeLimitIntoATinyOne.
//
// limit and max_matches reach the wire as uint32. A plain conversion turned
// 2^32+3 into 3, and the result then reported the walk as cut short and named
// the very argument that caused it as the way to get more.
func TestClampCount_DoesNotWrapAHugeLimitIntoATinyOne(t *testing.T) {
	assert.Equal(t, uint32(500), clampCount(0, 500), "unset takes the default")
	assert.Equal(t, uint32(500), clampCount(-1, 500), "and so does a negative one")
	assert.Equal(t, uint32(7), clampCount(7, 500))
	assert.Equal(t, uint32(math.MaxUint32), clampCount(math.MaxUint32, 500))
	assert.Equal(t, uint32(math.MaxUint32), clampCount(math.MaxUint32+1, 500),
		"a count past what the field holds is a caller asking for everything, not for none")
	assert.Equal(t, uint32(math.MaxUint32), clampCount(math.MaxUint32+4, 500),
		"and certainly not for three")
}

// TestPlanPush_StopsWalkingWhenTheCallerHasHungUp.
//
// The local walk is the one part of a transfer with no RPC in it, so nothing
// else in it notices a cancelled call: every other step derives a context and
// fails at once, while the walk ran a whole tree to the end first. On a source
// the caller chose badly — a home directory, a mounted volume — that is a tool
// call that cannot be interrupted.
func TestPlanPush_StopsWalkingWhenTheCallerHasHungUp(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte("x"), 0o600))
	}

	matcher, err := newExcludeMatcher(nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// A directory source reaches neither the file client nor the target, so a
	// bare registrar is enough to drive the walk.
	plan, err := (&Registrar{}).planPush(ctx, nil, nil,
		TransferArgs{Source: root, Destination: "/srv/app", Recursive: true}, matcher, "/")

	require.Error(t, err, "a cancelled call must not come back with a plan")
	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, plan)
}
