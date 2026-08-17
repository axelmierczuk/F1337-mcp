package tools

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
)

// TestRenderExec_TheTruncationNoteNamesTheCapThatBit.
//
// Two caps can cut an exec result: the caller's max_output_bytes, and the
// ceiling this process keeps on one result whatever the argument said. The note
// is the model's only instruction on what to do next, so it has to name the one
// that actually bit — telling a caller to raise an argument it has already
// raised past the binding limit sends it round the same loop with a bigger
// number.
//
// Asserted here rather than end to end because reaching the second case through
// the tool means a result holding the whole 8 MiB ceiling, which costs fifteen
// seconds of CI to test one sentence. The caps reach this function from one
// expression at its only call site.
func TestRenderExec_TheTruncationNoteNamesTheCapThatBit(t *testing.T) {
	result := &sandboxdv1.ExecResult{ExitCode: 0, Duration: durationpb.New(time.Second)}

	dropped := func() (*boundedBuffer, *boundedBuffer) {
		stdout, stderr := newBoundedBuffer(4), newBoundedBuffer(4)
		_, _ = stdout.Write([]byte("kept and then some dropped\n"))
		return stdout, stderr
	}

	t.Run("the caller's own cap is the one to raise", func(t *testing.T) {
		stdout, stderr := dropped()
		out := renderExecResult(result, ExecArgs{MaxOutputBytes: 4}, time.Minute, 4, 4, stdout, stderr)

		require.NotNil(t, out.Truncation)
		assert.Contains(t, out.Truncation.Note, "capped at 4 bytes")
		assert.Contains(t, out.Truncation.Note, "raise max_output_bytes")
	})

	t.Run("a ceiling above it is not blamed on the argument", func(t *testing.T) {
		stdout, stderr := dropped()
		out := renderExecResult(result, ExecArgs{MaxOutputBytes: 16 << 20}, time.Minute, 16<<20, 8<<20, stdout, stderr)

		require.NotNil(t, out.Truncation)
		assert.Contains(t, out.Truncation.Note, "this server's own ceiling")
		assert.Contains(t, out.Truncation.Note, "8388608 bytes", "and names the number that actually bit")
		assert.NotContains(t, out.Truncation.Note, "raise max_output_bytes",
			"raising the argument cannot lift a cap the argument is already above")
	})
}

// TestStreamTimeout_ScalesWithThePayload.
//
// The unary call timeout answers questions — a stat, a listing — and using it
// for a call that carries a file makes the limits these tools advertise
// unreachable: sandbox_transfer moves up to 256 MiB in one call, and 256 MiB
// inside 15 seconds is 17 MB/s sustained. The failure that produced was not a
// slow transfer but "transferred 40 of 200 files, then the call timed out".
func TestStreamTimeout_ScalesWithThePayload(t *testing.T) {
	deps := Deps{}

	assert.Equal(t, DefaultCallTimeout, deps.streamTimeout(0),
		"an empty payload is still a call, and still gets the ordinary deadline")
	assert.Equal(t, DefaultCallTimeout, deps.streamTimeout(1024),
		"and so is one small enough that the allowance rounds to nothing")

	assert.Greater(t, deps.streamTimeout(MaxTransferBytes), 4*time.Minute,
		"the largest transfer this tool will accept must have a deadline it can finish inside")

	// A size from the far side is not a number to trust with a deadline.
	assert.LessOrEqual(t, deps.streamTimeout(1<<62), DefaultCallTimeout+maxStreamAllowance)
	assert.Positive(t, deps.streamTimeout(1<<62), "and it must not wrap negative, which is a context born expired")

	// The configured timeout is the floor, not something the allowance replaces.
	slow := Deps{CallTimeout: time.Minute}
	assert.GreaterOrEqual(t, slow.streamTimeout(0), time.Minute)
	assert.Greater(t, slow.streamTimeout(MaxTransferBytes), slow.streamTimeout(0))
}
