package tools

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

// A repeat push skips a file when two things hold: the two sides agree on
// which file it is, and the destination looks no older than the source. Those
// are separate mechanisms with separate failure modes, and when a repeat push
// starts re-sending an unchanged tree it is one or the other. The two tests
// below split them, so the next person reads a failure and knows which.
//
// The history: TestTransfer_RepeatPushSkipsUnchangedFiles passed on Linux and
// macOS and failed on Windows, re-sending every file. It was the identity, not
// the age — the index was keyed by absolute path, and a Windows sandbox spells
// the same file differently from the way this side composes it.

// TestTransferKey_AgreesAcrossSeparatorSpellings is the identity half.
//
// Both sides of a push describe the same file, one from a local filepath.WalkDir
// and one from the sandbox's own walk. If those two spellings do not reduce to
// one key, nothing is ever recognised as already sent.
func TestTransferKey_AgreesAcrossSeparatorSpellings(t *testing.T) {
	for _, tc := range []struct {
		name       string
		local      string
		remote     string
		want       string
		wantEquals bool
	}{
		{
			name:       "a nested path spelled by each platform's separator is one file",
			local:      "cmd/app/main.go",
			remote:     `cmd\app\main.go`,
			want:       "cmd/app/main.go",
			wantEquals: true,
		},
		{
			name:       "a leading current-directory marker is not part of the identity",
			local:      "./go.mod",
			remote:     "go.mod",
			want:       "go.mod",
			wantEquals: true,
		},
		{
			name:       "a leading or trailing separator is not part of the identity",
			local:      "/internal/lib/lib.go",
			remote:     `internal\lib\lib.go`,
			want:       "internal/lib/lib.go",
			wantEquals: true,
		},
		{
			name:       "different files stay different",
			local:      "cmd/app/main.go",
			remote:     "cmd/app/other.go",
			wantEquals: false,
		},
		{
			// Folding case here would make these one key, and the second file
			// would then be skipped as unchanged when it is a different file
			// entirely. A redundant re-send is cheap; a skipped change is wrong.
			name:       "case is preserved, because whether a filesystem folds it is not ours to guess",
			local:      "README.md",
			remote:     "readme.md",
			wantEquals: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local, remote := transferKey(tc.local), transferKey(tc.remote)
			if tc.wantEquals {
				assert.Equal(t, tc.want, local)
				assert.Equal(t, tc.want, remote)
				assert.Equal(t, local, remote, "the two sides must reduce to one key")
				return
			}
			assert.NotEqual(t, local, remote)
		})
	}
}

// TestUnchangedRemote_ComparesSizeThenAge is the age half.
//
// The rule is rsync's quick check minus the modification time this protocol
// has no field to preserve: same size, and the copy at the destination is no
// older than the source.
func TestUnchangedRemote_ComparesSizeThenAge(t *testing.T) {
	source := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	entry := transferEntry{rel: "go.mod", size: 100, modified: source}

	remote := func(size uint64, modified time.Time) *sandboxdv1.FileMetadata {
		return &sandboxdv1.FileMetadata{SizeBytes: size, ModifiedAt: timestamppb.New(modified)}
	}

	assert.True(t, unchangedRemote(remote(100, source.Add(time.Minute)), entry),
		"same size and a destination written after the source is the ordinary repeat push")
	assert.True(t, unchangedRemote(remote(100, source), entry),
		"equal timestamps count as unchanged; a push and the file it came from can land in the same tick")
	assert.False(t, unchangedRemote(remote(100, source.Add(-time.Minute)), entry),
		"a destination older than the source has not seen this version")
	assert.False(t, unchangedRemote(remote(101, source.Add(time.Minute)), entry),
		"a different size is a different file whatever the timestamps say")

	assert.False(t, unchangedRemote(nil, entry),
		"nothing at the destination is never unchanged — this is also what a missed index lookup produces")
	assert.False(t, unchangedRemote(&sandboxdv1.FileMetadata{SizeBytes: 100}, entry),
		"a sandbox that reports no modification time cannot be compared, so the file is re-sent")
	assert.False(t, unchangedRemote(&sandboxdv1.FileMetadata{
		SizeBytes: 100, IsDir: true, ModifiedAt: timestamppb.New(source.Add(time.Minute)),
	}, entry), "a directory where a file should be is not an unchanged file")
}
