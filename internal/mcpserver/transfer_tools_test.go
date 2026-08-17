package mcpserver_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver/tools"
)

// transferResult mirrors tools.TransferResult for decoding.
type transferResult struct {
	Sandbox      string `json:"sandbox"`
	Direction    string `json:"direction"`
	Source       string `json:"source"`
	Destination  string `json:"destination"`
	Files        int    `json:"files"`
	Bytes        uint64 `json:"bytes"`
	Size         string `json:"size"`
	Unchanged    int    `json:"unchanged"`
	Excluded     int    `json:"excluded"`
	SkippedCount int    `json:"skipped_count"`
	Skipped      []struct {
		Path   string `json:"path"`
		Reason string `json:"reason"`
	} `json:"skipped"`
	Note string `json:"note"`
}

// localWorkspace makes a temporary directory the process's working directory
// for the test, which is what the local write confinement is measured against.
func localWorkspace(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	// The directory as os.Getwd reports it, which is what the refusal message
	// names. The confinement itself compares fully resolved paths — a macOS
	// temp directory reaches the caller through at least one symlink — but
	// that is the check's business, not the caller's.
	wd, err := os.Getwd()
	require.NoError(t, err)
	return wd
}

func writeLocal(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), mode))
}

// ------------------------------------------------------------------ push

// TestTransfer_PushesASingleFileByteForByte.
func TestTransfer_PushesASingleFileByteForByte(t *testing.T) {
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	source := filepath.Join(local, "main.go")
	content := "package main\n\nfunc main() {}\n"
	writeLocal(t, source, content, 0o644)
	destination := f.path("main.go")

	out := structured[transferResult](t, f.ok("fleet_transfer", map[string]any{
		"direction": "push", "source": source, "destination": destination,
	}))

	assert.Equal(t, 1, out.Files)
	assert.Equal(t, uint64(len(content)), out.Bytes)
	assert.Equal(t, "build-box", out.Sandbox)

	landed, err := os.ReadFile(destination)
	require.NoError(t, err)
	assert.Equal(t, content, string(landed))
}

// TestTransfer_PushesATreeWithStructurePreserved, and honours the default
// excludes while doing it.
func TestTransfer_PushesATreeWithStructurePreserved(t *testing.T) {
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	project := filepath.Join(local, "project")
	writeLocal(t, filepath.Join(project, "go.mod"), "module x\n", 0o644)
	writeLocal(t, filepath.Join(project, "cmd", "app", "main.go"), "package main\n", 0o644)
	writeLocal(t, filepath.Join(project, "internal", "lib", "lib.go"), "package lib\n", 0o644)
	// Two things nobody means to copy.
	writeLocal(t, filepath.Join(project, ".git", "HEAD"), "ref: refs/heads/main\n", 0o644)
	writeLocal(t, filepath.Join(project, "node_modules", "left-pad", "index.js"), "module.exports=1\n", 0o644)

	destination := f.path("workspace")
	out := structured[transferResult](t, f.ok("fleet_transfer", map[string]any{
		"direction": "push", "source": project, "destination": destination, "recursive": true,
	}))

	assert.Equal(t, 3, out.Files)
	assert.Positive(t, out.Excluded)
	assert.Contains(t, out.Note, "exclude pattern")

	for _, rel := range []string{"go.mod", "cmd/app/main.go", "internal/lib/lib.go"} {
		assert.FileExists(t, filepath.Join(destination, filepath.FromSlash(rel)))
	}
	assert.NoDirExists(t, filepath.Join(destination, ".git"))
	assert.NoDirExists(t, filepath.Join(destination, "node_modules"))
}

// TestTransfer_DirectoryWithoutRecursiveIsRefused rather than silently
// transferring nothing.
func TestTransfer_DirectoryWithoutRecursiveIsRefused(t *testing.T) {
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})
	writeLocal(t, filepath.Join(local, "tree", "a.txt"), "a\n", 0o644)

	text := f.fails("fleet_transfer", map[string]any{
		"direction": "push", "source": filepath.Join(local, "tree"), "destination": f.path("tree"),
	})

	assert.Contains(t, text, "recursive")
}

// TestTransfer_CallerExcludePatternsAreHonoured, on top of the defaults.
func TestTransfer_CallerExcludePatternsAreHonoured(t *testing.T) {
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	project := filepath.Join(local, "project")
	writeLocal(t, filepath.Join(project, "keep.go"), "package p\n", 0o644)
	writeLocal(t, filepath.Join(project, "skip.log"), "noise\n", 0o644)
	writeLocal(t, filepath.Join(project, "logs", "deep.log"), "noise\n", 0o644)

	destination := f.path("workspace")
	out := structured[transferResult](t, f.ok("fleet_transfer", map[string]any{
		"direction": "push", "source": project, "destination": destination,
		"recursive": true, "exclude": []any{"*.log"},
	}))

	assert.Equal(t, 1, out.Files)
	assert.Equal(t, 2, out.Excluded)
	assert.FileExists(t, filepath.Join(destination, "keep.go"))
	assert.NoFileExists(t, filepath.Join(destination, "skip.log"))
}

// TestTransfer_AnInvalidExcludePatternIsRefused. A caller who wrote
// exclude=["build["] believes build is excluded; a pattern that silently
// matches nothing is worse than no pattern.
func TestTransfer_AnInvalidExcludePatternIsRefused(t *testing.T) {
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})
	writeLocal(t, filepath.Join(local, "a.txt"), "a\n", 0o644)

	text := f.fails("fleet_transfer", map[string]any{
		"direction": "push", "source": filepath.Join(local, "a.txt"),
		"destination": f.path("a.txt"), "exclude": []any{"build["},
	})

	assert.Contains(t, text, "build[")
	assert.Contains(t, text, "glob")
}

// TestTransfer_ExecutableBitSurvivesAPush. A build script that arrives
// non-executable fails in a way that reads as a broken script.
func TestTransfer_ExecutableBitSurvivesAPush(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no executable bit to preserve")
	}
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	source := filepath.Join(local, "build.sh")
	writeLocal(t, source, "#!/bin/sh\nexit 0\n", 0o755)
	destination := f.path("build.sh")

	f.ok("fleet_transfer", map[string]any{
		"direction": "push", "source": source, "destination": destination,
	})

	info, err := os.Stat(destination)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode().Perm()&0o111, "the pushed script must still be executable, got %s", info.Mode())
}

// TestTransfer_ASymlinkOutOfTheSourceTreeIsSkippedAndReported.
//
// Following it silently is how "push my project" becomes "push my home
// directory", and dropping it silently is how a model concludes a file it can
// see locally simply failed to arrive.
func TestTransfer_ASymlinkOutOfTheSourceTreeIsSkippedAndReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a symlink on Windows needs a privilege CI does not grant")
	}
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	outside := filepath.Join(local, "outside", "secret.txt")
	writeLocal(t, outside, "not yours\n", 0o600)

	project := filepath.Join(local, "project")
	writeLocal(t, filepath.Join(project, "inside.txt"), "fine\n", 0o644)
	writeLocal(t, filepath.Join(project, "sub", "target.txt"), "also fine\n", 0o644)
	require.NoError(t, os.Symlink(outside, filepath.Join(project, "escape.txt")))
	require.NoError(t, os.Symlink(filepath.Join(project, "sub", "target.txt"), filepath.Join(project, "internal-link.txt")))

	destination := f.path("workspace")
	out := structured[transferResult](t, f.ok("fleet_transfer", map[string]any{
		"direction": "push", "source": project, "destination": destination, "recursive": true,
	}))

	require.Equal(t, 1, out.SkippedCount, "exactly the escaping link is skipped")
	assert.Equal(t, "escape.txt", out.Skipped[0].Path)
	assert.Contains(t, out.Skipped[0].Reason, "outside the source tree")
	assert.Contains(t, out.Skipped[0].Reason, outside, "and names what it pointed at")

	assert.NoFileExists(t, filepath.Join(destination, "escape.txt"), "the escaping link must not have been followed")
	// A link that stays inside is followed, or a repository full of them
	// transfers as a tree of holes.
	assert.FileExists(t, filepath.Join(destination, "internal-link.txt"))
	assert.FileExists(t, filepath.Join(destination, "inside.txt"))
}

// TestTransfer_RepeatPushSkipsUnchangedFiles. push, edit, push again is the
// workflow; re-sending an unchanged tree each time is the difference between
// usable and not.
//
// When this fails, the cause is one of two mechanisms, and the unit tests in
// tools/transfer_test.go separate them: TestTransferKey_… covers whether the
// two sides agree which file is which, and TestUnchangedRemote_… covers
// whether the destination looks older than the source. This test cannot tell
// them apart — both produce a re-sent file — so read those first.
func TestTransfer_RepeatPushSkipsUnchangedFiles(t *testing.T) {
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	project := filepath.Join(local, "project")
	writeLocal(t, filepath.Join(project, "a.go"), "package a\n", 0o644)
	writeLocal(t, filepath.Join(project, "b.go"), "package b\n", 0o644)
	destination := f.path("workspace")

	args := map[string]any{
		"direction": "push", "source": project, "destination": destination, "recursive": true,
	}
	first := structured[transferResult](t, f.ok("fleet_transfer", args))
	require.Equal(t, 2, first.Files)

	second := structured[transferResult](t, f.ok("fleet_transfer", args))
	assert.Zero(t, second.Files, "an unchanged tree must not be re-sent")
	assert.Equal(t, 2, second.Unchanged)
	assert.Contains(t, second.Note, "force")

	// Edit one file and it goes again — the other still does not.
	time.Sleep(1100 * time.Millisecond) // filesystem timestamp granularity
	writeLocal(t, filepath.Join(project, "a.go"), "package a // changed\n", 0o644)
	third := structured[transferResult](t, f.ok("fleet_transfer", args))
	assert.Equal(t, 1, third.Files)
	assert.Equal(t, 1, third.Unchanged)

	landed, err := os.ReadFile(filepath.Join(destination, "a.go"))
	require.NoError(t, err)
	assert.Equal(t, "package a // changed\n", string(landed))

	// And force sends everything regardless.
	forced := map[string]any{"force": true}
	for k, v := range args {
		forced[k] = v
	}
	fourth := structured[transferResult](t, f.ok("fleet_transfer", forced))
	assert.Equal(t, 2, fourth.Files)
	assert.Zero(t, fourth.Unchanged)
}

// TestTransfer_RepeatPushSkipsUnchangedFilesWhateverTheDestinationIsSpelledLike.
//
// This is the Windows failure, reproduced portably. There, the tool composed
// destination paths with the sandbox's cached separator while the agent's own
// walk answered with backslashes, so the two sides described every file with
// two different strings and nothing was ever recognised as already sent — a
// tree re-uploaded in full on every push, silently, on one platform only.
//
// A separator cannot be varied portably (a backslash is an ordinary filename
// character on Unix), but the *class* of bug can: any destination the agent
// normalises to something other than the bytes it was given produces exactly
// the same divergence. A path with a `..` segment in it does that on every
// platform. If the identity ever goes back to being an absolute path, this
// fails everywhere rather than only on the one runner nobody reads.
func TestTransfer_RepeatPushSkipsUnchangedFilesWhateverTheDestinationIsSpelledLike(t *testing.T) {
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	project := filepath.Join(local, "project")
	writeLocal(t, filepath.Join(project, "go.mod"), "module x\n", 0o644)
	writeLocal(t, filepath.Join(project, "cmd", "app", "main.go"), "package main\n", 0o644)

	// Two spellings of one directory: the plain one, and one the agent must
	// clean before it means anything.
	//
	// Built by concatenation, not filepath.Join, which is the whole point —
	// Join cleans, so a roundabout path handed to it arrives at the tool
	// already collapsed and the test proves nothing. (It did, until a revert
	// check showed it passing against the very bug it was written for.)
	plain := f.path("workspace")
	sep := string(filepath.Separator)
	roundabout := plain + sep + ".." + sep + "workspace"

	first := structured[transferResult](t, f.ok("fleet_transfer", map[string]any{
		"direction": "push", "source": project, "destination": plain, "recursive": true,
	}))
	require.Equal(t, 2, first.Files)

	second := structured[transferResult](t, f.ok("fleet_transfer", map[string]any{
		"direction": "push", "source": project, "destination": roundabout, "recursive": true,
	}))
	assert.Zero(t, second.Files,
		"the same tree under another spelling of the same destination must not be re-sent")
	assert.Equal(t, 2, second.Unchanged)

	// And the reverse order, so neither spelling is privileged.
	third := structured[transferResult](t, f.ok("fleet_transfer", map[string]any{
		"direction": "push", "source": project, "destination": plain, "recursive": true,
	}))
	assert.Zero(t, third.Files)
	assert.Equal(t, 2, third.Unchanged)
}

// ------------------------------------------------------------------ pull

// TestTransfer_PullsASingleFileByteForByte.
func TestTransfer_PullsASingleFileByteForByte(t *testing.T) {
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	source := f.path("report.txt")
	content := "line one\nline two\n"
	writeRemote(t, source, content)
	destination := filepath.Join(local, "report.txt")

	out := structured[transferResult](t, f.ok("fleet_transfer", map[string]any{
		"direction": "pull", "source": source, "destination": destination,
	}))

	assert.Equal(t, 1, out.Files)
	assert.Equal(t, uint64(len(content)), out.Bytes)

	landed, err := os.ReadFile(destination)
	require.NoError(t, err)
	assert.Equal(t, content, string(landed))
}

// TestTransfer_PullsATreeWithStructurePreserved.
func TestTransfer_PullsATreeWithStructurePreserved(t *testing.T) {
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	remote := f.path("results")
	writeRemote(t, filepath.Join(remote, "summary.txt"), "ok\n")
	writeRemote(t, filepath.Join(remote, "logs", "run.log"), "started\n")
	writeRemote(t, filepath.Join(remote, "node_modules", "junk.js"), "1\n")

	destination := filepath.Join(local, "pulled")
	out := structured[transferResult](t, f.ok("fleet_transfer", map[string]any{
		"direction": "pull", "source": remote, "destination": destination, "recursive": true,
	}))

	assert.Equal(t, 2, out.Files)
	assert.Positive(t, out.Excluded)
	assert.FileExists(t, filepath.Join(destination, "summary.txt"))
	assert.FileExists(t, filepath.Join(destination, "logs", "run.log"))
	assert.NoDirExists(t, filepath.Join(destination, "node_modules"))
}

// TestTransfer_ExecutableBitSurvivesAPull.
func TestTransfer_ExecutableBitSurvivesAPull(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no executable bit to preserve")
	}
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	source := f.path("run.sh")
	writeRemote(t, source, "#!/bin/sh\n")
	require.NoError(t, os.Chmod(source, 0o755))
	destination := filepath.Join(local, "run.sh")

	f.ok("fleet_transfer", map[string]any{"direction": "pull", "source": source, "destination": destination})

	info, err := os.Stat(destination)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode().Perm()&0o111, "the pulled script must be executable, got %s", info.Mode())
}

// TestTransfer_ARemoteSymlinkIsSkippedAndReported. ReadFile follows a link
// server-side, so pulling one would quietly copy whatever it points at under
// the link's name.
func TestTransfer_ARemoteSymlinkIsSkippedAndReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a symlink on Windows needs a privilege CI does not grant")
	}
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	remote := f.path("results")
	writeRemote(t, filepath.Join(remote, "real.txt"), "real\n")
	outside := f.path("elsewhere.txt")
	writeRemote(t, outside, "elsewhere\n")
	require.NoError(t, os.Symlink(outside, filepath.Join(remote, "link.txt")))

	destination := filepath.Join(local, "pulled")
	out := structured[transferResult](t, f.ok("fleet_transfer", map[string]any{
		"direction": "pull", "source": remote, "destination": destination, "recursive": true,
	}))

	assert.Equal(t, 1, out.Files)
	require.Equal(t, 1, out.SkippedCount)
	assert.Equal(t, "link.txt", out.Skipped[0].Path)
	assert.Contains(t, out.Skipped[0].Reason, "symlink")
	assert.NoFileExists(t, filepath.Join(destination, "link.txt"))
}

// ---------------------------------------------------- the local side

// TestTransfer_PullOutsideTheWorkingDirectoryIsRefused.
//
// The sandbox has an agent deciding what a caller may touch. This side has
// nothing, so a pull with a destination of /etc has to be refused rather than
// executed — and the refusal has to name the way to do it deliberately, or the
// model will simply try a different spelling of the same path.
func TestTransfer_PullOutsideTheWorkingDirectoryIsRefused(t *testing.T) {
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	source := f.path("payload.txt")
	writeRemote(t, source, "payload\n")
	outside := filepath.Join(t.TempDir(), "escaped.txt")

	text := f.fails("fleet_transfer", map[string]any{
		"direction": "pull", "source": source, "destination": outside,
	})

	assert.Contains(t, text, "outside this workstation's working directory")
	assert.Contains(t, text, local, "the refusal names where writes are allowed")
	assert.Contains(t, text, "allow_outside_working_dir", "and how to mean it on purpose")
	assert.NoFileExists(t, outside, "nothing may be written before the check")

	// The override is a real escape hatch, not a message with nothing behind
	// it.
	f.ok("fleet_transfer", map[string]any{
		"direction": "pull", "source": source, "destination": outside, "allow_outside_working_dir": true,
	})
	assert.FileExists(t, outside)
}

// namingFiles serves a directory listing whose entry names are the caller's,
// and a one-chunk read for any file in it. It stands in for a sandbox holding
// files somebody chose the names of — which is every sandbox, since the point
// of one is running code that writes files.
type namingFiles struct {
	sandboxdv1.FileServiceClient
	root  string
	names []string
}

func (n *namingFiles) StatPath(_ context.Context, in *sandboxdv1.StatPathRequest, _ ...grpc.CallOption) (*sandboxdv1.StatPathResponse, error) {
	return &sandboxdv1.StatPathResponse{Exists: true, Metadata: &sandboxdv1.FileMetadata{
		Path: in.GetPath(), IsDir: true, ModifiedAt: timestamppb.Now(),
	}}, nil
}

func (n *namingFiles) ListDirectory(_ context.Context, _ *sandboxdv1.ListDirectoryRequest, _ ...grpc.CallOption) (*sandboxdv1.ListDirectoryResponse, error) {
	resp := &sandboxdv1.ListDirectoryResponse{Path: n.root}
	for _, name := range n.names {
		resp.Entries = append(resp.Entries, &sandboxdv1.FileMetadata{
			// Composed the way the agent's own walk composes one: the resolved
			// root, a separator, then the name as it is on disk.
			Path: n.root + "/" + name, SizeBytes: 7, Mode: 0o644, ModifiedAt: timestamppb.Now(),
		})
	}
	return resp, nil
}

func (n *namingFiles) ReadFile(context.Context, *sandboxdv1.ReadFileRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[sandboxdv1.ReadFileResponse], error) {
	return &recvStream[sandboxdv1.ReadFileResponse]{messages: []*sandboxdv1.ReadFileResponse{
		{Event: &sandboxdv1.ReadFileResponse_Chunk{Chunk: []byte("owned!\n")}},
		{Event: &sandboxdv1.ReadFileResponse_Result{Result: &sandboxdv1.ReadResult{}}},
	}}, nil
}

// TestTransfer_APulledNameCannotEscapeTheDestination.
//
// The names in a pulled tree come from the sandbox, and a sandbox is the side
// of this system that runs code nobody vetted. Two of them are a way out of the
// destination directory:
//
//   - `..\..\x` is an ordinary filename on Linux, where a backslash is not a
//     separator. The normalisation that lets a Windows sandbox's
//     `cmd\app\main.go` mean `cmd/app/main.go` turns it into a traversal.
//   - `../x` outright, from an agent that is not the one this server thinks it
//     is talking to.
//
// Both used to be joined under the destination and written wherever they
// landed, which past two levels is outside the working directory the local
// confinement exists to enforce — the tool's one safety property on this side,
// bypassed by a filename. They are skipped and reported now, and the rest of
// the tree still arrives.
//
// Driven through a fake so it runs on every platform: the interesting name
// cannot be created on Windows, and the property is not Unix's.
func TestTransfer_APulledNameCannotEscapeTheDestination(t *testing.T) {
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	remote := f.path("results")
	f.clients.filesOverride = &namingFiles{
		FileServiceClient: f.backend.files,
		root:              remote,
		names:             []string{"real.txt", `..\..\escaped.txt`, "../also-escaped.txt"},
	}

	destination := filepath.Join(local, "pulled")
	out := structured[transferResult](t, f.ok("fleet_transfer", map[string]any{
		"direction": "pull", "source": remote, "destination": destination, "recursive": true,
	}))

	assert.Equal(t, 1, out.Files, "only the entry that stays inside the destination is transferred")
	assert.FileExists(t, filepath.Join(destination, "real.txt"))

	require.Equal(t, 2, out.SkippedCount, "and both escaping names are reported, not silently dropped")
	for _, skip := range out.Skipped {
		assert.Contains(t, skip.Reason, "inside the destination directory")
	}

	// The names resolve to a sibling of the working directory and to its
	// parent. Nothing may exist at either.
	assert.NoFileExists(t, filepath.Join(filepath.Dir(local), "escaped.txt"))
	assert.NoFileExists(t, filepath.Join(local, "also-escaped.txt"))
	assert.NoFileExists(t, filepath.Join(local, "escaped.txt"))
}

// TestTransfer_APulledEntryCannotEscapeThroughASymlinkedDirectory.
//
// The destination root is checked once, with its symlinks resolved. A
// *subdirectory* of it that is a link out is a second way through the same
// door: MkdirAll walks straight into it and the file lands wherever it points.
func TestTransfer_APulledEntryCannotEscapeThroughASymlinkedDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a symlink on Windows needs a privilege CI does not grant")
	}
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	remote := f.path("results")
	f.clients.filesOverride = &namingFiles{
		FileServiceClient: f.backend.files,
		root:              remote,
		names:             []string{"keep/real.txt", "logs/secret.txt"},
	}

	// The destination exists already, with one subdirectory pointing out of the
	// working directory — the shape a repeat pull into a prepared tree has.
	destination := filepath.Join(local, "pulled")
	escapeTarget := t.TempDir()
	require.NoError(t, os.MkdirAll(destination, 0o750))
	require.NoError(t, os.Symlink(escapeTarget, filepath.Join(destination, "logs")))

	out := structured[transferResult](t, f.ok("fleet_transfer", map[string]any{
		"direction": "pull", "source": remote, "destination": destination, "recursive": true,
	}))

	assert.Equal(t, 1, out.Files)
	assert.FileExists(t, filepath.Join(destination, "keep", "real.txt"))
	require.Equal(t, 1, out.SkippedCount)
	assert.Contains(t, out.Skipped[0].Reason, "outside this workstation's working directory")
	assert.NoFileExists(t, filepath.Join(escapeTarget, "secret.txt"),
		"a link out of the working directory must not be written through")
}

// TestTransfer_ASymlinkedDestinationCannotEscapeTheWorkingDirectory. Checking
// the path as written would let a link inside the working directory point
// anywhere at all.
func TestTransfer_ASymlinkedDestinationCannotEscapeTheWorkingDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a symlink on Windows needs a privilege CI does not grant")
	}
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	source := f.path("payload.txt")
	writeRemote(t, source, "payload\n")

	escapeTarget := t.TempDir()
	require.NoError(t, os.Symlink(escapeTarget, filepath.Join(local, "way-out")))

	text := f.fails("fleet_transfer", map[string]any{
		"direction": "pull", "source": source, "destination": filepath.Join(local, "way-out", "landed.txt"),
	})

	assert.Contains(t, text, "outside this workstation's working directory")
	assert.NoFileExists(t, filepath.Join(escapeTarget, "landed.txt"))
}

// TestTransfer_APushDestinationOutsideTheJailIsRejected.
//
// The other side of the same coin: on the sandbox it is the agent's jail that
// decides, and this asserts the refusal reaches the model as the agent's own
// words — naming the roots — rather than as a transfer that reports zero files
// and no reason. Run with exec disabled, the one configuration in which an
// agent has a jail at all.
func TestTransfer_APushDestinationOutsideTheJailIsRejected(t *testing.T) {
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{execDisabled: true})

	source := filepath.Join(local, "payload.txt")
	writeLocal(t, source, "payload\n", 0o644)
	outside := filepath.Join(t.TempDir(), "escaped.txt")

	text := f.fails("fleet_transfer", map[string]any{
		"direction": "push", "source": source, "destination": outside,
	})

	assert.Contains(t, text, "outside the allowed roots")
	assert.Contains(t, text, f.remote, "the refusal names the roots the model may use")
	assert.NoFileExists(t, outside)
}

// TestTransfer_PushIsNotConfinedToTheWorkingDirectory. The confinement is on
// local *writes*: a model that can call this tool can already read any local
// file with its own built-in tools, so refusing a source outside the working
// directory would add friction and no safety.
func TestTransfer_PushIsNotConfinedToTheWorkingDirectory(t *testing.T) {
	localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	elsewhere := filepath.Join(t.TempDir(), "from-elsewhere.txt")
	writeLocal(t, elsewhere, "content\n", 0o644)

	out := structured[transferResult](t, f.ok("fleet_transfer", map[string]any{
		"direction": "push", "source": elsewhere, "destination": f.path("arrived.txt"),
	}))
	assert.Equal(t, 1, out.Files)
	assert.FileExists(t, f.path("arrived.txt"))
}

// ------------------------------------------------------------- limits

// TestTransfer_FileCountCapNamesTheLimit rather than running for ten minutes.
func TestTransfer_FileCountCapNamesTheLimit(t *testing.T) {
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	project := filepath.Join(local, "many")
	for i := range tools.MaxTransferFiles + 5 {
		writeLocal(t, filepath.Join(project, fmt.Sprintf("f%05d.txt", i)), "x", 0o644)
	}

	text := f.fails("fleet_transfer", map[string]any{
		"direction": "push", "source": project, "destination": f.path("many"), "recursive": true,
	})

	assert.Contains(t, text, fmt.Sprintf("%d files", tools.MaxTransferFiles), "the error must name the limit")
	assert.Contains(t, text, "exclude", "and how to get under it")
	assert.NoDirExists(t, f.path("many"), "nothing may be sent before the cap is checked")
}

// TestTransfer_MissingSourceSaysWhichSideItLookedOn. Getting the direction
// backwards is the mistake this tool invites, and "no such file" alone sends
// the model looking on the wrong machine.
func TestTransfer_MissingSourceSaysWhichSideItLookedOn(t *testing.T) {
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	text := f.fails("fleet_transfer", map[string]any{
		"direction": "push", "source": filepath.Join(local, "nope.txt"), "destination": f.path("nope.txt"),
	})
	assert.Contains(t, text, "this workstation")
	assert.Contains(t, text, "use pull")

	text = f.fails("fleet_transfer", map[string]any{
		"direction": "pull", "source": f.path("nope.txt"), "destination": filepath.Join(local, "nope.txt"),
	})
	assert.Contains(t, text, "sandbox build-box")
	assert.Contains(t, text, "use push")
}

// TestTransfer_BadDirectionIsRefusedWithTheTwoThatWork.
func TestTransfer_BadDirectionIsRefusedWithTheTwoThatWork(t *testing.T) {
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})
	writeLocal(t, filepath.Join(local, "a.txt"), "a\n", 0o644)

	text := f.fails("fleet_transfer", map[string]any{
		"direction": "upload", "source": filepath.Join(local, "a.txt"), "destination": f.path("a.txt"),
	})

	assert.Contains(t, text, "push")
	assert.Contains(t, text, "pull")
}

// --------------------------------------------------------------- memory

// TestTransfer_APulledFileIsNeverHeldWhole.
//
// #25 asks that a large file transfer without this process's memory tracking
// its size. The code streams, and it will keep looking like it streams after
// someone puts an io.ReadAll in the middle of it, so the property is asserted
// rather than described. The measurement is internal/agent/fs's: peak live
// heap sampled while the content is still moving, because an implementation
// that buffered the file and released it at the end shows nothing afterwards.
func TestTransfer_APulledFileIsNeverHeldWhole(t *testing.T) {
	if testing.Short() {
		t.Skip("moves 64 MiB")
	}
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	source := f.path("large.bin")
	writeGeneratedFile(t, source, heapPayload)
	destination := filepath.Join(local, "large.bin")

	// A 64 MiB file arrives as a thousand 64 KiB chunks; sampling every
	// sixteenth keeps sixty-odd collections rather than a thousand. The
	// baseline is taken when the handler starts, not here.
	sampler := &heapSampler{every: 16}
	f.clients.onFiles = sampler.start
	f.clients.filesOverride = &samplingFiles{FileServiceClient: f.backend.files, sampler: sampler}

	out := structured[transferResult](t, f.ok("fleet_transfer", map[string]any{
		"direction": "pull", "source": source, "destination": destination,
	}))

	require.Equal(t, 1, out.Files)
	require.Equal(t, uint64(heapPayload), out.Bytes)
	require.Greater(t, sampler.ticks, 512, "a 64 MiB file has to arrive as many chunks, not one")

	info, err := os.Stat(destination)
	require.NoError(t, err)
	require.Equal(t, int64(heapPayload), info.Size(), "and all of it has to land")

	assertHeapBounded(t, sampler, heapPayload, "fleet_transfer pull")
}

// TestTransfer_APushedFileIsNeverHeldWhole, the same property in the other
// direction. The push path reads the local file in chunks and sends each one;
// holding the file whole would be an io.ReadAll of the source.
func TestTransfer_APushedFileIsNeverHeldWhole(t *testing.T) {
	if testing.Short() {
		t.Skip("moves 64 MiB")
	}
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	source := filepath.Join(local, "large.bin")
	writeGeneratedFile(t, source, heapPayload)
	destination := f.path("large.bin")

	sampler := &heapSampler{every: 16}
	f.clients.onFiles = sampler.start
	f.clients.filesOverride = &samplingFiles{FileServiceClient: f.backend.files, sampler: sampler}

	out := structured[transferResult](t, f.ok("fleet_transfer", map[string]any{
		"direction": "push", "source": source, "destination": destination,
	}))

	require.Equal(t, 1, out.Files)
	require.Equal(t, uint64(heapPayload), out.Bytes)
	require.Greater(t, sampler.ticks, 512, "a 64 MiB file has to be sent as many chunks, not one")

	info, err := os.Stat(destination)
	require.NoError(t, err)
	require.Equal(t, int64(heapPayload), info.Size())

	assertHeapBounded(t, sampler, heapPayload, "fleet_transfer push")
}

// truncatingFiles serves a ReadFile stream that delivers one chunk and then
// reports the read as truncated, which is what an agent does when it hits its
// own read cap.
type truncatingFiles struct {
	sandboxdv1.FileServiceClient
}

func (t *truncatingFiles) ReadFile(context.Context, *sandboxdv1.ReadFileRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[sandboxdv1.ReadFileResponse], error) {
	return &recvStream[sandboxdv1.ReadFileResponse]{messages: []*sandboxdv1.ReadFileResponse{
		{Event: &sandboxdv1.ReadFileResponse_Chunk{Chunk: []byte("the first part only")}},
		{Event: &sandboxdv1.ReadFileResponse_Result{Result: &sandboxdv1.ReadResult{
			Truncation: &sandboxdv1.Truncation{Truncated: true, BytesOmitted: 4096},
		}}},
	}}, nil
}

// TestTransfer_ATruncatedReadIsNotCommitted.
//
// A truncated read is a failed transfer, not a smaller file. Renaming the
// partial copy into place under the real name is worse than failing: every
// later reader treats it as whole, and so does the unchanged check on the next
// push, which compares sizes and would then never correct it.
func TestTransfer_ATruncatedReadIsNotCommitted(t *testing.T) {
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	source := f.path("big.bin")
	writeRemote(t, source, strings.Repeat("z", 8192))
	destination := filepath.Join(local, "big.bin")

	f.clients.filesOverride = &truncatingFiles{FileServiceClient: f.backend.files}

	text := f.fails("fleet_transfer", map[string]any{
		"direction": "pull", "source": source, "destination": destination,
	})

	assert.Contains(t, text, "truncated")
	assert.NoFileExists(t, destination, "a truncated read must not be renamed into place")
}

// resultlessFiles serves a ReadFile stream that delivers a chunk and then ends
// cleanly, with no result message. It is the shape of a read that stopped
// early without anything raising an error — a stream cut by something in the
// middle, or an agent that is not the one this server believes it is talking
// to. The bytes that arrived are a prefix of the file, and nothing in them says
// so.
type resultlessFiles struct {
	sandboxdv1.FileServiceClient
}

func (r *resultlessFiles) ReadFile(context.Context, *sandboxdv1.ReadFileRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[sandboxdv1.ReadFileResponse], error) {
	return &recvStream[sandboxdv1.ReadFileResponse]{messages: []*sandboxdv1.ReadFileResponse{
		{Event: &sandboxdv1.ReadFileResponse_Chunk{Chunk: []byte("the first part only")}},
	}}, nil
}

// TestTransfer_AReadThatNeverReportedAResultIsNotCommitted.
//
// The truncation check catches a read the sandbox *said* it cut short. This is
// the same partial file arriving without that admission: the getters are all
// nil-safe, so an absent result reads as "not truncated" and the prefix is
// renamed into place under the real name. Every later reader treats it as
// whole, and so does the next push's unchanged check, which compares sizes and
// would never correct it.
func TestTransfer_AReadThatNeverReportedAResultIsNotCommitted(t *testing.T) {
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	source := f.path("big.bin")
	writeRemote(t, source, strings.Repeat("z", 8192))
	destination := filepath.Join(local, "big.bin")

	f.clients.filesOverride = &resultlessFiles{FileServiceClient: f.backend.files}

	text := f.fails("fleet_transfer", map[string]any{
		"direction": "pull", "source": source, "destination": destination,
	})

	assert.Contains(t, text, "without reporting a result")
	assert.NoFileExists(t, destination, "a read that never finished must not be renamed into place")
}

// symlinkSourceFiles answers StatPath with a symlink, which is what the agent
// reports for one: metadata describing the *link*, not its target.
type symlinkSourceFiles struct {
	sandboxdv1.FileServiceClient
}

func (s *symlinkSourceFiles) StatPath(_ context.Context, in *sandboxdv1.StatPathRequest, _ ...grpc.CallOption) (*sandboxdv1.StatPathResponse, error) {
	return &sandboxdv1.StatPathResponse{Exists: true, Metadata: &sandboxdv1.FileMetadata{
		Path: in.GetPath(), SizeBytes: 11, Mode: 0o777, IsSymlink: true,
		SymlinkTarget: "/etc/shadow", ModifiedAt: timestamppb.Now(),
	}}, nil
}

// ReadFile answers as the agent does: it follows the link and returns the
// target's bytes. Without the refusal in front of it, that is what lands.
func (s *symlinkSourceFiles) ReadFile(context.Context, *sandboxdv1.ReadFileRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[sandboxdv1.ReadFileResponse], error) {
	return &recvStream[sandboxdv1.ReadFileResponse]{messages: []*sandboxdv1.ReadFileResponse{
		{Event: &sandboxdv1.ReadFileResponse_Chunk{Chunk: []byte("root:x:0:0\n")}},
		{Event: &sandboxdv1.ReadFileResponse_Result{Result: &sandboxdv1.ReadResult{}}},
	}}, nil
}

// TestTransfer_PullingASymlinkIsRefusedRatherThanFollowed.
//
// A recursive pull skips every link it walks past. A pull whose *source* is one
// used to follow it, and ReadFile follows links agent-side — so the file the
// link points at arrived under the link's name. Worse, the metadata describing
// a link is the link's own: its size, which the unchanged check then compares
// against, and its mode, which on Linux is 0777. "Pull that file" quietly
// produced a world-writable copy of something else.
func TestTransfer_PullingASymlinkIsRefusedRatherThanFollowed(t *testing.T) {
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})
	f.clients.filesOverride = &symlinkSourceFiles{FileServiceClient: f.backend.files}

	destination := filepath.Join(local, "landed.txt")
	text := f.fails("fleet_transfer", map[string]any{
		"direction": "pull", "source": f.path("link.txt"), "destination": destination,
	})

	assert.Contains(t, text, "symlink")
	assert.Contains(t, text, "/etc/shadow", "the refusal names what it points at")
	assert.NoFileExists(t, destination)
}

// --------------------------------------------------- interruption

// stallingFiles serves a ReadFile stream that delivers part of a file and then
// blocks, so a test can cancel a transfer half-way through one.
type stallingFiles struct {
	sandboxdv1.FileServiceClient
	started chan struct{}
}

func (s *stallingFiles) ReadFile(ctx context.Context, _ *sandboxdv1.ReadFileRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[sandboxdv1.ReadFileResponse], error) {
	return &stallingRead{ctx: ctx, started: s.started}, nil
}

type stallingRead struct {
	grpc.ClientStream
	ctx     context.Context
	started chan struct{}
	sent    bool
}

func (s *stallingRead) Recv() (*sandboxdv1.ReadFileResponse, error) {
	if !s.sent {
		s.sent = true
		close(s.started)
		return &sandboxdv1.ReadFileResponse{Event: &sandboxdv1.ReadFileResponse_Chunk{
			Chunk: []byte(strings.Repeat("partial ", 1024)),
		}}, nil
	}
	<-s.ctx.Done()
	return nil, s.ctx.Err()
}

// TestTransfer_AnInterruptedPullLeavesNoPartialFile.
//
// The destination is written through a temporary file and renamed, so a
// transfer cut off half way leaves nothing rather than a file that every later
// reader treats as complete.
func TestTransfer_AnInterruptedPullLeavesNoPartialFile(t *testing.T) {
	local := localWorkspace(t)
	f := newAgentFixture(t, backendOptions{})

	source := f.path("big.bin")
	writeRemote(t, source, strings.Repeat("z", 4096))
	destination := filepath.Join(local, "big.bin")

	started := make(chan struct{})
	f.clients.filesOverride = &stallingFiles{FileServiceClient: f.backend.files, started: started}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = f.session.CallTool(ctx, &mcp.CallToolParams{Name: "fleet_transfer", Arguments: map[string]any{
			"direction": "pull", "source": source, "destination": destination,
		}})
	}()

	<-started
	cancel()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the cancelled transfer never returned")
	}

	assert.NoFileExists(t, destination, "an interrupted transfer must leave no file at the destination")

	// The temporary file is cleaned up by the handler, which the SDK does not
	// wait for when the caller cancels — so this polls for the end state
	// rather than assuming the handler has already unwound.
	require.Eventuallyf(t, func() bool {
		entries, err := os.ReadDir(local)
		if err != nil {
			return false
		}
		for _, entry := range entries {
			if strings.Contains(entry.Name(), ".part") {
				return false
			}
		}
		return true
	}, 30*time.Second, 20*time.Millisecond, "a partial file was left behind in %s", local)
}
