package mcpserver_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver/tools"
)

// Mirrors of the tool results, for decoding.
type (
	truncationView struct {
		Truncated    bool   `json:"truncated"`
		BytesOmitted uint64 `json:"bytes_omitted"`
		LinesOmitted uint64 `json:"lines_omitted"`
		Note         string `json:"note"`
	}

	readResult struct {
		Sandbox         string          `json:"sandbox"`
		Path            string          `json:"path"`
		Content         string          `json:"content"`
		ContentBase64   string          `json:"content_base64"`
		FirstLine       int             `json:"first_line"`
		LinesReturned   uint64          `json:"lines_returned"`
		TotalLines      uint64          `json:"total_lines"`
		TotalLinesExact bool            `json:"total_lines_exact"`
		Size            string          `json:"size"`
		Truncation      *truncationView `json:"truncation"`
		Note            string          `json:"note"`
	}

	writeResult struct {
		Sandbox      string `json:"sandbox"`
		Path         string `json:"path"`
		BytesWritten uint64 `json:"bytes_written"`
		Created      bool   `json:"created"`
		Note         string `json:"note"`
	}

	editResult struct {
		Sandbox      string `json:"sandbox"`
		Path         string `json:"path"`
		Replacements uint32 `json:"replacements"`
		Diff         string `json:"diff"`
	}

	lsResult struct {
		Sandbox     string   `json:"sandbox"`
		Path        string   `json:"path"`
		Directories []string `json:"directories"`
		Files       []struct {
			Name     string `json:"name"`
			Size     string `json:"size"`
			Modified string `json:"modified"`
			Symlink  string `json:"symlink"`
		} `json:"files"`
		Truncation *truncationView `json:"truncation"`
		Note       string          `json:"note"`
	}

	globResult struct {
		Sandbox    string          `json:"sandbox"`
		Pattern    string          `json:"pattern"`
		Paths      []string        `json:"paths"`
		Matches    int             `json:"matches"`
		Truncation *truncationView `json:"truncation"`
		Note       string          `json:"note"`
	}

	grepResult struct {
		Sandbox       string          `json:"sandbox"`
		Pattern       string          `json:"pattern"`
		Matches       []string        `json:"matches"`
		Files         []string        `json:"files"`
		MatchCount    uint64          `json:"match_count"`
		FilesSearched uint64          `json:"files_searched"`
		Truncation    *truncationView `json:"truncation"`
		Note          string          `json:"note"`
	}
)

func writeRemote(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

// ------------------------------------------------------------------ read

// TestRead_IsLineNumberedInTheShapeOfTheBuiltInRead. The native tool renders
// the line number right-aligned in six columns followed by a tab, and a model
// that has learned to read that shape must not have to relearn it here.
func TestRead_IsLineNumberedInTheShapeOfTheBuiltInRead(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{})
	path := f.path("main.go")
	writeRemote(t, path, "package main\n\nfunc main() {}\n")

	out := structured[readResult](t, f.ok("fleet_read", map[string]any{"path": path}))

	assert.Equal(t, "     1\tpackage main\n     2\t\n     3\tfunc main() {}\n", out.Content)
	assert.Equal(t, 1, out.FirstLine)
	assert.Equal(t, uint64(3), out.LinesReturned)
	assert.Equal(t, uint64(3), out.TotalLines)
	assert.True(t, out.TotalLinesExact)
	assert.Equal(t, "build-box", out.Sandbox)
	assert.Empty(t, out.Note, "a complete small file needs no explanation")
}

// TestRead_OffsetAndLimitWindowTheFileAndReportTheWhole.
func TestRead_OffsetAndLimitWindowTheFileAndReportTheWhole(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{})
	path := f.path("many.txt")

	var content strings.Builder
	for i := 1; i <= 100; i++ {
		fmt.Fprintf(&content, "line %d\n", i)
	}
	writeRemote(t, path, content.String())

	out := structured[readResult](t, f.ok("fleet_read", map[string]any{
		"path": path, "offset": 40, "limit": 3,
	}))

	assert.Equal(t, "    40\tline 40\n    41\tline 41\n    42\tline 42\n", out.Content,
		"the numbering must be the file's own, not the window's")
	assert.Equal(t, 40, out.FirstLine)
	assert.Equal(t, uint64(3), out.LinesReturned)
	assert.Equal(t, uint64(100), out.TotalLines)
	assert.True(t, out.TotalLinesExact)
	assert.Contains(t, out.Note, "100", "the result must say how much of the file is not shown")
}

// TestRead_DefaultsToASaneLineLimitAndSaysThatItDid. A model given the first
// two thousand lines of a hundred thousand, with nothing saying so, will
// conclude the file ends there.
func TestRead_DefaultsToASaneLineLimitAndSaysThatItDid(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{})
	path := f.path("huge.txt")

	var content strings.Builder
	for i := 1; i <= tools.DefaultReadLines+500; i++ {
		fmt.Fprintf(&content, "line %d\n", i)
	}
	writeRemote(t, path, content.String())

	out := structured[readResult](t, f.ok("fleet_read", map[string]any{"path": path}))

	assert.Equal(t, uint64(tools.DefaultReadLines), out.LinesReturned)
	assert.Contains(t, out.Note, fmt.Sprintf("%d lines", tools.DefaultReadLines))
	assert.Contains(t, out.Note, "offset")
	assert.Contains(t, out.Note, fmt.Sprintf("%d", tools.DefaultReadLines+500))
}

// TestRead_BinaryFileIsRefusedWithAClearMessage.
func TestRead_BinaryFileIsRefusedWithAClearMessage(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{})
	path := f.path("app.bin")
	writeRemote(t, path, "\x7fELF\x00\x01\x02\x03binary\x00content")

	text := f.fails("fleet_read", map[string]any{"path": path})

	assert.Contains(t, text, "not text")
	assert.Contains(t, text, "raw", "and must name the argument that reads it anyway")
	assert.NotContains(t, text, "rpc error: code =")

	// And with raw it comes back as bytes rather than mangled text.
	out := structured[readResult](t, f.ok("fleet_read", map[string]any{"path": path, "raw": true}))
	decoded, err := base64.StdEncoding.DecodeString(out.ContentBase64)
	require.NoError(t, err)
	assert.Equal(t, "\x7fELF\x00\x01\x02\x03binary\x00content", string(decoded))
	assert.Empty(t, out.Content)
}

// TestRead_MissingFileIsAClearNotFound, not a gRPC status.
func TestRead_MissingFileIsAClearNotFound(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{})
	missing := f.path("nope.go")

	text := f.fails("fleet_read", map[string]any{"path": missing})

	assert.Contains(t, text, "not found")
	assert.Contains(t, text, missing)
	assert.Contains(t, text, "build-box")
	assert.NotContains(t, text, "rpc error: code =")
	assert.NotContains(t, text, "code = NotFound", "the model gets prose, not an enum name")
}

// TestRead_CRLFIsPreservedOnDiskAndCalledOutInTheResult. The model's next move
// after a read is often an edit, and an old_string built from a rendering that
// silently dropped the CR would not match.
func TestRead_CRLFIsPreservedOnDiskAndCalledOutInTheResult(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{})
	path := f.path("crlf.txt")
	writeRemote(t, path, "alpha\r\nbeta\r\n")

	out := structured[readResult](t, f.ok("fleet_read", map[string]any{"path": path}))

	assert.Equal(t, "     1\talpha\n     2\tbeta\n", out.Content)
	assert.Contains(t, out.Note, "CRLF")

	onDisk, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "alpha\r\nbeta\r\n", string(onDisk), "the file itself must be untouched")
}

// ----------------------------------------------------------------- write

// TestWrite_CreatesAFileAndReportsThatItDid.
func TestWrite_CreatesAFileAndReportsThatItDid(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{})
	path := f.path("nested", "new.txt")

	out := structured[writeResult](t, f.ok("fleet_write", map[string]any{
		"path": path, "content": "hello\n", "create_parents": true,
	}))

	assert.True(t, out.Created)
	assert.Equal(t, uint64(6), out.BytesWritten)
	assert.Equal(t, "build-box", out.Sandbox)

	onDisk, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "hello\n", string(onDisk))

	// A second write reports that it replaced something, which is the fact a
	// model that meant to create a new file needs to see.
	out = structured[writeResult](t, f.ok("fleet_write", map[string]any{"path": path, "content": "replaced\n"}))
	assert.False(t, out.Created)
	assert.Contains(t, out.Note, "Overwrote")
}

// capturingFiles records the WriteFile stream so a test can see the shape of
// what went over the wire, not just what came back.
type capturingFiles struct {
	sandboxdv1.FileServiceClient
	stream *sendStream[sandboxdv1.WriteFileRequest, sandboxdv1.WriteFileResponse]
}

func (c *capturingFiles) WriteFile(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[sandboxdv1.WriteFileRequest, sandboxdv1.WriteFileResponse], error) {
	c.stream = &sendStream[sandboxdv1.WriteFileRequest, sandboxdv1.WriteFileResponse]{
		response: &sandboxdv1.WriteFileResponse{Path: "/remote/big", BytesWritten: 0, Created: true},
	}
	return c.stream, nil
}

// TestWrite_LargeContentIsStreamedRatherThanSentWhole.
//
// Asserted on the messages rather than on the outcome, because a tool that
// buffered the whole file into one message would produce an identical file and
// an identical result — right up to the size where gRPC refuses the message,
// which is exactly the size at which nobody is watching.
func TestWrite_LargeContentIsStreamedRatherThanSentWhole(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{})
	capture := &capturingFiles{FileServiceClient: f.backend.files}
	f.clients.filesOverride = capture

	const size = 700 * 1024
	f.ok("fleet_write", map[string]any{"path": "/remote/big", "content": strings.Repeat("a", size)})

	require.NotNil(t, capture.stream)
	var header, chunks, bytes int
	for _, msg := range capture.stream.sent {
		switch event := msg.GetEvent().(type) {
		case *sandboxdv1.WriteFileRequest_Header:
			header++
		case *sandboxdv1.WriteFileRequest_Chunk:
			chunks++
			bytes += len(event.Chunk)
			assert.LessOrEqual(t, len(event.Chunk), 64*1024, "no single message may carry the whole file")
		}
	}
	assert.Equal(t, 1, header, "the header must be sent exactly once, first")
	assert.Greater(t, chunks, 1, "a 700 KiB write must be more than one message")
	assert.Equal(t, size, bytes, "and every byte must arrive")
}

// TestWrite_LargeContentIsNotCopiedWhole.
//
// The structural test above proves the content leaves as many messages; this
// proves the handler does not make a second copy of it on the way — an
// io.ReadAll in writeStream would keep both the request's string and a
// byte-for-byte duplicate of it live at once.
//
// It is the weakest of the three heap assertions, and the reason is the
// protocol rather than the code: fleet_write takes its content as a tool
// *argument*, so a 64 MiB write is a 64 MiB JSON string that MCP has already
// decoded whole before the handler is reached. No choice on this side changes
// that, so that copy is in the baseline and is not what is being measured.
//
// What is measured is every copy the handler makes after that, and the
// baseline is taken at the first thing it does — asking for a file client —
// rather than at the write stream's header, which is late enough for a copy
// made on the way there to hide behind it.
func TestWrite_LargeContentIsNotCopiedWhole(t *testing.T) {
	// No t.Parallel: this measures the process's live heap. See liveHeap.
	if testing.Short() {
		t.Skip("moves 64 MiB")
	}
	f := newAgentFixture(t, backendOptions{})
	path := f.path("large.bin")

	// Started when the handler asks for its file client, not here: at this
	// point the request has not even been sent, so the content string it
	// carries is not yet live and would not be in the baseline.
	sampler := &heapSampler{every: 16}
	f.clients.onFiles = sampler.start
	f.clients.filesOverride = &samplingFiles{FileServiceClient: f.backend.files, sampler: sampler}

	out := structured[writeResult](t, f.ok("fleet_write", map[string]any{
		"path": path, "content": strings.Repeat("abcdefgh", heapPayload/8),
	}))

	require.Equal(t, uint64(heapPayload), out.BytesWritten)
	require.Greater(t, sampler.ticks, 512, "64 MiB has to leave as many messages, not one")

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, int64(heapPayload), info.Size())

	assertHeapBounded(t, sampler, heapPayload, "fleet_write")
}

// refusingWrite is a WriteFile stream that accepts the header and then refuses
// content, while its CloseAndRecv answers as though everything had arrived.
//
// That combination is not perverse: a client stream's Send reports only that
// the connection is gone, and the useful error normally comes back from
// CloseAndRecv — so a response with no error is exactly what a caller that
// trusted CloseAndRecv alone would act on. This end knows better; it counted
// what it sent.
type refusingWrite struct {
	grpc.ClientStream
	sent int
}

func (w *refusingWrite) Send(*sandboxdv1.WriteFileRequest) error {
	w.sent++
	if w.sent == 1 {
		return nil // the header
	}
	return io.EOF
}

func (w *refusingWrite) CloseAndRecv() (*sandboxdv1.WriteFileResponse, error) {
	return &sandboxdv1.WriteFileResponse{Path: "/remote/big", BytesWritten: 0, Created: true}, nil
}

type refusingWriteFiles struct {
	sandboxdv1.FileServiceClient
}

func (r *refusingWriteFiles) WriteFile(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[sandboxdv1.WriteFileRequest, sandboxdv1.WriteFileResponse], error) {
	return &refusingWrite{}, nil
}

// TestWrite_AStreamThatStoppedAcceptingContentIsNotReportedAsAWrite.
//
// The write reports what the agent says it received. If the stream stops
// accepting content part way and the close still answers cleanly, what is at
// the path is a prefix of what was asked for — and returning that answer says
// "written" about a file that was not.
func TestWrite_AStreamThatStoppedAcceptingContentIsNotReportedAsAWrite(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{})
	f.clients.filesOverride = &refusingWriteFiles{FileServiceClient: f.backend.files}

	text := f.fails("fleet_write", map[string]any{
		"path": "/remote/big", "content": strings.Repeat("a", 200*1024),
	})

	assert.Contains(t, text, "not written whole")
}

// ------------------------------------------------------------------ edit

// TestEdit_ReturnsAReadableDiff.
func TestEdit_ReturnsAReadableDiff(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{})
	path := f.path("edit.go")
	writeRemote(t, path, "package main\n\nconst version = \"0.1.0\"\n")

	out := structured[editResult](t, f.ok("fleet_edit", map[string]any{
		"path": path, "old_string": `"0.1.0"`, "new_string": `"0.2.0"`,
	}))

	assert.Equal(t, uint32(1), out.Replacements)
	assert.Contains(t, out.Diff, "-", "a diff has removals")
	assert.Contains(t, out.Diff, "0.2.0")
	assert.Contains(t, out.Diff, "0.1.0")

	onDisk, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(onDisk), "0.2.0")
}

// TestEdit_TwoMatchesErrorsWithTheCountAndLeavesTheFileAlone.
//
// The count is the whole value of the error: "it matched twice" tells the
// model to add surrounding context, where "the edit failed" tells it to try
// the same thing again.
func TestEdit_TwoMatchesErrorsWithTheCountAndLeavesTheFileAlone(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{})
	path := f.path("dup.go")
	const original = "value := 1\nother := 2\nvalue := 1\n"
	writeRemote(t, path, original)

	text := f.fails("fleet_edit", map[string]any{
		"path": path, "old_string": "value := 1", "new_string": "value := 3",
	})

	assert.Contains(t, text, "2 times", "the error must name the count")
	assert.Contains(t, text, "replace_all", "and the argument that permits it")
	assert.NotContains(t, text, "rpc error: code =")

	onDisk, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, original, string(onDisk), "a refused edit must leave the file byte-for-byte unchanged")
}

// TestEdit_ReplaceAllChangesEveryOccurrence, which is the other half of the
// uniqueness rule.
func TestEdit_ReplaceAllChangesEveryOccurrence(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{})
	path := f.path("dup.go")
	writeRemote(t, path, "value := 1\nother := 2\nvalue := 1\n")

	out := structured[editResult](t, f.ok("fleet_edit", map[string]any{
		"path": path, "old_string": "value := 1", "new_string": "value := 3", "replace_all": true,
	}))

	assert.Equal(t, uint32(2), out.Replacements)
	onDisk, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "value := 3\nother := 2\nvalue := 3\n", string(onDisk))
}

// -------------------------------------------------------------------- ls

// TestLs_ListsDirectoriesFirstWithHumanReadableSizes.
func TestLs_ListsDirectoriesFirstWithHumanReadableSizes(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{})
	writeRemote(t, f.path("src", "main.go"), "package main\n")
	writeRemote(t, f.path("README.md"), strings.Repeat("x", 4096))

	out := structured[lsResult](t, f.ok("fleet_ls", map[string]any{"path": f.remote}))

	assert.Equal(t, []string{"src"}, out.Directories)
	require.Len(t, out.Files, 1)
	assert.Equal(t, "README.md", out.Files[0].Name, "names are relative to the directory listed")
	assert.Equal(t, "4.0 KiB", out.Files[0].Size, "sizes are readable, not raw byte counts")
	assert.NotEmpty(t, out.Files[0].Modified)
	assert.Equal(t, "build-box", out.Sandbox)
}

// TestLs_EmptyDirectorySaysSo rather than returning two absent lists the model
// has to interpret.
func TestLs_EmptyDirectorySaysSo(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{})
	require.NoError(t, os.MkdirAll(f.path("empty"), 0o755))

	out := structured[lsResult](t, f.ok("fleet_ls", map[string]any{"path": f.path("empty")}))

	assert.Empty(t, out.Directories)
	assert.Empty(t, out.Files)
	assert.Contains(t, out.Note, "empty")
	assert.Contains(t, out.Note, "include_hidden")
}

// TestLs_TruncationIsReported.
func TestLs_TruncationIsReported(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{})
	for i := range 10 {
		writeRemote(t, f.path("many", fmt.Sprintf("file%02d.txt", i)), "x")
	}

	out := structured[lsResult](t, f.ok("fleet_ls", map[string]any{"path": f.path("many"), "limit": 3}))

	assert.Len(t, out.Files, 3)
	require.NotNil(t, out.Truncation, "a cut listing must say it was cut")
	assert.True(t, out.Truncation.Truncated)
	assert.Contains(t, out.Truncation.Note, "limit")
}

// ------------------------------------------------------------------ glob

// TestGlob_ReturnsMatchesNewestFirst.
//
// The ordering is the agent's — it walks and then sorts by modification time —
// and this tool passes the list through. Asserted rather than assumed because
// pass-through is exactly what a later change re-sorting or de-duplicating on
// this side would break, and #24 asks for "newest first" by name. The times are
// set explicitly: files written a millisecond apart share a timestamp on a
// filesystem with one-second granularity, which is most of them.
func TestGlob_ReturnsMatchesNewestFirst(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{})
	writeRemote(t, f.path("a", "one.go"), "package a\n")
	writeRemote(t, f.path("b", "two.go"), "package b\n")
	writeRemote(t, f.path("b", "notes.md"), "# notes\n")

	now := time.Now()
	require.NoError(t, os.Chtimes(f.path("a", "one.go"), now.Add(-time.Hour), now.Add(-time.Hour)))
	require.NoError(t, os.Chtimes(f.path("b", "two.go"), now, now))

	out := structured[globResult](t, f.ok("fleet_glob", map[string]any{
		"pattern": "**/*.go", "root": f.remote,
	}))

	assert.Equal(t, 2, out.Matches)
	for _, p := range out.Paths {
		assert.True(t, strings.HasSuffix(p, ".go"), "unexpected match %s", p)
		assert.True(t, filepath.IsAbs(p), "paths must be absolute so they can be passed straight to fleet_read")
	}
	require.Len(t, out.Paths, 2)
	assert.True(t, strings.HasSuffix(out.Paths[0], "two.go"),
		"the newest match must come first, got %v", out.Paths)
	assert.True(t, strings.HasSuffix(out.Paths[1], "one.go"))
}

// TestGlob_NoMatchesExplainsTheAnchoringRule, which is the mistake a model
// makes here: *.go where **/*.go was meant.
func TestGlob_NoMatchesExplainsTheAnchoringRule(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{})
	writeRemote(t, f.path("deep", "main.go"), "package main\n")

	out := structured[globResult](t, f.ok("fleet_glob", map[string]any{"pattern": "*.go", "root": f.remote}))

	assert.Zero(t, out.Matches)
	assert.Contains(t, out.Note, "**/*.go")
}

// ------------------------------------------------------------------ grep

// TestGrep_RendersMatchesCompactlyWithContext, in grep's own shape: a colon
// after the line number for a match, a dash for context.
func TestGrep_RendersMatchesCompactlyWithContext(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{})
	path := f.path("app.go")
	writeRemote(t, path, "package main\n\nfunc handler() {\n\tpanic(\"boom\")\n}\n")

	out := structured[grepResult](t, f.ok("fleet_grep", map[string]any{
		"pattern": "panic", "root": f.remote, "context_lines": 1,
	}))

	require.Len(t, out.Matches, 3, "one match plus one line of context on each side")
	assert.Contains(t, out.Matches[1], ":4: ", "the match itself is path:line: text")
	assert.Contains(t, out.Matches[1], `panic("boom")`)
	assert.Contains(t, out.Matches[0], "-3- ", "context uses a dash, as grep does")
	assert.Contains(t, out.Matches[2], "-5- ")
	assert.Equal(t, uint64(1), out.MatchCount)
	assert.Positive(t, out.FilesSearched)
}

// TestGrep_ReportsTruncationAndHowLittleWasRead. max_matches stops the walk,
// so a truncated search is also an incomplete one, and saying only "truncated"
// would let a model conclude the rest of the tree has no matches.
func TestGrep_ReportsTruncationAndHowLittleWasRead(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{})
	for i := range 20 {
		writeRemote(t, f.path("pkg", fmt.Sprintf("file%02d.go", i)), "package pkg\n// TODO: something\n")
	}

	out := structured[grepResult](t, f.ok("fleet_grep", map[string]any{
		"pattern": "TODO", "root": f.remote, "max_matches": 3,
	}))

	assert.Len(t, out.Matches, 3)
	require.NotNil(t, out.Truncation)
	assert.True(t, out.Truncation.Truncated)
	assert.Contains(t, out.Truncation.Note, "max_matches")
	assert.Contains(t, out.Truncation.Note, "unsearched")
}

// summarylessFiles serves a Grep stream that ends without a summary.
type summarylessFiles struct {
	sandboxdv1.FileServiceClient
}

func (s *summarylessFiles) Grep(context.Context, *sandboxdv1.GrepRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[sandboxdv1.GrepResponse], error) {
	return &recvStream[sandboxdv1.GrepResponse]{messages: []*sandboxdv1.GrepResponse{}}, nil
}

// TestGrep_ASearchWithoutASummaryIsNotReportedAsNoMatches.
//
// The summary carries the match count and how many files the walk read. Absent,
// the nil-safe getters make both zero — and this tool then says so in words:
// "No matches in 0 files searched". That is a search which did not happen,
// rendered as a search that found nothing, and the model's next move after "no
// matches" is to stop looking there.
func TestGrep_ASearchWithoutASummaryIsNotReportedAsNoMatches(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{})
	f.clients.filesOverride = &summarylessFiles{FileServiceClient: f.backend.files}

	text := f.fails("fleet_grep", map[string]any{"pattern": "TODO", "root": f.remote})

	assert.Contains(t, text, "without a summary")
	assert.NotContains(t, text, "No matches")
}

// TestGrep_FilesOnlyReturnsNames.
func TestGrep_FilesOnlyReturnsNames(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{})
	writeRemote(t, f.path("one.go"), "// TODO: a\n// TODO: b\n")

	out := structured[grepResult](t, f.ok("fleet_grep", map[string]any{
		"pattern": "TODO", "root": f.remote, "files_only": true,
	}))

	require.Len(t, out.Files, 1)
	assert.True(t, strings.HasSuffix(out.Files[0], "one.go"))
	assert.Empty(t, out.Matches)
}

// TestGrep_NoMatchesSaysWhatWasSearched.
func TestGrep_NoMatchesSaysWhatWasSearched(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{})
	writeRemote(t, f.path("one.go"), "package one\n")

	out := structured[grepResult](t, f.ok("fleet_grep", map[string]any{
		"pattern": "nothing-here", "root": f.remote,
	}))

	assert.Zero(t, out.MatchCount)
	assert.Contains(t, out.Note, "No matches")
	assert.Contains(t, out.Note, "node_modules", "and which directories were skipped by default")
}

// ------------------------------------------------------------------- jail

// TestFiles_JailRejectionNamesTheAllowedRoots.
//
// This is #24's jail criterion, tested in the one configuration where a jail
// exists: exec disabled. With exec enabled — the default — the agent is
// unconfined and there is no rejection to name roots in, which the test below
// asserts rather than leaves implied.
func TestFiles_JailRejectionNamesTheAllowedRoots(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{execDisabled: true})
	outside := filepath.Join(t.TempDir(), "escape.txt")

	text := f.fails("fleet_write", map[string]any{"path": outside, "content": "nope\n"})

	assert.Contains(t, text, "outside the allowed roots")
	assert.Contains(t, text, f.remote, "the error must name the roots the model may use")
	assert.Contains(t, text, "build-box")
	assert.NoFileExists(t, outside)
}

// TestFiles_AnUnconfinedAgentIsNotToldItIsConfined.
//
// The jail and ExecService are mutually exclusive, so the default agent has no
// roots at all. Synthesising a jail error here — or wording one as though
// roots existed — would be the model-facing version of telling an operator
// they are confined when they are not.
func TestFiles_AnUnconfinedAgentIsNotToldItIsConfined(t *testing.T) {
	t.Parallel()
	f := newAgentFixture(t, backendOptions{})
	elsewhere := filepath.Join(t.TempDir(), "anywhere.txt")

	out := structured[writeResult](t, f.ok("fleet_write", map[string]any{
		"path": elsewhere, "content": "written\n",
	}))

	assert.True(t, out.Created)
	assert.FileExists(t, elsewhere, "an unconfined agent really can write anywhere its account can")
}
