package tools

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/mcpserver/mcperr"
	"github.com/axelmierczuk/sandboxd-mcp/internal/mcpserver/selection"
)

// Bounds the file tools apply to their own side of a call. The agent has its
// own, generally larger, and clamps to them; these exist because the agent's
// limits are sized for a program reading a file and these are sized for a
// model reading one in its context window.
const (
	// DefaultReadLines is the window sandbox_read returns when the caller
	// names no limit. It matches the agent's own default, so a read that hits
	// it hits one limit rather than two at different numbers.
	DefaultReadLines = 2000

	// maxReadBytes bounds the content one sandbox_read may return, whatever
	// the line window works out to. Two thousand lines of a minified bundle is
	// not two thousand lines of source.
	maxReadBytes = 1024 * 1024

	// DefaultGrepMatches is how many matches sandbox_grep asks for when the
	// caller names none. Deliberately below the agent's own default of 500:
	// a search that returns five hundred lines has answered a question the
	// model did not ask, and max_matches stops the walk, so asking for fewer
	// is also asking the agent to do less work.
	DefaultGrepMatches = 100

	// maxGrepBytes bounds the rendered match list.
	maxGrepBytes = 64 * 1024

	// maxRenderedLine bounds one rendered line of grep output or context.
	maxRenderedLine = 400

	// DefaultListEntries is the directory listing size sandbox_ls asks for
	// when the caller names none.
	DefaultListEntries = 500

	// DefaultGlobResults is the match count sandbox_glob asks for when the
	// caller names none.
	DefaultGlobResults = 300

	// writeChunkBytes is the payload of one WriteFile chunk. It matches the
	// agent's own read chunk size, and it is what makes a large write a stream
	// rather than one enormous message the gRPC layer would refuse.
	writeChunkBytes = 64 * 1024
)

// registerFiles adds the six file tools.
//
// Their contracts deliberately mirror the model's own built-in file tools:
// same offset/limit meaning on read, same exact-match-with-uniqueness rule on
// edit, same line-numbered rendering. A remote tool that is *almost* the
// native one is worse than one that is obviously different, because the
// mismatch shows up as silent misuse rather than as an error.
func registerFiles(r *Registrar) {
	AddTargeted(r, &mcp.Tool{
		Name:  "sandbox_read",
		Title: "Read a file",
		Description: "Read a file on the selected sandbox, line-numbered, with the same offset/limit meaning as the built-in Read. " +
			"Defaults to the first 2000 lines and says so when there are more. Binary files are reported, not mangled.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, r.sandboxRead)

	AddTargeted(r, &mcp.Tool{
		Name:        "sandbox_write",
		Title:       "Write a file",
		Description: "Write a whole file on the selected sandbox. Streamed and written via a temporary file, so an interrupted write leaves no truncated file. Use sandbox_edit to change part of an existing file.",
	}, r.sandboxWrite)

	AddTargeted(r, &mcp.Tool{
		Name:  "sandbox_edit",
		Title: "Edit a file",
		Description: "Replace an exact string in a file on the selected sandbox and return a diff. " +
			"Whitespace is significant. Without replace_all the edit fails unless old_string matches exactly once, leaving the file untouched.",
	}, r.sandboxEdit)

	AddTargeted(r, &mcp.Tool{
		Name:        "sandbox_ls",
		Title:       "List a directory",
		Description: "List a directory on the selected sandbox: directories first, then files with human-readable sizes.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, r.sandboxLs)

	AddTargeted(r, &mcp.Tool{
		Name:  "sandbox_glob",
		Title: "Find files by pattern",
		Description: "Find files on the selected sandbox by glob pattern, newest first. The pattern is anchored at root: *.go does not recurse, **/*.go does. " +
			".git, node_modules, vendor and target are skipped unless include_default_ignored is set.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, r.sandboxGlob)

	AddTargeted(r, &mcp.Tool{
		Name:  "sandbox_grep",
		Title: "Search file contents",
		Description: "Search file contents on the selected sandbox with an RE2 pattern, rendered as path:line: text. " +
			"Runs on the sandbox, so a large tree is never streamed across the network. include_glob matches at any depth.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, r.sandboxGrep)
}

// pathCall builds the error mapping for a call about one path, so a NotFound
// reads as "not found on sandbox X: path /a/b: …" rather than as a bare gRPC
// status the model cannot act on.
func pathCall(target *selection.Target, path string) mcperr.Call {
	call := target.Call()
	call.Subject = "path " + path
	return call
}

// ------------------------------------------------------------------ read

// ReadArgs are the arguments to sandbox_read.
type ReadArgs struct {
	TargetArgs
	// Path is the file to read.
	Path string `json:"path" jsonschema:"absolute path to the file on the sandbox"`
	// Offset is the first line to return, 1-based.
	Offset int `json:"offset,omitempty" jsonschema:"first line to return, 1-based; defaults to the start of the file"`
	// Limit is the maximum number of lines to return.
	Limit int `json:"limit,omitempty" jsonschema:"maximum lines to return; defaults to 2000"`
	// Raw returns bytes rather than text, and is required for a binary file.
	Raw bool `json:"raw,omitempty" jsonschema:"return the bytes base64-encoded instead of text; required to read a binary file"`
}

// ReadResult is the sandbox_read result.
type ReadResult struct {
	// Echo carries the sandbox the file was read from.
	Echo
	// Path is the file that was read.
	Path string `json:"path" jsonschema:"the file that was read"`
	// Content is the line-numbered text, in the shape of the built-in Read.
	Content string `json:"content,omitempty" jsonschema:"line-numbered file content, one line per line, numbered from offset"`
	// ContentBase64 carries a raw read's bytes.
	ContentBase64 string `json:"content_base64,omitempty" jsonschema:"base64 of the raw bytes, present only for a raw read"`
	// FirstLine is the line number the content starts at.
	FirstLine int `json:"first_line,omitempty" jsonschema:"line number the content starts at, 1-based"`
	// LinesReturned is how many lines this window holds.
	LinesReturned uint64 `json:"lines_returned,omitempty" jsonschema:"how many lines this window holds"`
	// TotalLines is the file's line count, exact only when TotalLinesExact.
	TotalLines uint64 `json:"total_lines,omitempty" jsonschema:"lines in the whole file; a lower bound unless total_lines_exact is set"`
	// TotalLinesExact reports whether TotalLines counted the whole file.
	TotalLinesExact bool `json:"total_lines_exact,omitempty" jsonschema:"true when total_lines counted the whole file rather than stopping at a size bound"`
	// Size is the file's size, human-readable.
	Size string `json:"size,omitempty" jsonschema:"file size"`
	// Modified is how long ago the file changed.
	Modified string `json:"modified,omitempty" jsonschema:"how long ago the file was last modified"`
	// Truncation is present only when content was cut.
	Truncation *Truncation `json:"truncation,omitempty" jsonschema:"present only when the content was cut short"`
	// Note states anything the fields alone would leave the model to infer.
	Note string `json:"note,omitempty" jsonschema:"what the result means when the numbers alone do not say it"`
}

func (r *Registrar) sandboxRead(ctx context.Context, _ *mcp.CallToolRequest, target *selection.Target, in ReadArgs) (ReadResult, error) {
	if strings.TrimSpace(in.Path) == "" {
		return ReadResult{}, errors.New("path is required")
	}
	if in.Offset < 0 || in.Limit < 0 {
		return ReadResult{}, fmt.Errorf("offset %d and limit %d must not be negative", in.Offset, in.Limit)
	}
	if in.Raw && (in.Offset > 0 || in.Limit > 0) {
		return ReadResult{}, errors.New("offset and limit are line-oriented and cannot be combined with raw, which returns bytes")
	}

	files, err := r.deps.Clients.Files(target.Name(), target.Address())
	if err != nil {
		return ReadResult{}, target.Call().Map(err)
	}

	limit := uint64(DefaultReadLines)
	defaulted := in.Limit <= 0
	if !defaulted {
		limit = uint64(in.Limit) //nolint:gosec // checked non-negative above
	}

	req := &sandboxdv1.ReadFileRequest{
		Path:        in.Path,
		OffsetLines: uint64(in.Offset), //nolint:gosec // checked non-negative above
		Raw:         in.Raw,
		MaxBytes:    maxReadBytes,
	}
	if !in.Raw {
		req.LimitLines = limit
	}

	callCtx, cancel := context.WithTimeout(ctx, r.deps.callTimeout())
	defer cancel()

	stream, err := files.ReadFile(callCtx, req)
	if err != nil {
		return ReadResult{}, pathCall(target, in.Path).Map(err)
	}

	var (
		metadata *sandboxdv1.FileMetadata
		result   *sandboxdv1.ReadResult
	)
	content := newBoundedBuffer(maxReadBytes)
	for {
		msg, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		if recvErr != nil {
			return ReadResult{}, pathCall(target, in.Path).Map(recvErr)
		}
		switch event := msg.GetEvent().(type) {
		case *sandboxdv1.ReadFileResponse_Metadata:
			metadata = event.Metadata
		case *sandboxdv1.ReadFileResponse_Chunk:
			_, _ = content.Write(event.Chunk)
		case *sandboxdv1.ReadFileResponse_Result:
			result = event.Result
		}
	}
	if result == nil {
		return ReadResult{}, fmt.Errorf("sandbox %s ended the read of %s without a result, so the content may be incomplete",
			target.Name(), in.Path)
	}

	return renderRead(in, metadata, result, content, defaulted), nil
}

// renderRead assembles the line-numbered view.
func renderRead(in ReadArgs, metadata *sandboxdv1.FileMetadata, result *sandboxdv1.ReadResult, content *boundedBuffer, defaulted bool) ReadResult {
	first := in.Offset
	if first <= 0 {
		first = 1
	}

	out := ReadResult{
		Path:            in.Path,
		FirstLine:       first,
		LinesReturned:   result.GetLinesReturned(),
		TotalLines:      result.GetTotalLines(),
		TotalLinesExact: result.GetTotalLinesExact(),
		Size:            humanBytes(metadata.GetSizeBytes()),
	}
	if ts := metadata.GetModifiedAt(); ts != nil {
		out.Modified = relativeTime(ts.AsTime(), time.Now())
	}

	capNote := fmt.Sprintf("Content was capped at %d bytes; narrow the window with offset and limit.", maxReadBytes)
	out.Truncation = truncationFrom(result.GetTruncation(), capNote).merge(content.truncation(capNote))

	var note notes
	if in.Raw {
		out.ContentBase64 = base64.StdEncoding.EncodeToString(content.Bytes())
		note.add("Raw read: the bytes are base64-encoded because they are not text.")
		out.Note = note.String()
		return out
	}

	numbered, crlf := numberLines(content.String(), first)
	out.Content = numbered

	switch {
	case content.Len() == 0 && result.GetLinesReturned() == 0 && first > 1:
		note.add("No lines at offset %d; the file has %s lines.", first, lineCountPhrase(result))
	case content.Len() == 0:
		note.add("The file is empty.")
	}
	if crlf {
		// Worth one sentence, because the model's next move is often an edit,
		// and an old_string built from this view would be missing the CR the
		// file actually holds.
		note.add("This file uses CRLF line endings. They are preserved on the sandbox and not shown above; an exact-match edit must include them.")
	}
	if more := moreLines(result, first); more && defaulted {
		note.add("No limit was given, so at most %d lines were returned; the file has %s lines. Pass offset and limit to page through it.",
			DefaultReadLines, lineCountPhrase(result))
	} else if more {
		note.add("The file has %s lines; this window shows %d of them starting at %d.",
			lineCountPhrase(result), result.GetLinesReturned(), first)
	}
	out.Note = note.String()
	return out
}

// moreLines reports whether the file continues past the window that was
// returned.
func moreLines(result *sandboxdv1.ReadResult, first int) bool {
	if result.GetTruncation().GetTruncated() {
		return true
	}
	shown := uint64(first-1) + result.GetLinesReturned() //nolint:gosec // first is at least 1
	return result.GetTotalLines() > shown
}

// lineCountPhrase renders a line count that may only be a lower bound.
//
// The agent stops counting at a size bound rather than reading a gigabyte to
// answer a windowed read, so "of 4000" would be an invention on a large file.
func lineCountPhrase(result *sandboxdv1.ReadResult) string {
	if result.GetTotalLinesExact() {
		return fmt.Sprintf("%d", result.GetTotalLines())
	}
	return fmt.Sprintf("at least %d", result.GetTotalLines())
}

// numberLines renders content in the shape of the built-in Read: the line
// number right-aligned in six columns, a tab, then the line.
//
// It also reports whether the content carried CRLF endings. The CR is dropped
// from the rendering — a stray carriage return in the middle of a result is
// noise a model will either ignore or, worse, copy into its next argument —
// and the fact that it was there is said in the note instead.
func numberLines(content string, first int) (rendered string, crlf bool) {
	if content == "" {
		return "", false
	}
	body := strings.TrimSuffix(content, "\n")
	lines := strings.Split(body, "\n")

	var b strings.Builder
	b.Grow(len(content) + 8*len(lines))
	for i, line := range lines {
		if strings.HasSuffix(line, "\r") {
			crlf = true
			line = strings.TrimSuffix(line, "\r")
		}
		fmt.Fprintf(&b, "%6d\t%s\n", first+i, line)
	}
	return b.String(), crlf
}

// ----------------------------------------------------------------- write

// WriteArgs are the arguments to sandbox_write.
type WriteArgs struct {
	TargetArgs
	// Path is the file to write.
	Path string `json:"path" jsonschema:"absolute path to the file on the sandbox"`
	// Content is the whole file.
	Content string `json:"content" jsonschema:"the file's whole new content"`
	// CreateParents creates missing parent directories.
	CreateParents bool `json:"create_parents,omitempty" jsonschema:"create missing parent directories"`
	// FailIfExists refuses to overwrite.
	FailIfExists bool `json:"fail_if_exists,omitempty" jsonschema:"refuse rather than overwrite an existing file"`
	// Append adds to the end of the file instead of replacing it.
	Append bool `json:"append,omitempty" jsonschema:"append to the file instead of replacing it"`
}

// WriteResult is the sandbox_write result.
type WriteResult struct {
	// Echo carries the sandbox the file was written on.
	Echo
	// Path is the file that was written.
	Path string `json:"path" jsonschema:"the file that was written"`
	// BytesWritten is how much content landed.
	BytesWritten uint64 `json:"bytes_written" jsonschema:"bytes written"`
	// Created reports whether the file did not exist before.
	Created bool `json:"created" jsonschema:"true when the file did not exist before this call"`
	// Note states what the call did in words.
	Note string `json:"note,omitempty" jsonschema:"what the call did, when the fields alone do not say it"`
}

func (r *Registrar) sandboxWrite(ctx context.Context, _ *mcp.CallToolRequest, target *selection.Target, in WriteArgs) (WriteResult, error) {
	if strings.TrimSpace(in.Path) == "" {
		return WriteResult{}, errors.New("path is required")
	}
	if in.Append && in.FailIfExists {
		return WriteResult{}, errors.New("append and fail_if_exists contradict each other: one requires the file to exist, the other requires it not to")
	}

	files, err := r.deps.Clients.Files(target.Name(), target.Address())
	if err != nil {
		return WriteResult{}, target.Call().Map(err)
	}

	callCtx, cancel := context.WithTimeout(ctx, r.deps.callTimeout())
	defer cancel()

	resp, err := writeStream(callCtx, files, &sandboxdv1.WriteFileHeader{
		Path:          in.Path,
		CreateParents: in.CreateParents,
		FailIfExists:  in.FailIfExists,
		Append:        in.Append,
	}, strings.NewReader(in.Content))
	if err != nil {
		return WriteResult{}, pathCall(target, in.Path).Map(err)
	}

	out := WriteResult{
		Path:         resp.GetPath(),
		BytesWritten: resp.GetBytesWritten(),
		Created:      resp.GetCreated(),
	}
	var note notes
	switch {
	case in.Append:
		note.add("Appended to the existing file.")
	case !resp.GetCreated():
		note.add("Overwrote the existing file.")
	}
	out.Note = note.String()
	return out, nil
}

// writeStream sends a header and then the content in chunks, and returns the
// agent's summary.
//
// Chunked rather than sent whole because the content can be a whole file:
// one message carrying it would be refused by the gRPC message cap long before
// it was large enough to matter, and buffering a copy of it on the way out is
// memory this process does not need to spend. The agent writes to a temporary
// file and renames, so a stream abandoned part-way leaves nothing behind.
func writeStream(ctx context.Context, files sandboxdv1.FileServiceClient, header *sandboxdv1.WriteFileHeader, content io.Reader) (*sandboxdv1.WriteFileResponse, error) {
	stream, err := files.WriteFile(ctx)
	if err != nil {
		return nil, err
	}
	if err := stream.Send(&sandboxdv1.WriteFileRequest{
		Event: &sandboxdv1.WriteFileRequest_Header{Header: header},
	}); err != nil {
		return nil, err
	}

	buf := make([]byte, writeChunkBytes)
	for {
		n, readErr := content.Read(buf)
		if n > 0 {
			if err := stream.Send(&sandboxdv1.WriteFileRequest{
				Event: &sandboxdv1.WriteFileRequest_Chunk{Chunk: buf[:n]},
			}); err != nil {
				// A send failure here means the agent has already given up on
				// the stream, and its own error is the useful one: take it
				// from CloseAndRecv rather than reporting the write end's
				// generic "broken pipe".
				resp, closeErr := stream.CloseAndRecv()
				if closeErr != nil {
					return nil, closeErr
				}
				return resp, nil
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_, _ = stream.CloseAndRecv()
			return nil, readErr
		}
	}
	return stream.CloseAndRecv()
}

// ------------------------------------------------------------------ edit

// EditArgs are the arguments to sandbox_edit.
type EditArgs struct {
	TargetArgs
	// Path is the file to edit.
	Path string `json:"path" jsonschema:"absolute path to the file on the sandbox"`
	// OldString is the exact text to replace.
	OldString string `json:"old_string" jsonschema:"exact text to replace; whitespace is significant and it must match exactly once unless replace_all is set"`
	// NewString is what replaces it.
	NewString string `json:"new_string" jsonschema:"replacement text"`
	// ReplaceAll replaces every occurrence.
	ReplaceAll bool `json:"replace_all,omitempty" jsonschema:"replace every occurrence instead of requiring exactly one"`
}

// EditResult is the sandbox_edit result.
type EditResult struct {
	// Echo carries the sandbox the file was edited on.
	Echo
	// Path is the file that was edited.
	Path string `json:"path" jsonschema:"the file that was edited"`
	// Replacements is how many occurrences changed.
	Replacements uint32 `json:"replacements" jsonschema:"how many occurrences were replaced"`
	// Diff is a unified diff of the change.
	Diff string `json:"diff,omitempty" jsonschema:"unified diff of the change, trimmed to a few lines of context"`
}

func (r *Registrar) sandboxEdit(ctx context.Context, _ *mcp.CallToolRequest, target *selection.Target, in EditArgs) (EditResult, error) {
	if strings.TrimSpace(in.Path) == "" {
		return EditResult{}, errors.New("path is required")
	}

	files, err := r.deps.Clients.Files(target.Name(), target.Address())
	if err != nil {
		return EditResult{}, target.Call().Map(err)
	}

	callCtx, cancel := context.WithTimeout(ctx, r.deps.callTimeout())
	defer cancel()

	// A non-unique match comes back as an error naming the count and the lines
	// it matched on, with the file untouched. It is passed through rather than
	// softened into a result, because "I did nothing" reported as a success is
	// exactly the shape of a silent no-op the model will build on.
	resp, err := files.EditFile(callCtx, &sandboxdv1.EditFileRequest{
		Path:       in.Path,
		OldString:  in.OldString,
		NewString:  in.NewString,
		ReplaceAll: in.ReplaceAll,
	})
	if err != nil {
		return EditResult{}, pathCall(target, in.Path).Map(err)
	}

	return EditResult{
		Path:         resp.GetPath(),
		Replacements: resp.GetReplacements(),
		Diff:         resp.GetDiff(),
	}, nil
}

// -------------------------------------------------------------------- ls

// LsArgs are the arguments to sandbox_ls.
type LsArgs struct {
	TargetArgs
	// Path is the directory to list.
	Path string `json:"path" jsonschema:"absolute path to the directory on the sandbox"`
	// Recursive walks the whole tree.
	Recursive bool `json:"recursive,omitempty" jsonschema:"walk subdirectories; symlinked directories are reported but never descended into"`
	// IncludeHidden includes dot-files.
	IncludeHidden bool `json:"include_hidden,omitempty" jsonschema:"include entries whose names begin with a dot"`
	// Limit bounds the entries returned.
	Limit int `json:"limit,omitempty" jsonschema:"maximum entries to return; defaults to 500"`
}

// LsEntry is one file in a listing. Directories are listed separately, by
// name only, so the common case — "what is in here" — reads as two short lists
// rather than one long table of mostly-empty columns.
type LsEntry struct {
	// Name is the entry's path relative to the directory listed.
	Name string `json:"name" jsonschema:"path relative to the directory listed"`
	// Size is the file's size, human-readable.
	Size string `json:"size,omitempty" jsonschema:"file size"`
	// Modified is how long ago it changed.
	Modified string `json:"modified,omitempty" jsonschema:"how long ago it was last modified"`
	// Symlink is what this entry points at, when it is a link.
	Symlink string `json:"symlink,omitempty" jsonschema:"target, when this entry is a symlink"`
}

// LsResult is the sandbox_ls result.
type LsResult struct {
	// Echo carries the sandbox the directory is on.
	Echo
	// Path is the directory that was listed.
	Path string `json:"path" jsonschema:"the directory that was listed"`
	// Directories are the subdirectory names, first because that is the shape
	// of the question a listing usually answers.
	Directories []string `json:"directories,omitempty" jsonschema:"subdirectory names, relative to path"`
	// Files are the file entries.
	Files []LsEntry `json:"files,omitempty" jsonschema:"file entries, relative to path"`
	// Truncation is present only when the listing was cut.
	Truncation *Truncation `json:"truncation,omitempty" jsonschema:"present only when the listing was cut short"`
	// Note states anything the lists alone would leave the model to infer.
	Note string `json:"note,omitempty" jsonschema:"what the listing means when the entries alone do not say it"`
}

func (r *Registrar) sandboxLs(ctx context.Context, _ *mcp.CallToolRequest, target *selection.Target, in LsArgs) (LsResult, error) {
	if strings.TrimSpace(in.Path) == "" {
		return LsResult{}, errors.New("path is required")
	}
	if in.Limit < 0 {
		return LsResult{}, fmt.Errorf("limit %d must not be negative", in.Limit)
	}

	files, err := r.deps.Clients.Files(target.Name(), target.Address())
	if err != nil {
		return LsResult{}, target.Call().Map(err)
	}

	limit := uint32(DefaultListEntries)
	if in.Limit > 0 {
		limit = uint32(in.Limit) //nolint:gosec // checked non-negative above
	}

	callCtx, cancel := context.WithTimeout(ctx, r.deps.callTimeout())
	defer cancel()

	resp, err := files.ListDirectory(callCtx, &sandboxdv1.ListDirectoryRequest{
		Path:          in.Path,
		Recursive:     in.Recursive,
		Limit:         limit,
		IncludeHidden: in.IncludeHidden,
	})
	if err != nil {
		return LsResult{}, pathCall(target, in.Path).Map(err)
	}

	root := resp.GetPath()
	out := LsResult{Path: root}
	now := time.Now()
	for _, entry := range resp.GetEntries() {
		name := relativeTo(root, entry.GetPath())
		if entry.GetIsDir() {
			out.Directories = append(out.Directories, name)
			continue
		}
		file := LsEntry{Name: name, Size: humanBytes(entry.GetSizeBytes()), Symlink: entry.GetSymlinkTarget()}
		if ts := entry.GetModifiedAt(); ts != nil {
			file.Modified = relativeTime(ts.AsTime(), now)
		}
		out.Files = append(out.Files, file)
	}
	sort.Strings(out.Directories)
	sort.Slice(out.Files, func(i, j int) bool { return out.Files[i].Name < out.Files[j].Name })

	out.Truncation = truncationFrom(resp.GetTruncation(),
		fmt.Sprintf("The walk stopped at %d entries, so this is a prefix of the directory rather than all of it; raise limit or list a subdirectory.", limit))

	var note notes
	if len(out.Directories) == 0 && len(out.Files) == 0 {
		note.add("The directory is empty.")
		if !in.IncludeHidden {
			note.add("Hidden entries were not listed; pass include_hidden to see them.")
		}
	}
	out.Note = note.String()
	return out, nil
}

// ------------------------------------------------------------------ glob

// GlobArgs are the arguments to sandbox_glob.
type GlobArgs struct {
	TargetArgs
	// Pattern is the glob, anchored at Root.
	Pattern string `json:"pattern" jsonschema:"glob pattern anchored at root, e.g. **/*.go; *.go does not recurse"`
	// Root is the directory to search from.
	Root string `json:"root,omitempty" jsonschema:"directory to search from; defaults to the agent's working directory"`
	// Limit bounds the results.
	Limit int `json:"limit,omitempty" jsonschema:"maximum matches to return; defaults to 300"`
	// RespectGitignore honours .gitignore while walking.
	RespectGitignore bool `json:"respect_gitignore,omitempty" jsonschema:"honour .gitignore rules while walking"`
	// IncludeDefaultIgnored walks the directories skipped by default.
	IncludeDefaultIgnored bool `json:"include_default_ignored,omitempty" jsonschema:"walk into .git, node_modules, vendor and target, which are skipped by default"`
}

// GlobResult is the sandbox_glob result.
type GlobResult struct {
	// Echo carries the sandbox that was searched.
	Echo
	// Pattern is what was matched.
	Pattern string `json:"pattern" jsonschema:"the pattern that was matched"`
	// Paths are the matches, newest first.
	Paths []string `json:"paths" jsonschema:"absolute paths of matching files, newest first"`
	// Matches is how many are listed.
	Matches int `json:"matches" jsonschema:"how many paths are listed"`
	// Truncation is present only when the result was cut.
	Truncation *Truncation `json:"truncation,omitempty" jsonschema:"present only when the match list was cut short"`
	// Note states anything the list alone would leave the model to infer.
	Note string `json:"note,omitempty" jsonschema:"what the result means when the list alone does not say it"`
}

func (r *Registrar) sandboxGlob(ctx context.Context, _ *mcp.CallToolRequest, target *selection.Target, in GlobArgs) (GlobResult, error) {
	if strings.TrimSpace(in.Pattern) == "" {
		return GlobResult{}, errors.New(`pattern is required, e.g. pattern="**/*.go"`)
	}
	if in.Limit < 0 {
		return GlobResult{}, fmt.Errorf("limit %d must not be negative", in.Limit)
	}

	files, err := r.deps.Clients.Files(target.Name(), target.Address())
	if err != nil {
		return GlobResult{}, target.Call().Map(err)
	}

	limit := uint32(DefaultGlobResults)
	if in.Limit > 0 {
		limit = uint32(in.Limit) //nolint:gosec // checked non-negative above
	}

	callCtx, cancel := context.WithTimeout(ctx, r.deps.callTimeout())
	defer cancel()

	resp, err := files.Glob(callCtx, &sandboxdv1.GlobRequest{
		Pattern:               in.Pattern,
		Root:                  in.Root,
		Limit:                 limit,
		RespectGitignore:      in.RespectGitignore,
		IncludeDefaultIgnored: in.IncludeDefaultIgnored,
	})
	if err != nil {
		call := target.Call()
		call.Subject = "pattern " + in.Pattern
		if in.Root != "" {
			call.Subject += " under " + in.Root
		}
		return GlobResult{}, call.Map(err)
	}

	out := GlobResult{
		Pattern: in.Pattern,
		Paths:   resp.GetPaths(),
		Matches: len(resp.GetPaths()),
	}
	out.Truncation = truncationFrom(resp.GetTruncation(),
		fmt.Sprintf("More than %d files matched; raise limit or narrow the pattern.", limit))

	var note notes
	if out.Matches == 0 {
		note.add("Nothing matched. The pattern is anchored at root, so *.go looks in one directory and **/*.go recurses.")
		if !in.IncludeDefaultIgnored {
			note.add(".git, node_modules, vendor and target were skipped; pass include_default_ignored to search them.")
		}
	}
	out.Note = note.String()
	return out, nil
}

// ------------------------------------------------------------------ grep

// GrepArgs are the arguments to sandbox_grep.
type GrepArgs struct {
	TargetArgs
	// Pattern is the RE2 expression to search for.
	Pattern string `json:"pattern" jsonschema:"RE2 regular expression to search for"`
	// Root is the directory to search from.
	Root string `json:"root,omitempty" jsonschema:"directory to search from; defaults to the agent's working directory"`
	// IncludeGlob restricts the search to matching paths.
	IncludeGlob string `json:"include_glob,omitempty" jsonschema:"restrict to paths matching this glob, with gitignore semantics: *.go matches at any depth"`
	// CaseInsensitive ignores case.
	CaseInsensitive bool `json:"case_insensitive,omitempty" jsonschema:"ignore case"`
	// ContextLines includes surrounding lines with each match.
	ContextLines int `json:"context_lines,omitempty" jsonschema:"lines of context on each side of a match"`
	// MaxMatches bounds the search.
	MaxMatches int `json:"max_matches,omitempty" jsonschema:"stop after this many matches; defaults to 100. This stops the walk, so a low value also searches less of the tree"`
	// FilesOnly returns matching file names rather than lines.
	FilesOnly bool `json:"files_only,omitempty" jsonschema:"return only the names of matching files"`
	// RespectGitignore honours .gitignore while walking.
	RespectGitignore bool `json:"respect_gitignore,omitempty" jsonschema:"honour .gitignore rules while walking"`
	// IncludeDefaultIgnored searches the directories skipped by default.
	IncludeDefaultIgnored bool `json:"include_default_ignored,omitempty" jsonschema:"search inside .git, node_modules, vendor and target, which are skipped by default"`
}

// GrepResult is the sandbox_grep result.
type GrepResult struct {
	// Echo carries the sandbox that was searched.
	Echo
	// Pattern is what was searched for.
	Pattern string `json:"pattern" jsonschema:"the pattern that was searched for"`
	// Matches are rendered lines, "path:line: text", with context lines
	// rendered "path-line- text" as grep itself does.
	Matches []string `json:"matches,omitempty" jsonschema:"matching lines rendered as path:line: text; context lines use a dash instead of a colon"`
	// Files are the matching file names, when files_only was set.
	Files []string `json:"files,omitempty" jsonschema:"matching file names, present only when files_only was set"`
	// MatchCount is how many matches the agent found.
	MatchCount uint64 `json:"match_count" jsonschema:"how many matches were found"`
	// FilesSearched is how many files the walk read.
	FilesSearched uint64 `json:"files_searched" jsonschema:"how many files the walk actually read"`
	// Truncation is present only when the search stopped early.
	Truncation *Truncation `json:"truncation,omitempty" jsonschema:"present only when the search stopped short of the whole tree"`
	// Note states anything the list alone would leave the model to infer.
	Note string `json:"note,omitempty" jsonschema:"what the result means when the matches alone do not say it"`
}

func (r *Registrar) sandboxGrep(ctx context.Context, _ *mcp.CallToolRequest, target *selection.Target, in GrepArgs) (GrepResult, error) {
	if strings.TrimSpace(in.Pattern) == "" {
		return GrepResult{}, errors.New("pattern is required")
	}
	if in.ContextLines < 0 || in.MaxMatches < 0 {
		return GrepResult{}, fmt.Errorf("context_lines %d and max_matches %d must not be negative", in.ContextLines, in.MaxMatches)
	}

	files, err := r.deps.Clients.Files(target.Name(), target.Address())
	if err != nil {
		return GrepResult{}, target.Call().Map(err)
	}

	maxMatches := uint32(DefaultGrepMatches)
	if in.MaxMatches > 0 {
		maxMatches = uint32(in.MaxMatches) //nolint:gosec // checked non-negative above
	}

	callCtx, cancel := context.WithTimeout(ctx, r.deps.callTimeout())
	defer cancel()

	stream, err := files.Grep(callCtx, &sandboxdv1.GrepRequest{
		Pattern:               in.Pattern,
		Root:                  in.Root,
		IncludeGlob:           in.IncludeGlob,
		CaseInsensitive:       in.CaseInsensitive,
		ContextLines:          uint32(in.ContextLines), //nolint:gosec // checked non-negative above
		MaxMatches:            maxMatches,
		RespectGitignore:      in.RespectGitignore,
		FilesOnly:             in.FilesOnly,
		IncludeDefaultIgnored: in.IncludeDefaultIgnored,
	})
	if err != nil {
		call := target.Call()
		call.Subject = "pattern " + in.Pattern
		return GrepResult{}, call.Map(err)
	}

	out := GrepResult{Pattern: in.Pattern}
	seenFiles := map[string]bool{}
	var (
		summary       *sandboxdv1.GrepSummary
		renderedBytes int
		droppedBytes  uint64
		droppedLines  uint64
	)

	for {
		msg, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		if recvErr != nil {
			call := target.Call()
			call.Subject = "pattern " + in.Pattern
			return GrepResult{}, call.Map(recvErr)
		}
		switch event := msg.GetEvent().(type) {
		case *sandboxdv1.GrepResponse_Match:
			match := event.Match
			if in.FilesOnly {
				if !seenFiles[match.GetPath()] {
					seenFiles[match.GetPath()] = true
					out.Files = append(out.Files, match.GetPath())
				}
				continue
			}
			// Rendered into a byte budget rather than appended without bound:
			// one match per line is compact, but a thousand of them is a wall
			// of text charged to every later call in the conversation. Whole
			// lines are kept or dropped, never half of one, so nothing in the
			// list is a fragment the model could read as a whole line.
			for _, line := range renderMatch(match) {
				if renderedBytes+len(line) > maxGrepBytes {
					droppedBytes += uint64(len(line))
					droppedLines++
					continue
				}
				out.Matches = append(out.Matches, line)
				renderedBytes += len(line)
			}
		case *sandboxdv1.GrepResponse_Summary:
			summary = event.Summary
		}
	}

	out.MatchCount = summary.GetMatchesFound()
	out.FilesSearched = summary.GetFilesSearched()
	out.Truncation = truncationFrom(summary.GetTruncation(),
		fmt.Sprintf("The search stopped at %d matches, so only %d files were read and the rest of the tree is unsearched; raise max_matches or narrow the pattern.",
			maxMatches, summary.GetFilesSearched()))
	if droppedBytes > 0 {
		out.Truncation = out.Truncation.merge(&Truncation{
			Truncated:    true,
			BytesOmitted: droppedBytes,
			LinesOmitted: droppedLines,
			Note:         fmt.Sprintf("Rendered matches were capped at %d bytes; narrow the pattern or set files_only.", maxGrepBytes),
		})
	}

	var note notes
	if out.MatchCount == 0 {
		note.add("No matches in %d files searched.", out.FilesSearched)
		if !in.IncludeDefaultIgnored {
			note.add(".git, node_modules, vendor and target were skipped; pass include_default_ignored to search them.")
		}
	}
	out.Note = note.String()
	return out, nil
}

// renderMatch renders one match and its context, in grep's own shape: a colon
// separates a matching line from its path, a dash separates a context line.
// That difference is the only thing distinguishing the two once they are in a
// flat list, and it is the convention every reader of grep output already
// knows.
func renderMatch(match *sandboxdv1.GrepMatch) []string {
	line := match.GetLineNumber()
	out := make([]string, 0, 1+len(match.GetBeforeContext())+len(match.GetAfterContext()))

	before := match.GetBeforeContext()
	for i, text := range before {
		out = append(out, fmt.Sprintf("%s-%d- %s", match.GetPath(), line-u64(len(before)-i), clip(text, maxRenderedLine)))
	}
	out = append(out, fmt.Sprintf("%s:%d: %s", match.GetPath(), line, clip(match.GetLine(), maxRenderedLine)))
	for i, text := range match.GetAfterContext() {
		out = append(out, fmt.Sprintf("%s-%d- %s", match.GetPath(), line+u64(i)+1, clip(text, maxRenderedLine)))
	}
	return out
}
