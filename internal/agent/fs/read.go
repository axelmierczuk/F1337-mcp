package fs

import (
	"bytes"
	"errors"
	"io"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

// ReadFile streams a file: metadata, then content chunks, then a result.
//
// Nothing here holds more than one chunk. A 100 MB file costs a chunk buffer
// and the garbage collector's patience, never 100 MB of heap — which is the
// point of it being a stream rather than a response with a bytes field.
//
// The metadata message is sent before anything can fail on the content, so a
// caller that asked for a binary file as text learns its size, mode and
// is_binary flag along with the refusal rather than instead of it.
func (s *Service) ReadFile(req *sandboxdv1.ReadFileRequest, stream grpc.ServerStreamingServer[sandboxdv1.ReadFileResponse]) error {
	ctx := stream.Context()
	if req.GetRaw() && (req.GetOffsetLines() > 0 || req.GetLimitLines() > 0) {
		return status.Error(codes.InvalidArgument,
			"offset_lines and limit_lines are line-oriented and cannot be combined with raw; raw returns bytes, which have no lines to window")
	}

	resolved, err := s.resolve(req.GetPath())
	if err != nil {
		return err
	}
	// Before the open, because the open is where a named pipe blocks forever.
	if err := refuseIrregular(resolved); err != nil {
		return err
	}
	// The resolved path, not the one the request carried. The jail documents that
	// its result is the only path a caller may hand to a syscall, and this is the
	// one place in the package that re-derived it from the input instead — which
	// also meant the irregular-file check above and the open below were made
	// about two different expressions.
	file, err := s.jail.OpenFile(resolved, os.O_RDONLY, 0)
	if err != nil {
		return s.pathError(resolved, err)
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return fileError(resolved, err)
	}
	if info.IsDir() {
		return status.Errorf(codes.InvalidArgument, "%s is a directory; use ListDirectory", resolved)
	}

	// The metadata describes the file that was opened, so a path that was a
	// symlink is reported as its target: that is the file whose bytes follow.
	// ListDirectory and StatPath are where the link itself is described.
	md := metadataFor(resolved, info)
	md.IsSymlink, md.SymlinkTarget = false, ""
	binary, err := sniffBinary(file)
	if err != nil {
		return fileError(resolved, err)
	}
	md.IsBinary = binary

	if err := stream.Send(&sandboxdv1.ReadFileResponse{
		Event: &sandboxdv1.ReadFileResponse_Metadata{Metadata: md},
	}); err != nil {
		return err
	}

	if binary && !req.GetRaw() {
		return status.Errorf(codes.FailedPrecondition,
			"%s is not text — the first %d bytes contain a NUL byte or invalid UTF-8 — and returning it as text would mangle it; set raw to read the bytes",
			resolved, sniffBytes)
	}

	send := func(chunk []byte) error {
		if err := ctxErr(ctx); err != nil {
			return err
		}
		return stream.Send(&sandboxdv1.ReadFileResponse{
			Event: &sandboxdv1.ReadFileResponse_Chunk{Chunk: chunk},
		})
	}

	maxBytes := req.GetMaxBytes()
	if maxBytes == 0 {
		maxBytes = s.limits.DefaultMaxReadBytes
	}

	var result *sandboxdv1.ReadResult
	if req.GetRaw() {
		result, err = s.readRaw(file, info.Size(), maxBytes, send)
	} else {
		result, err = s.readLines(file, info.Size(), req, maxBytes, send)
	}
	if err != nil {
		return err
	}
	return stream.Send(&sandboxdv1.ReadFileResponse{
		Event: &sandboxdv1.ReadFileResponse_Result{Result: result},
	})
}

// readRaw streams bytes verbatim, capped at maxBytes.
//
// No line counting: raw exists for content whose bytes are not lines, and
// scanning a 100 MB image for newlines to report a number nobody can use is
// work for its own sake.
func (s *Service) readRaw(file *os.File, size int64, maxBytes uint64, send func([]byte) error) (*sandboxdv1.ReadResult, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fileError(file.Name(), err)
	}

	var written uint64
	for written < maxBytes {
		want := min(u64(s.limits.ChunkBytes), maxBytes-written)
		// A fresh buffer per chunk: gRPC's SendMsg may hand the message to a
		// stats handler that reads it after the call returns, so the bytes
		// cannot be reused under it. They are garbage immediately afterwards,
		// which is what keeps the live heap flat.
		buf := make([]byte, want)
		n, err := file.Read(buf)
		if n > 0 {
			if err := send(buf[:n]); err != nil {
				return nil, err
			}
			written += u64(n)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fileError(file.Name(), err)
		}
	}

	truncated := size >= 0 && written < u64(size)
	var omitted uint64
	if truncated {
		omitted = u64(size) - written
	}
	return &sandboxdv1.ReadResult{Truncation: truncation(truncated, omitted, 0)}, nil
}

// readLines serves a line window without ever holding a line, let alone a file.
//
// The window is found by streaming: bytes are read a chunk at a time, newlines
// counted as they go by, and only the bytes whose line falls inside the window
// are sent. A file whose single line is 100 MB long streams in chunks like any
// other, because the emission is byte-oriented and the line numbering is a
// counter beside it.
//
// # total_lines
//
// Counting every line means reading every byte, and the issue is explicit that
// answering a windowed read must not cost a gigabyte of I/O. So the count is
// bounded by file size, and the bound is reported rather than hidden:
//
//   - Files up to Limits.LineCountLimitBytes are counted to EOF. total_lines is
//     exact and total_lines_exact is true.
//   - Larger files are read only as far as the window needs. total_lines is
//     then how many lines the read passed on the way, which is a lower bound,
//     and total_lines_exact is false.
//
// A caller rendering "line 40 of N" must check the flag. That is why the flag
// exists rather than a zero that could be mistaken for an empty file.
func (s *Service) readLines(file *os.File, size int64, req *sandboxdv1.ReadFileRequest, maxBytes uint64, send func([]byte) error) (*sandboxdv1.ReadResult, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fileError(file.Name(), err)
	}

	start := max(req.GetOffsetLines(), 1)
	limit := req.GetLimitLines()
	if limit == 0 {
		limit = s.limits.DefaultReadLines
	}
	end := start + limit - 1
	countToEOF := size <= s.limits.LineCountLimitBytes

	var (
		readBuf = make([]byte, s.limits.ChunkBytes)
		out     []byte

		curLine    uint64 = 1 // line the next byte belongs to
		totalLines uint64     // complete lines seen so far
		emitted    uint64     // lines fully inside the window and sent
		sentBytes  uint64
		consumed   uint64 // bytes read up to and including the last emitted byte
		offset     uint64 // bytes read from the file so far

		capped bool // stopped emitting because of maxBytes
		// openLine tracks a line the read has entered but not yet seen the end
		// of. A line routinely spans several reads, so this cannot be inferred
		// from the last segment of a buffer: a 70 KB line ends the first 64 KB
		// read without a newline and is terminated by the second.
		openLine bool
		// lineEmitted records that some of the open line went out, so a line
		// split across two reads is counted once whichever read emitted it.
		lineEmitted bool
	)

	flush := func() error {
		if len(out) == 0 {
			return nil
		}
		if err := send(out); err != nil {
			return err
		}
		out = nil
		return nil
	}
	emit := func(seg []byte) error {
		if sentBytes >= maxBytes {
			capped = true
			return nil
		}
		if room := maxBytes - sentBytes; u64(len(seg)) > room {
			seg, capped = seg[:room], true
		}
		if out == nil {
			out = make([]byte, 0, s.limits.ChunkBytes)
		}
		out = append(out, seg...)
		sentBytes += u64(len(seg))
		consumed = offset + u64(len(seg))
		if len(out) >= s.limits.ChunkBytes {
			return flush()
		}
		return nil
	}

readLoop:
	for {
		n, readErr := file.Read(readBuf)
		data := readBuf[:n]
		for len(data) > 0 {
			seg, terminated := data, false
			if idx := bytes.IndexByte(data, '\n'); idx >= 0 {
				seg, terminated = data[:idx+1], true
			}
			data = data[len(seg):]

			if curLine >= start && curLine <= end && !capped {
				sentBefore := sentBytes
				if err := emit(seg); err != nil {
					return nil, err
				}
				// Only a line some of which actually went out counts as
				// returned; landing exactly on max_bytes emits nothing.
				lineEmitted = lineEmitted || sentBytes > sentBefore
			}
			offset += u64(len(seg))

			if terminated {
				totalLines++
				if lineEmitted {
					emitted++
				}
				curLine++
				openLine, lineEmitted = false, false
			} else {
				openLine = true
			}

			// Past the window with nothing left to count for: stop reading. This
			// is what keeps a windowed read of a huge file from touching the
			// rest of it.
			if curLine > end && !countToEOF {
				break readLoop
			}
		}
		if errors.Is(readErr, io.EOF) || n == 0 && readErr == nil {
			break
		}
		if readErr != nil {
			return nil, fileError(file.Name(), readErr)
		}
	}
	if openLine {
		// A final line with no terminator is still a line.
		totalLines++
		if lineEmitted {
			emitted++
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}

	reachedEOF := countToEOF
	lastLine := start + emitted - 1
	var linesOmitted uint64
	if reachedEOF && totalLines > lastLine && emitted > 0 {
		linesOmitted = totalLines - lastLine
	}
	var bytesOmitted uint64
	truncated := capped
	if size >= 0 && consumed < u64(size) && emitted > 0 {
		bytesOmitted = u64(size) - consumed
		truncated = truncated || linesOmitted > 0 || !reachedEOF
	}
	return &sandboxdv1.ReadResult{
		LinesReturned:   emitted,
		TotalLines:      totalLines,
		TotalLinesExact: reachedEOF,
		Truncation:      truncation(truncated, bytesOmitted, linesOmitted),
	}, nil
}
