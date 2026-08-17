package exec

import (
	"bytes"
	"sync"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

// maxChunkBytes bounds one OutputChunk.
//
// Well under the 4 MiB gRPC message limit both sides configure, because the
// chunk is not the whole message and a cap that only just fits leaves nothing
// for framing. 32 KiB is also io.Copy's buffer size, so in the ordinary case a
// chunk is exactly one read from the pipe and this cap never splits anything.
const maxChunkBytes = 32 * 1024

// sink is where a running command's output goes: chunked, capped, and
// serialised onto one gRPC stream.
//
// # The cap is not a stop
//
// Past maxBytes the sink stops sending and starts counting, but it never stops
// accepting. A writer that returns a short count or an error makes io.Copy stop
// reading, the pipe fills, and the process blocks in write(2) forever — so the
// command that produced too much output would hang until its timeout instead of
// finishing, and the caller would get a timeout for a command that had done its
// job. Accepting and discarding is what keeps the pipe drained.
//
// # The lock is held across Send, and Send can park indefinitely
//
// grpc-go's Send waits for the stream's flow-control window, which a caller
// that has stopped reading never reopens; only the RPC ending releases it. So a
// method on this type can block for as long as the client likes, and anything
// calling one from the handler's own goroutine — after the handler has decided
// to give up on such a caller, say — deadlocks the very path that would have
// freed it. exec.go's abandon path touches nothing here for that reason.
//
// Serialising on one mutex is not incidental either: grpc.ServerStream permits
// one Send at a time, and stdout and stderr are copied by two goroutines.
type sink struct {
	mu     sync.Mutex
	stream sandboxdv1.ExecService_ExecServer

	maxBytes uint64
	sent     uint64

	omitted      uint64
	omittedLines uint64

	// err is the first send failure. Once set the sink is inert: a stream that
	// has failed will not accept the next chunk either, and a handler that
	// keeps trying turns one dead client into a busy loop.
	err error
}

func newSink(stream sandboxdv1.ExecService_ExecServer, maxBytes uint64) *sink {
	return &sink{stream: stream, maxBytes: maxBytes}
}

// writer returns an io.Writer that tags everything written to it as coming
// from stream.
func (s *sink) writer(stream sandboxdv1.Stream) *streamWriter {
	return &streamWriter{sink: s, stream: stream}
}

// write records p as output from stream, sending what fits under the cap.
//
// It always reports the full length as written. See the type comment.
func (s *sink) write(stream sandboxdv1.Stream, p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	remaining := p
	if s.maxBytes > 0 {
		room := s.maxBytes - min(s.sent, s.maxBytes)
		if uint64(len(remaining)) > room {
			dropped := remaining[room:]
			remaining = remaining[:room]
			lines := bytes.Count(dropped, []byte{'\n'})
			s.omitted += uint64(len(dropped))
			s.omittedLines += uint64(lines) //nolint:gosec // G115: a count of newlines in a slice cannot be negative
		}
	}

	for len(remaining) > 0 && s.err == nil {
		chunk := remaining
		if len(chunk) > maxChunkBytes {
			chunk = chunk[:maxChunkBytes]
		}
		remaining = remaining[len(chunk):]

		// The bytes are copied because grpc.SendMsg marshals asynchronously
		// with respect to this call returning, while p belongs to io.Copy's
		// buffer and is overwritten by the next read.
		data := make([]byte, len(chunk))
		copy(data, chunk)

		s.err = s.stream.Send(&sandboxdv1.ExecResponse{
			Event: &sandboxdv1.ExecResponse_Output{
				Output: &sandboxdv1.OutputChunk{Stream: stream, Data: data},
			},
		})
		if s.err == nil {
			s.sent += uint64(len(data))
		}
	}

	return len(p), nil
}

// truncation reports what the cap dropped.
func (s *sink) truncation() *sandboxdv1.Truncation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &sandboxdv1.Truncation{
		Truncated:    s.omitted > 0,
		BytesOmitted: s.omitted,
		LinesOmitted: s.omittedLines,
	}
}

// sendErr returns the first failure to send a chunk, if any.
func (s *sink) sendErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// sendResult puts the terminal ExecResult on the stream.
func (s *sink) sendResult(result *sandboxdv1.ExecResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	return s.stream.Send(&sandboxdv1.ExecResponse{
		Event: &sandboxdv1.ExecResponse_Result{Result: result},
	})
}

// streamWriter is the io.Writer half of a sink, bound to one output stream.
type streamWriter struct {
	sink   *sink
	stream sandboxdv1.Stream
}

func (w *streamWriter) Write(p []byte) (int, error) { return w.sink.write(w.stream, p) }
