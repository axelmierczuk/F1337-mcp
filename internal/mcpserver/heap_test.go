package mcpserver_test

import (
	"context"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
)

// Three tools carry the same criterion — a large payload must move without
// this process's memory tracking its size — and the same failure mode: the
// code looks streaming because it was written to stream, and nothing catches
// the day an io.ReadAll appears in the middle of it. The claim is asserted
// here rather than left to a comment.
//
// The measurement copies internal/agent/fs's, which asserts the same property
// on the other side of the same wire (see liveHeap and
// TestReadFile_LargeFileIsNotBufferedWhole there). Matching it matters more
// than any improvement on it: two idioms for one property means the next
// person has to work out which is right.
//
// Two things about the measurement are load-bearing:
//
//   - It is HeapAlloc after a forced collection, never TotalAlloc or Sys.
//     TotalAlloc counts every byte ever allocated, so a correctly streaming
//     implementation legitimately reaches the file's size and an assertion on
//     it either proves nothing or fails working code. HeapAlloc after a GC is
//     what "is this being held all at once" actually means.
//
//   - It is the *peak* during the operation, sampled while the stream is
//     still running, not a before-and-after delta. An implementation that
//     buffered the whole payload and released it at the end shows almost no
//     delta afterwards, which is the exact regression this is here to catch.
//
// And one thing about *where the baseline is taken* is load-bearing too. It is
// the moment the handler asks for its file client — the first thing every one
// of these handlers does, and the earliest point in a tool call observable from
// outside it (see backendClients.onFiles). It used to be the header message of
// the write stream, which is later, and the gap between the two was somewhere a
// whole copy could hide: a handler that did []byte(in.Content) before opening
// the stream had already made its extra copy by the time the baseline was
// taken, and the assertion passed. Taking it at the client lookup means every
// copy the handler makes, anywhere, is on the far side of the baseline.

// liveHeap forces a collection and reports what is still reachable.
//
// It reads the *process's* heap, which is why every test that samples it is
// sequential and has to stay that way: a parallel test allocating alongside is
// indistinguishable from the handler under test holding its payload, and it
// would fail whichever way round the noise happened to land. Sequential tests
// all complete before the first parallel one is released, so this stays a
// measurement of one thing.
func liveHeap() uint64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// heapSampler records the highest live heap reached between start and the last
// tick.
//
// It samples every `every` ticks rather than on each one because every sample
// is a full stop-the-world collection; over a thousand chunks that is the
// difference between a test that takes a second and one nobody runs.
type heapSampler struct {
	every    int
	ticks    int
	baseline uint64
	peak     uint64
}

func newHeapSampler(every int) *heapSampler {
	s := &heapSampler{every: every}
	s.start()
	return s
}

func (s *heapSampler) start() {
	s.baseline = liveHeap()
	s.peak = s.baseline
}

func (s *heapSampler) tick() {
	s.ticks++
	if s.every > 1 && s.ticks%s.every != 0 {
		return
	}
	if live := liveHeap(); live > s.peak {
		s.peak = live
	}
}

func (s *heapSampler) growth() int64 {
	return int64(s.peak) - int64(s.baseline) //nolint:gosec // heap sizes here are far below the int64 range
}

// heapBound is how much live heap one of these operations may add while a
// payload of heapPayload bytes moves through it.
//
// Do not tighten this. It is not a budget and it is not policing allocation
// volume — it is a threshold dropped into the gap between two outcomes that
// differ by the size of the payload. Both sides were measured rather than
// guessed, on this branch, over three runs each under -race:
//
//	                          streaming (observed)   buffering (observed)
//	fleet_transfer pull      7.7 – 9.8 MiB          87 MiB
//	fleet_transfer push      9.1 – 10.1 MiB         89 MiB
//	fleet_write              0 – 12.6 MiB           90 MiB
//	fleet_exec               0.12 MiB               (whole 256 MiB stream)
//
// The streaming floor is not the tools' own memory — it is gRPC's buffer
// pools, bufconn's 1 MiB pipe and the SDK's encoding, none of which this side
// controls and all of which scale with throughput rather than with the file.
// That is the noisy side, and it is the side that needs headroom: 48 MiB is
// roughly four times the worst floor observed.
//
// The other side needs less headroom than it looks, because it is not noisy:
// a buffering implementation holds one extra whole copy of the payload, so its
// peak is deterministic at payload + floor. 48 MiB sits comfortably under the
// ~88 MiB that a 64 MiB payload produces, and every entry in the table above
// was produced by actually breaking the implementation and watching the
// assertion fire.
//
// A tighter number buys no coverage — there is nothing between the two columns
// to catch — and would eventually flake on a slower runner, at which point
// someone deletes the test. internal/agent/fs uses 32 MiB for the same
// property against a 100 MB payload with no gRPC in the path.
const heapBound = 48 << 20

// heapPayload is what these tests move. It is generated, never committed, and
// it is far larger than any buffer in the path: 1024 times the 64 KiB chunk
// size, so an implementation that holds it whole is unmistakable against
// heapBound.
//
// It is not larger, and fleet_write is the reason. That tool takes its
// content as a tool argument, so its payload is a JSON string the protocol has
// already decoded whole — the test process holds several copies of it before
// the handler is even reached, and doubling it doubles the memory the test
// itself needs rather than the signal it produces.
const heapPayload = 64 << 20

// assertHeapBounded is the assertion all three tools share.
func assertHeapBounded(t *testing.T, s *heapSampler, payload int, what string) {
	t.Helper()
	assert.Lessf(t, s.growth(), int64(heapBound),
		"live heap peaked %d bytes above baseline while %d bytes moved through %s: it is being held whole, not streamed",
		s.growth(), payload, what)
}

// writeGeneratedFile writes size bytes to path without ever holding them, so a
// test fixture cannot be the thing that fails the assertion it sets up.
func writeGeneratedFile(t *testing.T, path string, size int) {
	t.Helper()
	file, err := os.Create(path) //nolint:gosec // a path this test just built under t.TempDir
	if err != nil {
		t.Fatalf("creating %s: %v", path, err)
	}
	defer func() { _ = file.Close() }()

	block := make([]byte, 64<<10)
	for i := range block {
		block[i] = byte('a' + i%26)
	}
	for written := 0; written < size; written += len(block) {
		n := min(len(block), size-written)
		if _, err := file.Write(block[:n]); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatalf("closing %s: %v", path, err)
	}
}

// samplingFiles wraps a real FileServiceClient and samples the heap as the
// content streams past, which is the only point from which the *peak* is
// observable — the handler does not come back until it is finished.
type samplingFiles struct {
	sandboxdv1.FileServiceClient
	sampler *heapSampler
}

func (s *samplingFiles) ReadFile(ctx context.Context, in *sandboxdv1.ReadFileRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[sandboxdv1.ReadFileResponse], error) {
	inner, err := s.FileServiceClient.ReadFile(ctx, in, opts...)
	if err != nil {
		return nil, err
	}
	return &samplingRead{ServerStreamingClient: inner, sampler: s.sampler}, nil
}

func (s *samplingFiles) WriteFile(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[sandboxdv1.WriteFileRequest, sandboxdv1.WriteFileResponse], error) {
	inner, err := s.FileServiceClient.WriteFile(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return &samplingWrite{ClientStreamingClient: inner, sampler: s.sampler}, nil
}

type samplingRead struct {
	grpc.ServerStreamingClient[sandboxdv1.ReadFileResponse]
	sampler *heapSampler
}

func (s *samplingRead) Recv() (*sandboxdv1.ReadFileResponse, error) {
	msg, err := s.ServerStreamingClient.Recv()
	s.sampler.tick()
	return msg, err
}

type samplingWrite struct {
	grpc.ClientStreamingClient[sandboxdv1.WriteFileRequest, sandboxdv1.WriteFileResponse]
	sampler *heapSampler
}

// Send samples on every content chunk. The header carries none, so it is not
// worth a stop-the-world collection.
//
// It deliberately does not re-baseline: the baseline belongs at the start of
// the handler, not at the last moment before content moves. See the note on
// where the baseline is taken, above.
func (s *samplingWrite) Send(msg *sandboxdv1.WriteFileRequest) error {
	if _, isHeader := msg.GetEvent().(*sandboxdv1.WriteFileRequest_Header); !isHeader {
		s.sampler.tick()
	}
	return s.ClientStreamingClient.Send(msg)
}
