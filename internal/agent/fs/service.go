package fs

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/agent"
	"github.com/axelmierczuk/sandboxd-mcp/internal/platform"
	"github.com/axelmierczuk/sandboxd-mcp/internal/security/jail"
)

// init registers FileService with every sandboxd-agent daemon that links this
// package. See internal/cli/sandboxdagent/services.go for the import that does.
func init() {
	agent.Register("fs", New)
}

// Limits bound what one RPC may cost the agent. Every field has a default; the
// zero value is the default set, which is what the daemon uses.
type Limits struct {
	// ChunkBytes is the payload size of one ReadFile chunk.
	ChunkBytes int

	// DefaultReadLines is the line window ReadFile serves when the caller names
	// none.
	DefaultReadLines uint64

	// DefaultMaxReadBytes caps a ReadFile response when the caller names no
	// max_bytes. It sits under the 32 MiB gRPC message cap with room to spare;
	// the cap is per-message, but a caller collecting a stream into one buffer
	// is the common case and this keeps that honest.
	DefaultMaxReadBytes uint64

	// LineCountLimitBytes is the file size past which ReadFile stops counting
	// lines. Counting means reading every byte, and reading a gigabyte to
	// answer a windowed read is exactly what the caller asked not to do. Past
	// this size total_lines reports how far the count got and total_lines_exact
	// is false.
	LineCountLimitBytes int64

	// MaxEditBytes is the largest file EditFile will load. Exact-match
	// replacement needs the whole file, so this is a real ceiling rather than a
	// streaming threshold.
	MaxEditBytes int64

	// DefaultListEntries caps ListDirectory when the caller names no limit.
	DefaultListEntries int

	// DefaultGlobResults caps Glob when the caller names no limit.
	DefaultGlobResults int

	// MaxGlobCandidates bounds the paths Glob holds while walking. Glob sorts
	// by modification time, so it cannot stop at the first N matches the way
	// Grep can — the newest match may be the last file the walk reaches. This
	// bounds the memory that costs; hitting it is reported as truncation.
	MaxGlobCandidates int

	// DefaultGrepMatches caps Grep when the caller names no max_matches.
	DefaultGrepMatches uint64

	// MaxGrepLineBytes is the longest line Grep will read. A file with a longer
	// one is abandoned mid-scan rather than buffered: it is minified or packed
	// data, and matching a megabyte-long line usefully is not a thing.
	MaxGrepLineBytes int
}

// Defaults for [Limits]. They are exported because #24 renders what these
// produce and needs to describe the caps in the tool schema.
const (
	DefaultChunkBytes          = 64 * 1024
	DefaultReadLines           = 2000
	DefaultMaxReadBytes        = 8 * 1024 * 1024
	DefaultLineCountLimitBytes = 32 * 1024 * 1024
	DefaultMaxEditBytes        = 16 * 1024 * 1024
	DefaultListEntries         = 1000
	DefaultGlobResults         = 1000
	DefaultMaxGlobCandidates   = 100_000
	DefaultGrepMatches         = 500
	DefaultMaxGrepLineBytes    = 256 * 1024
)

// withDefaults fills every unset field, so a partially populated Limits from a
// test is still a working one.
func (l Limits) withDefaults() Limits {
	if l.ChunkBytes <= 0 {
		l.ChunkBytes = DefaultChunkBytes
	}
	if l.DefaultReadLines == 0 {
		l.DefaultReadLines = DefaultReadLines
	}
	if l.DefaultMaxReadBytes == 0 {
		l.DefaultMaxReadBytes = DefaultMaxReadBytes
	}
	if l.LineCountLimitBytes <= 0 {
		l.LineCountLimitBytes = DefaultLineCountLimitBytes
	}
	if l.MaxEditBytes <= 0 {
		l.MaxEditBytes = DefaultMaxEditBytes
	}
	if l.DefaultListEntries <= 0 {
		l.DefaultListEntries = DefaultListEntries
	}
	if l.DefaultGlobResults <= 0 {
		l.DefaultGlobResults = DefaultGlobResults
	}
	if l.MaxGlobCandidates <= 0 {
		l.MaxGlobCandidates = DefaultMaxGlobCandidates
	}
	if l.DefaultGrepMatches == 0 {
		l.DefaultGrepMatches = DefaultGrepMatches
	}
	if l.MaxGrepLineBytes <= 0 {
		l.MaxGrepLineBytes = DefaultMaxGrepLineBytes
	}
	return l
}

// Service implements sandboxd.v1.FileService.
//
// MakeDirectory, RemovePath and MovePath are not implemented here: they are in
// the proto but in none of #8, #9 or #10, and the embedded
// UnimplementedFileServiceServer answers them with codes.Unimplemented rather
// than a half-built version of a contract nobody has written down yet.
type Service struct {
	sandboxdv1.UnimplementedFileServiceServer

	// jail is the whole of this service's path handling. It is never nil: an
	// unconfined agent gets jail.Unconfined(), which normalises and permits.
	jail   *jail.Jail
	log    *slog.Logger
	limits Limits

	// locks serialise the read-modify-write of EditFile and the create-and-
	// rename of WriteFile against each other, per path. Without them two edits
	// that both read the same file before either renames leave whichever
	// renamed last as the only surviving edit.
	locks *pathLocks
}

// New builds the file service. It satisfies agent.Factory.
func New(deps agent.Deps) (agent.Service, error) {
	if deps.Jail == nil {
		// The daemon always supplies one — jail.Unconfined() when there is no
		// confinement — so a nil here is a wiring mistake. Refusing to build is
		// how it stays a startup failure instead of an unconfined agent.
		return nil, errors.New("fs: Deps.Jail is required; an unconfined agent supplies jail.Unconfined()")
	}
	if !deps.Jail.Configured() {
		return nil, errors.New("fs: Deps.Jail was never constructed; every path would be refused")
	}
	return NewService(deps.Jail, deps.Log, Limits{}), nil
}

// NewService builds a file service directly, for a caller that has a jail and a
// logger but no agent.Deps.
func NewService(j *jail.Jail, log *slog.Logger, limits Limits) *Service {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{
		jail:   j,
		log:    log.With("service", "fs"),
		limits: limits.withDefaults(),
		locks:  newPathLocks(),
	}
}

// Register attaches FileService to the daemon's gRPC server.
func (s *Service) Register(r grpc.ServiceRegistrar) {
	sandboxdv1.RegisterFileServiceServer(r, s)
}

// resolve puts a caller-supplied path through the jail and maps its refusals to
// gRPC codes.
//
// The returned path is the resolved one, which is the only path callers may
// hand to a syscall: re-deriving it from the request discards the symlink
// resolution that made the check mean anything.
func (s *Service) resolve(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", status.Error(codes.InvalidArgument, "path is required")
	}
	resolved, err := s.jail.Resolve(path)
	if err != nil {
		return "", s.pathError(path, err)
	}
	return resolved, nil
}

// lexical makes a caller's path absolute and cleans it, resolving no symlinks.
//
// It is never a containment decision — a lexically clean path can still be a
// symlink out of the jail, which is the mistake the jail package exists to
// prevent. Use it only alongside a successful resolve, to name the path the
// caller asked about rather than the one it turned out to be.
func (s *Service) lexical(path string) (string, error) {
	abs, err := platform.NormalizePath(s.jail.WorkingDir(), path)
	if err != nil {
		return "", status.Errorf(codes.InvalidArgument, "%s is not a path this agent will interpret: %v", path, err)
	}
	return abs, nil
}

// pathError maps a jail refusal, or an ordinary filesystem error, to a status.
//
// The allowed roots are named only when there are some. On an unconfined agent
// there is no rejection to explain and no roots to name, and inventing either
// would be the model-facing version of telling an operator they are confined
// when they are not.
func (s *Service) pathError(path string, err error) error {
	switch {
	case errors.Is(err, jail.ErrOutsideJail):
		return status.Errorf(codes.PermissionDenied,
			"%s is outside the allowed roots %s", path, strings.Join(s.jail.ConfiguredRoots(), ", "))
	case errors.Is(err, jail.ErrDanglingSymlink):
		return status.Errorf(codes.FailedPrecondition,
			"%s traverses a symlink whose target does not exist; the agent refuses it because there is nothing to check containment against", path)
	case errors.Is(err, jail.ErrInvalidPath), errors.Is(err, platform.ErrPathNamespace):
		return status.Errorf(codes.InvalidArgument, "%s is not a path this agent will interpret: %v", path, err)
	case errors.Is(err, jail.ErrNotConfigured):
		return status.Errorf(codes.Internal, "the agent has no path jail configured, so every path is refused")
	}
	return fileError(path, err)
}

// fileError maps an ordinary filesystem error to a status code.
func fileError(path string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fs.ErrNotExist):
		return status.Errorf(codes.NotFound, "%s does not exist", path)
	case errors.Is(err, fs.ErrExist):
		return status.Errorf(codes.AlreadyExists, "%s already exists", path)
	case errors.Is(err, fs.ErrPermission):
		return status.Errorf(codes.PermissionDenied, "%s: permission denied", path)
	case errors.Is(err, context.Canceled):
		return status.FromContextError(err).Err()
	case errors.Is(err, context.DeadlineExceeded):
		return status.FromContextError(err).Err()
	}
	// Unwrap a *PathError so the message reads as one sentence rather than
	// repeating the path the caller already sent.
	var pe *os.PathError
	if errors.As(err, &pe) {
		return status.Errorf(codes.Internal, "%s: %s: %v", path, pe.Op, pe.Err)
	}
	return status.Errorf(codes.Internal, "%s: %v", path, err)
}

// ctxErr converts a cancelled request context into the status a handler should
// return, and nil when the context is still live.
func ctxErr(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return status.FromContextError(err).Err()
	}
	return nil
}

// truncation builds the Truncation every capped response carries. It is always
// non-nil: a caller that cannot tell a truncated result from a complete one
// draws wrong conclusions from it, and an absent message is exactly that
// ambiguity.
func truncation(truncated bool, bytesOmitted, linesOmitted uint64) *sandboxdv1.Truncation {
	return &sandboxdv1.Truncation{
		Truncated:    truncated,
		BytesOmitted: bytesOmitted,
		LinesOmitted: linesOmitted,
	}
}

// u64 converts a size or a byte count to the unsigned form the proto uses.
//
// Every caller's value is non-negative by construction — a file size, a byte
// count from a read, a configured limit — and the guard makes that true rather
// than assumed, so a negative that should be impossible becomes a zero instead
// of a number near 2^64 that a caller would render as a real quantity.
func u64[T int | int64](n T) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}
