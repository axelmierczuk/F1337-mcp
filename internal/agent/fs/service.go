package fs

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
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

// Service implements sandboxd.v1.FileService: every RPC the proto declares.
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

// resolveSelf resolves a path for an operation on the path itself rather than
// on whatever it points at. verb names the operation, for the error an allowed
// root produces.
//
// Containment is decided on the resolved *parent*, and the last component is
// left exactly as the caller wrote it. That difference is the whole of it:
// resolving the last component too — which every content RPC here does, because
// reading a symlink should read its target — would make RemovePath delete what
// a link points at and MovePath drag it somewhere else. A link inside the roots
// aimed anywhere at all is then a way out of them, which is the classic shape
// of this bug.
//
// The parent still gets the full treatment, so a path whose directory is a
// symlink out of the jail is refused exactly as it would be anywhere else.
func (s *Service) resolveSelf(path, verb string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", status.Error(codes.InvalidArgument, "path is required")
	}
	named, err := s.lexical(path)
	if err != nil {
		return "", err
	}
	parent := filepath.Dir(named)
	if parent == named {
		// A filesystem root has no parent to check, and is not something this
		// service will unlink or rename under any configuration.
		return "", status.Errorf(codes.InvalidArgument,
			"%s is a filesystem root, not a path this agent will operate on", named)
	}
	// An allowed root is refused here rather than by the resolve below, and the
	// reason is the message rather than the outcome. The parent of a root is
	// outside the jail by construction, so resolving it refuses the request —
	// correctly — with "the parent is outside the allowed roots", which names a
	// directory the caller never mentioned and reads as a contradiction when the
	// root is its own answer. Refusing the root by name says the true thing.
	// The handlers check the *resolved* target as well, for the spellings this
	// lexical comparison cannot see; see Service.refuseJailRoot.
	if err := s.refuseJailRoot(named, verb); err != nil {
		return "", err
	}
	resolvedParent, err := s.resolve(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolvedParent, filepath.Base(named)), nil
}

// writeTarget returns the path a write should commit to, given an
// already-jail-resolved one.
//
// Every write here lands by renaming a sibling temp file over the target, and a
// rename over a symlink replaces the link with a regular file. So the path a
// write commits to has to be the file the name resolves to, not the name
// itself. A confined jail has already done that — Resolve follows every symlink
// and returns what the kernel would reach — but jail.Unconfined normalises
// without resolving, and the unconfined agent is the *default* one, since the
// jail is only wired in with exec disabled.
//
// Without this, a write to a symlinked path on a default agent unlinks the
// symlink, writes a new file where it stood, leaves the file the caller meant
// to change untouched, and gives the new file the link's own permission bits —
// 0777 on Linux, where a symlink is lrwxrwxrwx. All three are wrong, and the
// last one is world-writable.
//
// A dangling link is left as the caller wrote it. There is nothing to write
// through, and creating the file the link points at is a decision this does not
// make on the caller's behalf.
//
// The whole path is resolved, not only its last component, and the difference
// shows up in the same place: two spellings of one file. A confined jail returns
// a path with every symlink on it already followed, so "dir/f" and "link/f" are
// the same string by the time a handler sees them and take the same path lock.
// Unconfined they are two strings, so two concurrent edits to the one file take
// two different locks and the second silently discards the first — the lost
// update the locks exist to prevent, reached by naming a parent directory
// through a link instead of the file itself.
func (s *Service) writeTarget(resolved string) (string, error) {
	target := resolveExisting(resolved)
	if !s.jail.ContainsResolved(target) {
		// This is the check that following the link requires, not a formality.
		// A rename does not follow a symlink in its final component, so before
		// this function existed a link swapped in after the resolve could only
		// ever be *replaced*, never written through. Following it deliberately
		// gives up that accident, so containment is decided again on what the
		// link actually points at — which is what catches a component swapped
		// for a symlink between Resolve and here, the race the jail package
		// documents as unavoidable off Linux.
		return "", s.pathError(resolved, jail.ErrOutsideJail)
	}
	return target, nil
}

// resolveExisting returns path with every symlink on it followed, as far as the
// filesystem can follow them.
//
// A path that resolves whole is returned resolved. A path whose last component
// does not resolve — it does not exist yet, or it is a dangling link — keeps that
// component exactly as written and takes the resolved form of its parent, which
// is what lets a write create a file, and what leaves a dangling link where it
// stands rather than creating whatever it pointed at.
//
// Nothing here is a containment decision, and it returns no error: a path that
// cannot be resolved at all is returned unchanged, and the syscall that follows
// reports what is wrong with it better than a guess here would. The caller
// re-checks containment on the result; see Service.writeTarget.
func resolveExisting(path string) string {
	if target, err := filepath.EvalSymlinks(path); err == nil {
		return target
	}
	parent := filepath.Dir(path)
	if parent == path {
		return path
	}
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return path
	}
	return filepath.Join(resolvedParent, filepath.Base(path))
}

// isIrregular reports whether path is something other than a regular file or a
// directory: a device, a socket or a named pipe.
//
// A path that cannot be stat'd is not irregular as far as this is concerned.
// Whatever is wrong with it, the syscall that follows reports it better than a
// guess here would.
func isIrregular(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir() && !info.Mode().IsRegular()
}

// refuseIrregular rejects a path that is neither a regular file nor a
// directory.
//
// Opening a named pipe blocks inside open(2) until a writer appears. Nothing
// times it out and a cancelled request cannot interrupt it, so one RPC naming a
// FIFO strands its handler goroutine for the life of the process — and the FIFO
// does not have to be the caller's own, only present in a tree it can name. A
// device or a socket is no better behaved, and none of the three has contents a
// file RPC could return.
//
// walkTree has skipped these since it was written; this is the same rule for
// the paths a caller names directly. Directories are left to the callers, which
// have something more useful to say about them.
func refuseIrregular(path string) error {
	if !isIrregular(path) {
		return nil
	}
	return status.Errorf(codes.FailedPrecondition,
		"%s is not a regular file; this agent will not open a device, a socket or a named pipe, because reading one either blocks with no way to time it out or returns something that is not a file's contents",
		path)
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
