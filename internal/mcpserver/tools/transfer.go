package tools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/sandboxd-mcp/internal/mcpserver/selection"
)

// Directions for sandbox_transfer.
const (
	directionPush = "push"
	directionPull = "pull"
)

// Bounds on one transfer.
const (
	// MaxTransferFiles is the most files one call will move.
	//
	// A cap that is hit is a call that fails in a second naming the limit,
	// where an uncapped one is a call that runs for ten minutes and is
	// abandoned — and an abandoned transfer leaves a half-copied tree nobody
	// knows the shape of.
	MaxTransferFiles = 5000

	// MaxTransferBytes is the most content one call will move.
	MaxTransferBytes = 256 << 20

	// maxSkipsReported bounds the skip list in the result. The count is always
	// exact; it is the enumeration that is capped.
	maxSkipsReported = 25

	// transferDirMode is the permission a pull gives a directory it has to
	// create. It is the caller's own working directory tree, and the files
	// inside it carry the sandbox's modes rather than this one.
	transferDirMode = 0o750
)

// defaultExcludes are the directories and files nobody means to copy.
//
// They are defaults rather than a fixed list: a caller's own exclude patterns
// are added to these, and the result always reports how many entries they
// skipped, so the exclusion is never silent. Applied only *below* the source
// root, so naming .git as the source still transfers it.
var defaultExcludes = []string{
	".git", ".hg", ".svn",
	"node_modules", "vendor", "target", "dist", "build",
	".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
	".next", ".nuxt", ".terraform", ".gradle", ".tox",
	".idea", ".vscode", ".DS_Store",
	"*.pyc", "*.class",
}

// registerTransfer adds sandbox_transfer.
func registerTransfer(r *Registrar) {
	AddTargeted(r, &mcp.Tool{
		Name:  "sandbox_transfer",
		Title: "Transfer files",
		Description: "Copy files or directories between this workstation and the selected sandbox. " +
			"push sends local to remote, pull the reverse. Executable bits are preserved. " +
			".git, node_modules and other build directories are excluded by default, and pull writes only inside this workstation's working directory unless allow_outside_working_dir is set.",
	}, r.sandboxTransfer)
}

// TransferArgs are the arguments to sandbox_transfer.
type TransferArgs struct {
	TargetArgs
	// Direction is push or pull.
	Direction string `json:"direction" jsonschema:"push to send this workstation's files to the sandbox, or pull to fetch the sandbox's"`
	// Source is the path being copied from, on whichever side Direction names.
	Source string `json:"source" jsonschema:"path to copy from: local for push, on the sandbox for pull"`
	// Destination is the path being copied to.
	Destination string `json:"destination" jsonschema:"path to copy to: on the sandbox for push, local for pull. An existing directory receives the source under its own name"`
	// Recursive permits a directory transfer.
	Recursive bool `json:"recursive,omitempty" jsonschema:"required to transfer a directory rather than a single file"`
	// Exclude adds glob patterns to the defaults.
	Exclude []string `json:"exclude,omitempty" jsonschema:"extra glob patterns to skip, matched against each path segment and the path relative to source; added to the defaults"`
	// Force re-sends files the unchanged check would skip.
	Force bool `json:"force,omitempty" jsonschema:"re-send files that look unchanged; by default a file whose size matches and whose destination is no older is skipped"`
	// AllowOutsideWorkingDir lifts the local write confinement.
	AllowOutsideWorkingDir bool `json:"allow_outside_working_dir,omitempty" jsonschema:"permit a pull to write outside this workstation's working directory; off by default because the local filesystem has no jail"`
}

// TransferSkip is one entry that was not transferred, and why.
type TransferSkip struct {
	// Path is the entry, relative to the source root.
	Path string `json:"path" jsonschema:"the entry that was not transferred, relative to source"`
	// Reason says why in a few words.
	Reason string `json:"reason" jsonschema:"why it was skipped"`
}

// TransferResult is the sandbox_transfer result.
type TransferResult struct {
	// Echo carries the sandbox the transfer went to or came from.
	Echo
	// Direction is push or pull.
	Direction string `json:"direction" jsonschema:"push or pull"`
	// Source is the resolved source path.
	Source string `json:"source" jsonschema:"the resolved source path"`
	// Destination is the resolved destination path.
	Destination string `json:"destination" jsonschema:"the resolved destination path"`
	// Files is how many files were written.
	Files int `json:"files" jsonschema:"how many files were written"`
	// Bytes is how much content was written.
	Bytes uint64 `json:"bytes" jsonschema:"how many bytes were written"`
	// Size renders Bytes for a reader.
	Size string `json:"size,omitempty" jsonschema:"the same byte count, human-readable"`
	// DurationMs is how long the transfer took.
	DurationMs int64 `json:"duration_ms" jsonschema:"wall-clock milliseconds the transfer took"`
	// Unchanged counts files skipped because the destination already matched.
	Unchanged int `json:"unchanged,omitempty" jsonschema:"files skipped because the destination already looked identical"`
	// Excluded counts entries an exclude pattern skipped.
	Excluded int `json:"excluded,omitempty" jsonschema:"entries skipped by an exclude pattern"`
	// SkippedCount is the exact number of entries skipped for a reason worth
	// reporting — a symlink out of the tree, an unreadable file.
	SkippedCount int `json:"skipped_count,omitempty" jsonschema:"entries skipped for a reason worth reporting"`
	// Skipped enumerates those entries, capped.
	Skipped []TransferSkip `json:"skipped,omitempty" jsonschema:"the skipped entries, capped in number; skipped_count is exact"`
	// Note states anything the counts alone would leave the model to infer.
	Note string `json:"note,omitempty" jsonschema:"what the transfer did when the counts alone do not say it"`
}

// transferEntry is one file the transfer will move.
type transferEntry struct {
	// rel is the path relative to the source root, in slash form.
	rel string
	// source and destination are the absolute paths on their own sides,
	// already spelled for the filesystem that will see them.
	source      string
	destination string
	size        uint64
	mode        uint32
	modified    time.Time
}

// transferPlan is what a walk of the source produced: what to move, what was
// deliberately left behind, and why.
type transferPlan struct {
	entries  []transferEntry
	skips    []TransferSkip
	excluded int
	bytes    uint64
	// dir reports whether the source was a directory, which decides how the
	// destination is composed.
	dir bool
}

func (r *Registrar) sandboxTransfer(ctx context.Context, _ *mcp.CallToolRequest, target *selection.Target, in TransferArgs) (TransferResult, error) {
	direction := strings.ToLower(strings.TrimSpace(in.Direction))
	if direction != directionPush && direction != directionPull {
		return TransferResult{}, fmt.Errorf(`direction %q is not push or pull: push sends this workstation's files to the sandbox, pull fetches the sandbox's`, in.Direction)
	}
	if strings.TrimSpace(in.Source) == "" || strings.TrimSpace(in.Destination) == "" {
		return TransferResult{}, errors.New("source and destination are both required")
	}

	files, err := r.deps.Clients.Files(target.Name(), target.Address())
	if err != nil {
		return TransferResult{}, target.Call().Map(err)
	}

	matcher, err := newExcludeMatcher(in.Exclude)
	if err != nil {
		return TransferResult{}, err
	}

	started := time.Now()
	sep := remoteSeparator(target)

	var (
		plan  *transferPlan
		moved transferCounts
	)
	if direction == directionPush {
		plan, err = r.planPush(ctx, files, target, in, matcher, sep)
		if err != nil {
			return TransferResult{}, err
		}
		moved, err = r.runPush(ctx, files, target, plan, in.Destination, in.Force)
	} else {
		plan, err = r.planPull(ctx, files, target, in, matcher)
		if err != nil {
			return TransferResult{}, err
		}
		moved, err = r.runPull(ctx, files, target, plan, in.Force)
	}
	if err != nil {
		return TransferResult{}, err
	}

	return renderTransfer(direction, in, plan, moved, started, sep), nil
}

// transferCounts is what actually moved.
type transferCounts struct {
	files     int
	bytes     uint64
	unchanged int
}

// renderTransfer assembles the summary.
func renderTransfer(direction string, in TransferArgs, plan *transferPlan, moved transferCounts, started time.Time, sep string) TransferResult {
	source, destination := in.Source, in.Destination
	if len(plan.entries) > 0 && !plan.dir {
		source, destination = plan.entries[0].source, plan.entries[0].destination
	}

	out := TransferResult{
		Direction:    direction,
		Source:       source,
		Destination:  destination,
		Files:        moved.files,
		Bytes:        moved.bytes,
		Size:         humanBytes(moved.bytes),
		DurationMs:   time.Since(started).Milliseconds(),
		Unchanged:    moved.unchanged,
		Excluded:     plan.excluded,
		SkippedCount: len(plan.skips),
	}
	if len(plan.skips) > maxSkipsReported {
		out.Skipped = plan.skips[:maxSkipsReported]
	} else {
		out.Skipped = plan.skips
	}

	var note notes
	if moved.files == 0 && moved.unchanged == 0 && len(plan.entries) == 0 {
		note.add("Nothing was transferred: the source matched no files after exclusions.")
	}
	if moved.unchanged > 0 {
		note.add("%s already up to date and not re-sent; pass force to send them anyway.",
			plural(moved.unchanged, "file was", "files were"))
	}
	if plan.excluded > 0 {
		note.add("%s skipped by an exclude pattern. The defaults cover .git, node_modules, vendor, target and similar build output.",
			plural(plan.excluded, "entry was", "entries were"))
	}
	if len(plan.skips) > maxSkipsReported {
		note.add("%d entries were skipped; the first %d are listed.", len(plan.skips), maxSkipsReported)
	}
	if plan.dir && sep != "/" && direction == directionPush {
		note.add("The sandbox uses %q as its path separator; destination paths were composed with it.", sep)
	}
	out.Note = note.String()
	return out
}

// remoteSeparator is the path separator the sandbox uses, from whatever the
// registry cached about it. Unix is the fallback: it is right for two of the
// three platforms, and a Windows agent accepts forward slashes in any case —
// so guessing wrong costs a cosmetically odd path, not a failed transfer.
func remoteSeparator(target *selection.Target) string {
	if sep := target.Sandbox.Platform.PathSeparator; sep != "" {
		return sep
	}
	return "/"
}

// remoteJoin composes a remote path from a base and a slash-separated relative
// path.
func remoteJoin(base, rel, sep string) string {
	if rel == "" {
		return base
	}
	trimmed := strings.TrimRight(base, `/\`)
	return trimmed + sep + strings.ReplaceAll(rel, "/", sep)
}

// ------------------------------------------------------------------ push

// planPush walks the local source and decides what will move.
//
// The whole walk happens before anything is sent, which is what lets a cap be
// an error rather than an abandoned half-transfer, and what lets the skip list
// be complete in the result rather than trickling out as it goes.
func (r *Registrar) planPush(ctx context.Context, files sandboxdv1.FileServiceClient, target *selection.Target, in TransferArgs, matcher *excludeMatcher, sep string) (*transferPlan, error) {
	root, err := filepath.Abs(in.Source)
	if err != nil {
		return nil, fmt.Errorf("source %s is not a usable local path: %w", in.Source, err)
	}
	info, err := os.Stat(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("source %s does not exist on this workstation. push takes a local source; use pull to fetch from the sandbox", root)
	}
	if err != nil {
		return nil, fmt.Errorf("source %s cannot be read on this workstation: %w", root, err)
	}

	plan := &transferPlan{dir: info.IsDir()}
	if !info.IsDir() {
		destination, err := r.pushFileDestination(ctx, files, target, root, in.Destination, sep)
		if err != nil {
			return nil, err
		}
		plan.entries = append(plan.entries, transferEntry{
			rel:         filepath.Base(root),
			source:      root,
			destination: destination,
			size:        u64(info.Size()),
			mode:        uint32(info.Mode().Perm()),
			modified:    info.ModTime(),
		})
		plan.bytes = u64(info.Size())
		return plan, nil
	}

	if !in.Recursive {
		return nil, fmt.Errorf("source %s is a directory; set recursive to transfer a tree", root)
	}

	// WalkDir lstats its own root, so a source that is itself a symlink to a
	// directory would walk as one entry and transfer nothing. The caller named
	// it, so it is followed here — the escape rule below is about links found
	// *inside* the tree, not about the tree the caller chose.
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}

	walkErr := filepath.WalkDir(root, func(current string, entry fs.DirEntry, err error) error {
		if err != nil {
			// A directory that cannot be read is reported rather than failing
			// the transfer: one unreadable subtree in a repository should not
			// stop the other nine hundred files from arriving.
			plan.skips = append(plan.skips, TransferSkip{Path: relSlash(root, current), Reason: "could not be read: " + err.Error()})
			return nil //nolint:nilerr // recorded as a skip and reported; one unreadable subtree must not stop the rest of the tree
		}
		if current == root {
			return nil
		}
		rel := relSlash(root, current)
		if matcher.matches(rel, entry.Name()) {
			plan.excluded++
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			plan.skips = append(plan.skips, TransferSkip{Path: rel, Reason: "could not be stat'd: " + err.Error()})
			return nil //nolint:nilerr // recorded as a skip and reported, for the same reason as above
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			resolved, reason := resolveLocalSymlink(root, current)
			if reason != "" {
				plan.skips = append(plan.skips, TransferSkip{Path: rel, Reason: reason})
				return nil
			}
			target, err := os.Stat(resolved)
			if err != nil || !target.Mode().IsRegular() {
				plan.skips = append(plan.skips, TransferSkip{Path: rel, Reason: "symlink does not point at a regular file"})
				return nil //nolint:nilerr // recorded as a skip and reported, for the same reason as above
			}
			info = target
			current = resolved
		}
		if !info.Mode().IsRegular() {
			plan.skips = append(plan.skips, TransferSkip{Path: rel, Reason: "not a regular file"})
			return nil
		}

		plan.entries = append(plan.entries, transferEntry{
			rel:         rel,
			source:      current,
			destination: remoteJoin(in.Destination, rel, sep),
			size:        u64(info.Size()),
			mode:        uint32(info.Mode().Perm()),
			modified:    info.ModTime(),
		})
		plan.bytes += u64(info.Size())
		return checkCaps(len(plan.entries), plan.bytes)
	})
	if walkErr != nil {
		return nil, walkErr
	}
	sort.Slice(plan.entries, func(i, j int) bool { return plan.entries[i].rel < plan.entries[j].rel })
	return plan, checkCaps(len(plan.entries), plan.bytes)
}

// pushFileDestination decides where a single pushed file lands: under the
// destination when it names an existing directory, at it otherwise. That is
// cp's rule, and getting it wrong turns "copy this into the workspace" into
// "replace the workspace with this file".
func (r *Registrar) pushFileDestination(ctx context.Context, files sandboxdv1.FileServiceClient, target *selection.Target, source, destination, sep string) (string, error) {
	callCtx, cancel := context.WithTimeout(ctx, r.deps.callTimeout())
	defer cancel()

	stat, err := files.StatPath(callCtx, &sandboxdv1.StatPathRequest{Path: destination})
	if err != nil {
		// A destination that cannot be described is not necessarily a
		// destination that cannot be written — the parent may simply not exist
		// yet — so this falls through to the literal interpretation rather than
		// failing the call.
		if status.Code(err) == codes.NotFound {
			return destination, nil
		}
		return "", pathCall(target, destination).Map(err)
	}
	if stat.GetExists() && stat.GetMetadata().GetIsDir() {
		return remoteJoin(destination, filepath.Base(source), sep), nil
	}
	return destination, nil
}

// runPush sends the planned files.
func (r *Registrar) runPush(ctx context.Context, files sandboxdv1.FileServiceClient, target *selection.Target, plan *transferPlan, destination string, force bool) (transferCounts, error) {
	var moved transferCounts

	existing := map[string]*sandboxdv1.FileMetadata{}
	if !force {
		existing = r.remoteIndex(ctx, files, plan, destination)
	}

	for _, entry := range plan.entries {
		if !force && unchangedRemote(existing[transferKey(entry.rel)], entry) {
			moved.unchanged++
			continue
		}

		//nolint:gosec // the path is the caller's own source, already walked from it
		handle, err := os.Open(entry.source)
		if err != nil {
			return moved, fmt.Errorf("reading %s on this workstation: %w", entry.source, err)
		}

		callCtx, cancel := context.WithTimeout(ctx, r.deps.streamTimeout(entry.size))
		resp, err := writeStream(callCtx, files, &sandboxdv1.WriteFileHeader{
			Path:          entry.destination,
			Mode:          entry.mode,
			CreateParents: true,
		}, handle)
		cancel()
		_ = handle.Close()
		if err != nil {
			return moved, fmt.Errorf("transferred %d of %d files, then %w",
				moved.files, len(plan.entries), pathCall(target, entry.destination).Map(err))
		}
		moved.files++
		moved.bytes += resp.GetBytesWritten()
	}
	return moved, nil
}

// remoteIndex lists what is already at the destination, so a repeat push can
// skip what has not changed.
//
// One listing rather than a stat per file: the common workflow is push, edit,
// push again over a tree of a few thousand files, and a round trip each is the
// difference between a second and a minute. A listing that fails for any
// reason yields an empty index, which costs a re-send and never a wrong one.
//
// The index is keyed by [transferKey], never by an absolute path. See there.
func (r *Registrar) remoteIndex(ctx context.Context, files sandboxdv1.FileServiceClient, plan *transferPlan, destination string) map[string]*sandboxdv1.FileMetadata {
	index := map[string]*sandboxdv1.FileMetadata{}
	callCtx, cancel := context.WithTimeout(ctx, r.deps.callTimeout())
	defer cancel()

	if !plan.dir {
		if len(plan.entries) == 0 {
			return index
		}
		stat, err := files.StatPath(callCtx, &sandboxdv1.StatPathRequest{Path: plan.entries[0].destination})
		if err == nil && stat.GetExists() {
			index[transferKey(plan.entries[0].rel)] = stat.GetMetadata()
		}
		return index
	}

	// Every entry shares one destination root, so listing it once covers them
	// all. The root is the argument the caller gave, which is also what the
	// writes were composed from; the agent normalises it on its own side and
	// reports back what it resolved to, which is what the entries are made
	// relative to below.
	resp, err := files.ListDirectory(callCtx, &sandboxdv1.ListDirectoryRequest{
		Path: destination, Recursive: true, Limit: MaxTransferFiles, IncludeHidden: true,
	})
	if err != nil {
		return index
	}
	root := resp.GetPath()
	for _, entry := range resp.GetEntries() {
		index[transferKey(relativeTo(root, entry.GetPath()))] = entry
	}
	return index
}

// transferKey is how the two sides of a repeat push agree on which file is
// which.
//
// It is a path *relative* to the transfer root, with separators normalised,
// and both halves of that are load-bearing.
//
// Relative, because the absolute paths do not match and cannot be made to.
// This side composes a destination from the caller's argument and the sandbox's
// cached path separator; the sandbox answers with whatever its own walk
// produced, rooted at the path its normalisation resolved to. On a Windows
// sandbox those are `…\workspace/go.mod` and `…\workspace\go.mod` — the same
// file, two strings. Keying on them made every file look new on the second
// push, so a tree that had just been sent was sent again in full, silently,
// on every push. The part both sides genuinely agree on is the path *within*
// the tree.
//
// Separators normalised, because the same divergence appears inside the
// relative part of a nested path: this side builds `cmd/app/main.go` and a
// Windows sandbox reports `cmd\app\main.go`.
//
// Case is deliberately *not* folded. Whether a filesystem folds case is a
// property of that filesystem, not of the platform — macOS usually folds,
// Linux does not, and Windows can be configured either way — so folding here
// would be a guess. Guessing wrong makes two files that differ only in case
// share one key, and the second one is then skipped as unchanged when it is
// not: a wrong answer. A redundant re-send is merely slow.
func transferKey(rel string) string {
	rel = strings.ReplaceAll(rel, `\`, "/")
	rel = strings.TrimPrefix(rel, "./")
	return strings.Trim(rel, "/")
}

// unchangedRemote reports whether the destination already holds this file.
//
// Size plus "the destination is no older than the source" — rsync's quick
// check, minus the mtime preservation this protocol has no field for. It is a
// heuristic and it is documented as one: a local file whose content changed
// without its size changing *and* whose mtime went backwards is skipped, which
// is what force exists for. The alternative, hashing, means reading the whole
// remote file back to compare it, which costs the same as re-sending it.
func unchangedRemote(remote *sandboxdv1.FileMetadata, entry transferEntry) bool {
	if remote == nil || remote.GetIsDir() || remote.GetSizeBytes() != entry.size {
		return false
	}
	modified := remote.GetModifiedAt()
	if modified == nil {
		return false
	}
	return !modified.AsTime().Before(entry.modified)
}

// ------------------------------------------------------------------ pull

// planPull lists the remote source and decides what will come back.
func (r *Registrar) planPull(ctx context.Context, files sandboxdv1.FileServiceClient, target *selection.Target, in TransferArgs, matcher *excludeMatcher) (*transferPlan, error) {
	callCtx, cancel := context.WithTimeout(ctx, r.deps.callTimeout())
	defer cancel()

	stat, err := files.StatPath(callCtx, &sandboxdv1.StatPathRequest{Path: in.Source})
	if err != nil {
		return nil, pathCall(target, in.Source).Map(err)
	}
	if !stat.GetExists() {
		return nil, fmt.Errorf("source %s does not exist on sandbox %s. pull takes a source on the sandbox; use push to send from this workstation",
			in.Source, target.Name())
	}

	metadata := stat.GetMetadata()
	plan := &transferPlan{dir: metadata.GetIsDir()}

	if !metadata.GetIsDir() {
		if metadata.GetIsSymlink() {
			// The same rule the recursive walk applies, for the same reason:
			// ReadFile follows the link on the sandbox, so this would copy
			// whatever it points at under the link's name — and the metadata
			// here describes the *link*, so the file would land with the link's
			// size and the link's mode, which on Linux is 0777.
			return nil, fmt.Errorf(
				"source %s on sandbox %s is a symlink to %s, and links are not followed: reading it would copy that file under this name, with the link's permissions rather than its own. Name the target directly if that is what you mean",
				in.Source, target.Name(), metadata.GetSymlinkTarget())
		}
		destination, err := localFileDestination(in.Destination, metadata.GetPath(), in.AllowOutsideWorkingDir)
		if err != nil {
			return nil, err
		}
		plan.entries = append(plan.entries, transferEntry{
			rel:         path.Base(strings.ReplaceAll(metadata.GetPath(), `\`, "/")),
			source:      in.Source,
			destination: destination,
			size:        metadata.GetSizeBytes(),
			mode:        metadata.GetMode(),
			modified:    modifiedTime(metadata),
		})
		plan.bytes = metadata.GetSizeBytes()
		return plan, nil
	}

	if !in.Recursive {
		return nil, fmt.Errorf("source %s is a directory on sandbox %s; set recursive to transfer a tree", in.Source, target.Name())
	}

	destinationRoot, err := localWriteTarget(in.Destination, in.AllowOutsideWorkingDir)
	if err != nil {
		return nil, err
	}

	listCtx, listCancel := context.WithTimeout(ctx, r.deps.callTimeout())
	defer listCancel()
	listing, err := files.ListDirectory(listCtx, &sandboxdv1.ListDirectoryRequest{
		Path: in.Source, Recursive: true, Limit: MaxTransferFiles, IncludeHidden: true,
	})
	if err != nil {
		return nil, pathCall(target, in.Source).Map(err)
	}
	if listing.GetTruncation().GetTruncated() {
		return nil, fmt.Errorf("%s on sandbox %s holds more than the %d files one transfer will move; narrow it with exclude or pull a subdirectory",
			in.Source, target.Name(), MaxTransferFiles)
	}

	root := listing.GetPath()
	for _, entry := range listing.GetEntries() {
		rel := strings.ReplaceAll(relativeTo(root, entry.GetPath()), `\`, "/")
		if rel == "" || rel == entry.GetPath() {
			continue
		}
		if matcher.matches(rel, path.Base(rel)) {
			plan.excluded++
			continue
		}
		if entry.GetIsDir() {
			continue
		}
		if entry.GetIsSymlink() {
			// Skipped rather than followed, and reported rather than dropped.
			// ReadFile follows a link server-side, so pulling one would copy
			// whatever it points at under the link's name — and deciding
			// whether that target is inside the source tree means resolving a
			// remote path from here, which is the "check before resolution"
			// mistake the agent's own jail exists to avoid.
			plan.skips = append(plan.skips, TransferSkip{
				Path:   rel,
				Reason: "symlink to " + entry.GetSymlinkTarget() + "; links are not followed out of the source tree",
			})
			continue
		}
		destination, skipReason := localEntryDestination(destinationRoot, rel, in.AllowOutsideWorkingDir)
		if skipReason != "" {
			plan.skips = append(plan.skips, TransferSkip{Path: rel, Reason: skipReason})
			continue
		}
		plan.entries = append(plan.entries, transferEntry{
			rel:         rel,
			source:      entry.GetPath(),
			destination: destination,
			size:        entry.GetSizeBytes(),
			mode:        entry.GetMode(),
			modified:    modifiedTime(entry),
		})
		plan.bytes += entry.GetSizeBytes()
	}
	sort.Slice(plan.entries, func(i, j int) bool { return plan.entries[i].rel < plan.entries[j].rel })
	return plan, checkCaps(len(plan.entries), plan.bytes)
}

// runPull fetches the planned files.
func (r *Registrar) runPull(ctx context.Context, files sandboxdv1.FileServiceClient, target *selection.Target, plan *transferPlan, force bool) (transferCounts, error) {
	var moved transferCounts

	for _, entry := range plan.entries {
		if !force && unchangedLocal(entry) {
			moved.unchanged++
			continue
		}
		if err := os.MkdirAll(filepath.Dir(entry.destination), transferDirMode); err != nil {
			return moved, fmt.Errorf("creating %s on this workstation: %w", filepath.Dir(entry.destination), err)
		}

		callCtx, cancel := context.WithTimeout(ctx, r.deps.streamTimeout(entry.size))
		written, err := r.pullFile(callCtx, files, entry)
		cancel()
		if err != nil {
			return moved, fmt.Errorf("transferred %d of %d files, then %w",
				moved.files, len(plan.entries), pathCall(target, entry.source).Map(err))
		}
		moved.files++
		moved.bytes += written
	}
	return moved, nil
}

// pullFile streams one remote file into a local temporary and renames it into
// place.
//
// The rename is what makes an interrupted transfer leave nothing behind: a
// cancelled call, a dead agent or a full disk leaves a temporary file that is
// removed on the way out, never a destination holding half a file that every
// later reader will treat as whole.
func (r *Registrar) pullFile(ctx context.Context, files sandboxdv1.FileServiceClient, entry transferEntry) (uint64, error) {
	// MaxBytes is set explicitly, and it is not optional. ReadFile applies the
	// agent's own default when a request names none, and that default is 8 MiB
	// — sized for a caller reading a file into a result, not for one copying a
	// file. Left unset, every pull of anything larger arrives silently
	// truncated, is renamed into place, and is reported as a completed
	// transfer. The cap on a transfer is the transfer's own.
	stream, err := files.ReadFile(ctx, &sandboxdv1.ReadFileRequest{
		Path: entry.source, Raw: true, MaxBytes: MaxTransferBytes,
	})
	if err != nil {
		return 0, err
	}

	dir := filepath.Dir(entry.destination)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(entry.destination)+"-*.part")
	if err != nil {
		return 0, fmt.Errorf("creating a temporary file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	var (
		written uint64
		result  *sandboxdv1.ReadResult
	)
	for {
		msg, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		if recvErr != nil {
			return 0, recvErr
		}
		switch event := msg.GetEvent().(type) {
		case *sandboxdv1.ReadFileResponse_Chunk:
			n, err := tmp.Write(event.Chunk)
			if err != nil {
				return 0, fmt.Errorf("writing %s: %w", tmpPath, err)
			}
			written += u64(n)
		case *sandboxdv1.ReadFileResponse_Result:
			result = event.Result
		}
	}

	// The stream is metadata, then chunks, then exactly one result. Ending
	// without one means the read did not finish, and the bytes that did arrive
	// are a prefix of the file rather than the file. Committing that is the
	// same failure as committing a truncated read, arrived at from the other
	// direction, and nil-safe getters would report it as a whole file.
	if result == nil {
		return 0, fmt.Errorf(
			"the sandbox ended the read of %s without reporting a result, so whether the file arrived whole is unknown; it was not written", entry.source)
	}

	// A truncated read is a failed transfer, not a smaller file. Committing it
	// would rename a partial copy into place under the real name, where every
	// later reader — and every later unchanged check, which compares sizes —
	// treats it as the whole thing. The temporary file is discarded by the
	// deferred cleanup above, so the destination keeps whatever it had.
	if result.GetTruncation().GetTruncated() {
		return 0, fmt.Errorf(
			"%s was truncated by the sandbox after %d of %d bytes, so it was not written; transfer it in pieces, or raise the agent's read cap",
			entry.source, written, entry.size)
	}

	mode := fs.FileMode(entry.mode).Perm()
	if mode == 0 {
		// A sandbox that reports no mode bits — Windows does — still has to
		// produce a readable file here rather than one with no permissions at
		// all.
		mode = 0o644
	}
	if err := tmp.Chmod(mode); err != nil && !errors.Is(err, os.ErrInvalid) {
		return 0, fmt.Errorf("setting permissions on %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return 0, fmt.Errorf("closing %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, entry.destination); err != nil {
		return 0, fmt.Errorf("renaming %s into place: %w", tmpPath, err)
	}
	committed = true
	return written, nil
}

// modifiedTime reads an entry's modification time, returning the zero time
// when the sandbox reported none.
//
// The nil guard is the whole function: an absent timestamp converts to the
// Unix epoch rather than to a zero time, and epoch is *older than everything*
// — so a missing modification time would make every local file look current
// and skip the transfer entirely.
func modifiedTime(metadata *sandboxdv1.FileMetadata) time.Time {
	if metadata.GetModifiedAt() == nil {
		return time.Time{}
	}
	return metadata.GetModifiedAt().AsTime()
}

// unchangedLocal is the pull-side quick check: same size, and the local copy
// is no older than the remote one.
func unchangedLocal(entry transferEntry) bool {
	info, err := os.Stat(entry.destination)
	if err != nil || info.IsDir() {
		return false
	}
	if u64(info.Size()) != entry.size {
		return false
	}
	// A remote entry with no modification time cannot be compared, so it is
	// always re-fetched rather than assumed current.
	return !entry.modified.IsZero() && !info.ModTime().Before(entry.modified)
}

// -------------------------------------------------------- local safety

// localFileDestination resolves a single-file pull destination, applying cp's
// rule that an existing directory receives the file under its own name.
func localFileDestination(destination, remoteSource string, allowOutside bool) (string, error) {
	resolved, err := localWriteTarget(destination, allowOutside)
	if err != nil {
		return "", err
	}
	if info, err := os.Stat(resolved); err == nil && info.IsDir() {
		base := path.Base(strings.ReplaceAll(remoteSource, `\`, "/"))
		return localWriteTarget(filepath.Join(resolved, base), allowOutside)
	}
	return resolved, nil
}

// localEntryDestination places one pulled entry under the destination root,
// refusing a name that would put it anywhere else.
//
// The root is checked once, when the pull is planned. This checks every entry
// against it, because the name each one lands under comes from the sandbox —
// the untrusted side of this system — and two ordinary things turn a name into
// a way out of the tree:
//
//   - A file literally called `..\..\x` is a legal filename on Linux, and the
//     separator normalisation that lets a Windows sandbox's `cmd\app\main.go`
//     mean `cmd/app/main.go` turns that name into a traversal. Anything a
//     sandbox's own workload can create, it can name.
//   - A directory *inside* the destination that is a symlink pointing out of
//     it. The root's own resolution never saw it, and MkdirAll writes straight
//     through it.
//
// Past two levels either one leaves the working directory the pull confinement
// exists to enforce, so the check is the confinement's, applied per entry
// rather than only to the root it was composed from.
func localEntryDestination(root, rel string, allowOutside bool) (destination, skipReason string) {
	candidate := filepath.Join(root, filepath.FromSlash(rel))
	inside, err := filepath.Rel(root, candidate)
	if err != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
		return "", fmt.Sprintf("the sandbox names it %q, which does not stay inside the destination directory", rel)
	}
	if _, err := localWriteTarget(candidate, allowOutside); err != nil {
		return "", "it resolves outside this workstation's working directory, which a pull may not write to; a directory in the destination tree is a symlink pointing out of it"
	}
	return candidate, ""
}

// localWriteTarget resolves a local write destination and refuses one outside
// this process's working directory.
//
// The sandbox has an agent deciding what a caller may touch. This side has
// nothing: the MCP server runs as the user, with the user's whole filesystem
// in reach, and "pull /etc/hosts to /etc/hosts" is a single tool call away
// from being a working command. So the destination is confined to the
// directory the client is working in, and stepping outside it is a deliberate
// argument rather than an accident.
//
// Containment is decided on the resolved path — the nearest existing ancestor
// with its symlinks followed, plus whatever does not exist yet — because a
// symlink inside the working directory pointing at / is otherwise a way
// straight out of it.
func localWriteTarget(destination string, allowOutside bool) (string, error) {
	abs, err := filepath.Abs(destination)
	if err != nil {
		return "", fmt.Errorf("destination %s is not a usable local path: %w", destination, err)
	}
	abs = filepath.Clean(abs)
	if allowOutside {
		return abs, nil
	}

	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("this workstation's working directory could not be determined, so no local write can be checked against it: %w", err)
	}
	root := resolveExistingLocal(wd)
	candidate := resolveExistingLocal(abs)

	rel, err := filepath.Rel(root, candidate)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf(
			"destination %s is outside this workstation's working directory %s, and a pull writes to this machine's filesystem, which has no jail. Choose a destination under %s, or set allow_outside_working_dir if writing there is really what you mean",
			abs, wd, wd)
	}
	return abs, nil
}

// resolveExistingLocal follows symlinks as far as the path exists, keeping the
// components that do not yet.
func resolveExistingLocal(p string) string {
	remainder := ""
	current := filepath.Clean(p)
	for {
		if resolved, err := filepath.EvalSymlinks(current); err == nil {
			return filepath.Join(resolved, remainder)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return filepath.Join(current, remainder)
		}
		remainder = filepath.Join(filepath.Base(current), remainder)
		current = parent
	}
}

// resolveLocalSymlink follows a local symlink and decides whether it leaves
// the source tree.
//
// A link that stays inside is followed, because a repository full of them
// would otherwise transfer as a tree of holes. One that leaves is skipped and
// named — never silently followed, which is how "push my project" quietly
// becomes "push my home directory".
func resolveLocalSymlink(root, link string) (resolved, skipReason string) {
	target, err := filepath.EvalSymlinks(link)
	if err != nil {
		return "", "dangling symlink, or one this workstation could not resolve"
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		realRoot = root
	}
	rel, err := filepath.Rel(realRoot, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "symlink to " + target + ", which is outside the source tree"
	}
	return target, ""
}

// ---------------------------------------------------------------- shared

// checkCaps refuses a transfer that is too large, naming the limit that would
// stop it.
func checkCaps(files int, bytes uint64) error {
	if files > MaxTransferFiles {
		return fmt.Errorf("the transfer covers more than %d files, which is the limit for one call; narrow it with exclude or transfer a subdirectory",
			MaxTransferFiles)
	}
	if bytes > MaxTransferBytes {
		return fmt.Errorf("the transfer covers %s, over the %s limit for one call; narrow it with exclude or transfer a subdirectory",
			humanBytes(bytes), humanBytes(MaxTransferBytes))
	}
	return nil
}

// excludeMatcher decides which entries a transfer leaves behind.
type excludeMatcher struct {
	patterns []string
}

// newExcludeMatcher combines the caller's patterns with the defaults,
// rejecting a pattern the matcher cannot evaluate rather than treating it as
// one that never matches — a caller who wrote exclude=["build["] believes
// build is excluded.
func newExcludeMatcher(extra []string) (*excludeMatcher, error) {
	patterns := make([]string, 0, len(defaultExcludes)+len(extra))
	patterns = append(patterns, defaultExcludes...)
	for _, pattern := range extra {
		trimmed := strings.TrimSpace(pattern)
		if trimmed == "" {
			continue
		}
		if _, err := path.Match(trimmed, "probe"); err != nil {
			return nil, fmt.Errorf("exclude pattern %q is not a valid glob: %w", pattern, err)
		}
		patterns = append(patterns, trimmed)
	}
	return &excludeMatcher{patterns: patterns}, nil
}

// matches reports whether an entry is excluded. A pattern is tried against the
// whole relative path, against the entry's own name, and against every path
// segment — so "node_modules" excludes it at any depth and "src/*.tmp"
// excludes only there.
func (m *excludeMatcher) matches(rel, name string) bool {
	segments := strings.Split(rel, "/")
	for _, pattern := range m.patterns {
		if ok, _ := path.Match(pattern, rel); ok {
			return true
		}
		if ok, _ := path.Match(pattern, name); ok {
			return true
		}
		if strings.Contains(pattern, "/") {
			continue
		}
		for _, segment := range segments {
			if ok, _ := path.Match(pattern, segment); ok {
				return true
			}
		}
	}
	return false
}

// relSlash renders a path relative to root in slash form, which is the one
// spelling both sides of a transfer can agree on.
func relSlash(root, p string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return filepath.ToSlash(p)
	}
	return filepath.ToSlash(rel)
}

// plural renders a count with the right form of its noun. It is a small thing,
// and these notes are read by a model that has to decide what to do next —
// "1 entr(ies)" is a sentence written by a program, and reads like one.
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
