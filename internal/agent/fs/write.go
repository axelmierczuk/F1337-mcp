package fs

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

// DefaultFileMode is applied to a file this service creates when the caller
// names no mode. It is the umask-independent equivalent of what a shell
// redirect produces.
const DefaultFileMode fs.FileMode = 0o644

// DefaultDirMode is applied to directories created by create_parents.
const DefaultDirMode fs.FileMode = 0o755

// WriteFile receives a header and then content, and renames the result over the
// target.
//
// Nothing is visible at the target path until the last byte has been received
// and fsynced. A stream that dies halfway — a cancelled RPC, a killed client, a
// disk that fills — removes the temp file and leaves the original exactly as it
// was. That is the guarantee the sibling temp file and the rename buy, and it
// is why this is a client stream rather than a request with a bytes field.
//
// The whole call holds the path's lock, so a write and an edit racing on one
// file serialise rather than losing each other's work. Two writers to different
// paths never meet.
func (s *Service) WriteFile(stream grpc.ClientStreamingServer[sandboxdv1.WriteFileRequest, sandboxdv1.WriteFileResponse]) error {
	ctx := stream.Context()

	first, err := stream.Recv()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return status.Error(codes.InvalidArgument, "the stream closed before sending a header")
		}
		return err
	}
	header := first.GetHeader()
	if header == nil {
		return status.Error(codes.InvalidArgument, "the first message on a WriteFile stream must be a header")
	}

	resolved, err := s.resolve(header.GetPath())
	if err != nil {
		return err
	}
	// The file the commit lands on, which is not the name when the name is a
	// symlink. Taken before the lock, so a write through a link and a write to
	// the file it names take the same lock rather than passing each other.
	resolved, err = s.writeTarget(resolved)
	if err != nil {
		return err
	}

	release, err := s.locks.lock(ctx, resolved)
	if err != nil {
		return status.FromContextError(err).Err()
	}
	defer release()

	if header.GetCreateParents() {
		if err := os.MkdirAll(filepath.Dir(resolved), DefaultDirMode); err != nil {
			return fileError(filepath.Dir(resolved), err)
		}
	}

	// Lstat, not Stat: a broken symlink at the target still means the name is
	// taken, and fail_if_exists is about the name.
	//
	// fail_if_exists is checked here and the commit below does not check again,
	// so in principle the name could be taken between the two. Within this agent
	// it cannot: the path lock above is held across both, so concurrent creates
	// of one path serialise and exactly one of them sees a free name. What
	// remains is a process outside the agent creating the file in that window,
	// which no rename-based atomic write can exclude — the commit is a rename,
	// and rename replaces silently by definition.
	existing, statErr := os.Lstat(resolved)
	switch {
	case statErr == nil && existing.IsDir():
		return status.Errorf(codes.InvalidArgument, "%s is a directory", resolved)
	case statErr == nil && !existing.Mode().IsRegular() && existing.Mode()&fs.ModeSymlink == 0:
		// A device, a socket or a named pipe — a directory was handled above,
		// and a symlink is either already followed by writeTarget or dangling.
		// Committing over one would replace it with a regular file, and
		// appending to one would block in open(2) with no way to time it out.
		return status.Errorf(codes.FailedPrecondition,
			"%s is not a regular file; this agent will not replace a device, a socket or a named pipe with one", resolved)
	case statErr == nil && header.GetFailIfExists():
		return status.Errorf(codes.AlreadyExists, "%s already exists and fail_if_exists was set", resolved)
	case statErr != nil && !errors.Is(statErr, fs.ErrNotExist):
		return fileError(resolved, statErr)
	}
	created := statErr != nil

	// An existing file keeps the mode it has: a caller appending a line to a
	// 0600 secret must not find it 0644 afterwards. Only a file this call
	// creates takes the requested mode.
	//
	// The mode comes from a Stat rather than the Lstat above. writeTarget has
	// already followed a live symlink, but a *dangling* one is left as written,
	// and Lstat on it reports the link's own bits — 0777 on Linux. Those are not
	// a mode to hand a regular file.
	mode := DefaultFileMode
	target, targetErr := os.Stat(resolved)
	switch {
	case !created && targetErr == nil:
		mode = target.Mode().Perm()
	case header.GetMode() != 0:
		mode = fs.FileMode(header.GetMode()).Perm()
	}

	tmp, err := createAtomic(s.jail, s.log, resolved, mode)
	if err != nil {
		return fileError(resolved, err)
	}
	// The cleanup that makes an interrupted write harmless. Close on an
	// uncommitted writer removes the temp file and never touches the target.
	defer func() { _ = tmp.Close() }()

	if header.GetAppend() && !created {
		// Append copies the original into the temp file rather than opening the
		// target with O_APPEND, because an O_APPEND write that dies halfway
		// leaves a partly appended file — the one outcome this RPC promises not
		// to produce. The cost is one copy of the file per append, which is the
		// honest price of the guarantee.
		// The resolved target rather than the requested path: they differ when
		// the name is a symlink, and appending must read the same file the
		// commit will land on.
		if err := s.copyExisting(resolved, tmp); err != nil {
			return err
		}
	}

	var received uint64
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// A cancelled or broken stream: return without committing, and the
			// deferred Close takes the temp file with it.
			return err
		}
		if msg.GetHeader() != nil {
			return status.Error(codes.InvalidArgument, "a WriteFile stream carries exactly one header, as its first message")
		}
		chunk := msg.GetChunk()
		if len(chunk) == 0 {
			continue
		}
		if _, err := tmp.Write(chunk); err != nil {
			return fileError(resolved, err)
		}
		received += u64(len(chunk))
	}

	if err := ctxErr(ctx); err != nil {
		return err
	}
	if err := tmp.Commit(); err != nil {
		return fileError(resolved, err)
	}

	return stream.SendAndClose(&sandboxdv1.WriteFileResponse{
		Path:         resolved,
		BytesWritten: received,
		Created:      created,
	})
}

// copyExisting streams the current contents of path into the temp file, for an
// append.
func (s *Service) copyExisting(path string, dst io.Writer) error {
	src, err := s.jail.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return s.pathError(path, err)
	}
	defer func() { _ = src.Close() }()

	if _, err := io.Copy(dst, src); err != nil {
		return fileError(path, err)
	}
	return nil
}
