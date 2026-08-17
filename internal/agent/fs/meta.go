package fs

import (
	"io"
	"io/fs"
	"os"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/timestamppb"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
)

// sniffBytes is how much of a file's head decides whether it is text. It is the
// same 8 KiB git uses, and the same the issue specifies: enough to catch a
// binary whose first bytes happen to be printable, cheap enough to do on every
// read.
const sniffBytes = 8 * 1024

// metadataFor builds a FileMetadata from an already-resolved path and its
// FileInfo.
//
// info must come from Lstat when the caller cares whether the path itself is a
// symlink — this function reports what it is given and follows nothing.
func metadataFor(path string, info fs.FileInfo) *sandboxdv1.FileMetadata {
	md := &sandboxdv1.FileMetadata{
		Path:       path,
		SizeBytes:  u64(info.Size()),
		Mode:       uint32(info.Mode().Perm()),
		ModifiedAt: timestamppb.New(info.ModTime().UTC()),
		IsDir:      info.IsDir(),
		IsSymlink:  info.Mode()&fs.ModeSymlink != 0,
	}
	if md.GetIsSymlink() {
		// Reported best-effort: a link whose target cannot be read is still a
		// link, and saying so with an empty target beats failing the listing.
		if target, err := os.Readlink(path); err == nil {
			md.SymlinkTarget = target
		}
	}
	return md
}

// sniffBinary reads the head of an open file and reports whether it looks
// binary, leaving the file positioned where it found it.
//
// Two signals, both from the first 8 KiB: a NUL byte, which no text encoding
// this agent serves produces, and invalid UTF-8. Either one means returning the
// file as text would hand the caller mangled content, which is worse than
// refusing: a model that is told a file is 4 KB of replacement characters draws
// conclusions from the replacement characters.
func sniffBinary(r io.ReaderAt) (bool, error) {
	buf := make([]byte, sniffBytes)
	n, err := r.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return false, err
	}
	return looksBinary(buf[:n]), nil
}

// looksBinary applies the sniffing rules to a head of a file.
func looksBinary(head []byte) bool {
	for _, b := range head {
		if b == 0 {
			return true
		}
	}
	// A multi-byte rune straddling the end of the window is not invalid UTF-8,
	// it is a window that ended mid-rune. Trimming the partial tail is what
	// keeps an 8 KiB boundary landing inside a CJK character from reporting a
	// perfectly good UTF-8 file as binary.
	return !utf8.Valid(trimPartialRune(head))
}

// trimPartialRune drops a trailing incomplete UTF-8 sequence.
func trimPartialRune(b []byte) []byte {
	if len(b) < sniffBytes {
		// The read reached EOF, so nothing was cut off: a partial rune here is
		// a genuinely truncated file, which is not valid UTF-8 and should be
		// reported as such.
		return b
	}
	// A rune is at most 4 bytes, so at most 3 trailing bytes can be a partial
	// one.
	for i := len(b) - 1; i >= 0 && i > len(b)-4; i-- {
		if utf8.RuneStart(b[i]) {
			if r, size := utf8.DecodeRune(b[i:]); r == utf8.RuneError && size <= 1 {
				return b[:i]
			}
			return b
		}
	}
	return b
}
