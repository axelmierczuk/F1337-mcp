package fs

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

// maxContextLines bounds context_lines. Context is buffered per match, so an
// unbounded request is an unbounded allocation.
const maxContextLines = 20

// Grep searches a tree and streams matches as it finds them.
//
// It runs here rather than being composed from ListDirectory and ReadFile
// because the alternative is streaming a tree across the network to search it
// on the other side. Two properties follow from that, and both are contractual:
//
//   - Matches are sent as they are found. The first match reaches the caller
//     while the walk is still going, so a search over a large tree is useful
//     before it is finished.
//   - max_matches stops the walk. It is a bound on work, not a filter applied
//     to a finished search: the summary's files_searched reports how few files
//     were opened, and on a large tree that number is the difference between a
//     search that costs milliseconds and one that costs the whole disk.
//
// Binary files are skipped rather than matched, since a regex over compiled
// code produces matches that mean nothing and lines that render as noise.
// One implementation, no ripgrep: shelling out to a binary that is on some
// fleet hosts and not others gives two different search semantics behind one
// tool name, and the caller cannot tell which one answered.
func (s *Service) Grep(req *sandboxdv1.GrepRequest, stream grpc.ServerStreamingServer[sandboxdv1.GrepResponse]) error {
	ctx := stream.Context()

	expr := req.GetPattern()
	if strings.TrimSpace(expr) == "" {
		return status.Error(codes.InvalidArgument, "pattern is required")
	}
	if req.GetCaseInsensitive() {
		expr = "(?i)" + expr
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return status.Errorf(codes.InvalidArgument,
			"pattern %q is not a valid RE2 expression: %v", req.GetPattern(), err)
	}

	include, err := compileIncludeGlob(req.GetIncludeGlob())
	if err != nil {
		return status.Errorf(codes.InvalidArgument,
			"include_glob %q is not a valid glob: %v", req.GetIncludeGlob(), errors.Unwrap(err))
	}

	root, err := s.resolveRoot(req.GetRoot())
	if err != nil {
		return err
	}

	maxMatches := uint64(req.GetMaxMatches())
	if maxMatches == 0 {
		maxMatches = s.limits.DefaultGrepMatches
	}
	contextLines := int(min(req.GetContextLines(), maxContextLines))

	search := &grepSearch{
		svc:          s,
		stream:       stream,
		re:           re,
		include:      include,
		filesOnly:    req.GetFilesOnly(),
		contextLines: contextLines,
		maxMatches:   maxMatches,
	}

	walkErr := s.walkTree(ctx, walkOptions{
		root:                  root,
		respectGitignore:      req.GetRespectGitignore(),
		includeDefaultIgnored: req.GetIncludeDefaultIgnored(),
	}, search.visit)
	if walkErr != nil {
		return walkErr
	}
	if err := ctxErr(ctx); err != nil {
		return err
	}

	return stream.Send(&sandboxdv1.GrepResponse{
		Event: &sandboxdv1.GrepResponse_Summary{Summary: &sandboxdv1.GrepSummary{
			FilesSearched: search.filesSearched,
			MatchesFound:  search.matchesFound,
			Truncation:    truncation(search.capped, 0, 0),
		}},
	})
}

// grepSearch is one Grep call's state.
type grepSearch struct {
	svc          *Service
	stream       grpc.ServerStreamingServer[sandboxdv1.GrepResponse]
	re           *regexp.Regexp
	include      *pattern
	filesOnly    bool
	contextLines int
	maxMatches   uint64

	filesSearched uint64
	matchesFound  uint64
	capped        bool
}

// visit searches one file, and reports whether the walk should continue.
func (g *grepSearch) visit(path, rel string, _ fs.DirEntry) (bool, error) {
	if g.include != nil && !g.include.match(rel) {
		return true, nil
	}

	file, err := g.svc.jail.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		// A file that cannot be opened is a hole in the results, not a failed
		// search.
		return true, nil
	}
	defer func() { _ = file.Close() }()

	binary, err := sniffBinary(file)
	if err != nil || binary {
		return true, nil
	}
	g.filesSearched++

	if err := g.scan(path, file); err != nil {
		return false, err
	}
	return !g.capped, nil
}

// scan reads one file, sending matches as it goes.
func (g *grepSearch) scan(path string, file *os.File) error {
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), g.svc.limits.MaxGrepLineBytes)

	var (
		lineNum  uint64
		before   []string
		pending  []*sandboxdv1.GrepMatch
		stopping bool
	)

	for scanner.Scan() {
		lineNum++
		// Scanner strips the "\n"; the "\r" of a CRLF file is stripped here so
		// matches render as lines rather than as lines with a control character
		// on the end. Nothing is written back, so the file's endings are
		// untouched.
		//
		// The line is also made valid UTF-8, because GrepMatch.line is a proto3
		// string and marshalling one that is not fails the whole stream. The
		// binary sniff only looks at the first 8 KiB, so an ordinary log with one
		// stray byte a megabyte in passes it and then breaks the search — an
		// error about encoding, for a search that had already found its match.
		line := toValidUTF8(strings.TrimSuffix(scanner.Text(), "\r"))

		for _, m := range pending {
			if len(m.GetAfterContext()) < g.contextLines {
				m.AfterContext = append(m.AfterContext, line)
			}
		}
		var err error
		if pending, err = g.flushComplete(pending); err != nil {
			return err
		}

		if !stopping && g.re.MatchString(line) {
			if g.filesOnly {
				g.matchesFound++
				if err := g.send(&sandboxdv1.GrepMatch{Path: path}); err != nil {
					return err
				}
				g.capped = g.matchesFound >= g.maxMatches
				return nil
			}
			g.matchesFound++
			pending = append(pending, &sandboxdv1.GrepMatch{
				Path:          path,
				LineNumber:    lineNum,
				Line:          line,
				BeforeContext: append([]string(nil), before...),
			})
			if g.matchesFound >= g.maxMatches {
				// Keep reading only far enough to finish the context of the
				// matches already found, then stop. The walk stops with it.
				g.capped, stopping = true, true
			}
		}

		if g.contextLines > 0 {
			before = append(before, line)
			if len(before) > g.contextLines {
				before = before[1:]
			}
		}
		if stopping && len(pending) == 0 {
			break
		}
	}

	if err := scanner.Err(); err != nil && !errors.Is(err, bufio.ErrTooLong) {
		// A read error mid-file loses the rest of that file's matches, not the
		// search.
		g.svc.log.Debug("stopped reading a file during grep", "path", path, "error", err)
	}
	return g.flushAll(pending)
}

// flushComplete sends every pending match whose after-context is full.
func (g *grepSearch) flushComplete(pending []*sandboxdv1.GrepMatch) ([]*sandboxdv1.GrepMatch, error) {
	for len(pending) > 0 && len(pending[0].GetAfterContext()) >= g.contextLines {
		if err := g.send(pending[0]); err != nil {
			return nil, err
		}
		pending = pending[1:]
	}
	return pending, nil
}

// flushAll sends whatever is left, with however much context it collected: at
// the end of a file there are no more lines to wait for.
func (g *grepSearch) flushAll(pending []*sandboxdv1.GrepMatch) error {
	for _, m := range pending {
		if err := g.send(m); err != nil {
			return err
		}
	}
	return nil
}

// toValidUTF8 replaces invalid byte sequences with U+FFFD, which is what a
// terminal shows for them and what keeps a line usable rather than unsendable.
//
// Substituting rather than skipping the file is deliberate: a file whose head is
// text is a text file, the match and its line number are real, and dropping the
// whole file over a byte the caller cannot see would be a silent hole in the
// results. A file that is binary from the start never reaches here — the sniff
// already skipped it.
func toValidUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "�")
}

func (g *grepSearch) send(m *sandboxdv1.GrepMatch) error {
	if err := ctxErr(g.stream.Context()); err != nil {
		return err
	}
	return g.stream.Send(&sandboxdv1.GrepResponse{
		Event: &sandboxdv1.GrepResponse_Match{Match: m},
	})
}
