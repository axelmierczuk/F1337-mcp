package fs

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

// EditFile replaces an exact string in a file.
//
// The contract is deliberately the one the agent's built-in edit tool has,
// because a model that already knows that tool must not have to learn a second
// set of rules to use this one:
//
//   - The match is exact. Whitespace and indentation are significant, and
//     nothing is normalised on either side.
//   - Without replace_all the edit fails unless old_string occurs exactly once.
//     An ambiguous match is the failure mode this rule exists to prevent: with
//     two candidates, a replacement picks one, and the caller finds out which
//     by reading the diff afterwards. The error names the count so the caller
//     knows to add surrounding context rather than guess.
//   - old_string == new_string is an error. A no-op that reports success is a
//     caller believing it changed something.
//
// Every failure leaves the file exactly as it was. The replacement is computed
// in memory and committed through the same sibling-temp-file-and-rename path as
// WriteFile, so there is no window in which a rejected edit has partly
// happened.
//
// Line endings survive. The replacement is a byte-exact substring swap, so the
// terminators outside it are untouched, and a new_string whose endings disagree
// with the file's is refused rather than mixed in — see checkNewLineEndings.
func (s *Service) EditFile(ctx context.Context, req *sandboxdv1.EditFileRequest) (*sandboxdv1.EditFileResponse, error) {
	oldStr, newStr := req.GetOldString(), req.GetNewString()
	if oldStr == "" {
		return nil, status.Error(codes.InvalidArgument, "old_string is required; an empty string matches at every position")
	}
	if oldStr == newStr {
		return nil, status.Error(codes.InvalidArgument, "old_string and new_string are identical, so this edit would change nothing")
	}

	resolved, err := s.resolve(req.GetPath())
	if err != nil {
		return nil, err
	}
	// The file the commit lands on. Without this an edit through a symlink on an
	// unconfined agent reads the target and writes a new regular file over the
	// link — the change lands in a file nobody asked for and the file that was
	// edited keeps its old contents.
	resolved, err = s.writeTarget(resolved)
	if err != nil {
		return nil, err
	}

	release, err := s.locks.lock(ctx, resolved)
	if err != nil {
		return nil, status.FromContextError(err).Err()
	}
	defer release()

	content, mode, err := s.loadForEdit(resolved)
	if err != nil {
		return nil, err
	}

	count := strings.Count(content, oldStr)
	switch {
	case count == 0:
		return nil, s.noMatchError(resolved, content, oldStr)
	case count > 1 && !req.GetReplaceAll():
		return nil, status.Errorf(codes.FailedPrecondition,
			"old_string occurs %d times in %s (lines %s), and without replace_all an edit must match exactly once; add surrounding context to identify the one you mean, or set replace_all",
			count, resolved, strings.Join(occurrenceLines(content, oldStr, 5), ", "))
	}
	if err := checkNewLineEndings(resolved, content, newStr); err != nil {
		return nil, err
	}

	updated, occs := replaceOccurrences(content, oldStr, newStr, req.GetReplaceAll())
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	if err := s.writeWhole(resolved, []byte(updated), mode); err != nil {
		return nil, err
	}

	return &sandboxdv1.EditFileResponse{
		Path:         resolved,
		Replacements: uint32(len(occs)), //nolint:gosec // one occurrence per match in a file bounded by MaxEditBytes
		Diff:         unifiedDiff(resolved, []byte(content), []byte(updated), occs),
	}, nil
}

// loadForEdit reads the whole file and returns it with the mode to preserve.
//
// Whole, because an exact-match replacement has no streaming form: the match
// may straddle any boundary. That is why there is a size ceiling here and
// nowhere else in this package.
func (s *Service) loadForEdit(resolved string) (content string, mode os.FileMode, err error) {
	if err := refuseIrregular(resolved); err != nil {
		return "", 0, err
	}
	file, err := s.jail.OpenFile(resolved, os.O_RDONLY, 0)
	if err != nil {
		return "", 0, s.pathError(resolved, err)
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return "", 0, fileError(resolved, err)
	}
	if info.IsDir() {
		return "", 0, status.Errorf(codes.InvalidArgument, "%s is a directory", resolved)
	}
	if info.Size() > s.limits.MaxEditBytes {
		return "", 0, status.Errorf(codes.InvalidArgument,
			"%s is %d bytes, over the %d-byte limit for an edit; an exact-match replacement has to hold the whole file, so a file this size has to be rewritten with WriteFile instead",
			resolved, info.Size(), s.limits.MaxEditBytes)
	}

	data, err := io.ReadAll(io.LimitReader(file, s.limits.MaxEditBytes+1))
	if err != nil {
		return "", 0, fileError(resolved, err)
	}
	if int64(len(data)) > s.limits.MaxEditBytes {
		return "", 0, status.Errorf(codes.InvalidArgument,
			"%s grew past the %d-byte edit limit while being read", resolved, s.limits.MaxEditBytes)
	}
	if !utf8.Valid(data) {
		return "", 0, status.Errorf(codes.FailedPrecondition,
			"%s is not valid UTF-8, so an exact string match on it is not meaningful; the agent refuses to edit it rather than corrupt it", resolved)
	}
	return string(data), info.Mode().Perm(), nil
}

// writeWhole commits new contents through the same atomic path WriteFile uses.
func (s *Service) writeWhole(resolved string, data []byte, mode os.FileMode) error {
	tmp, err := createAtomic(s.jail, s.log, resolved, mode)
	if err != nil {
		return fileError(resolved, err)
	}
	defer func() { _ = tmp.Close() }()

	if _, err := tmp.Write(data); err != nil {
		return fileError(resolved, err)
	}
	if err := tmp.Commit(); err != nil {
		return fileError(resolved, err)
	}
	return nil
}

// replaceOccurrences performs the replacement and records where each one
// landed, so the diff can be exact rather than inferred.
func replaceOccurrences(content, oldStr, newStr string, all bool) (string, []occurrence) {
	var (
		out  strings.Builder
		occs []occurrence
		last int
	)
	out.Grow(len(content))
	for i := 0; ; {
		j := strings.Index(content[i:], oldStr)
		if j < 0 {
			break
		}
		at := i + j
		out.WriteString(content[last:at])
		newStart := out.Len()
		out.WriteString(newStr)
		occs = append(occs, occurrence{
			oldStart: at,
			oldEnd:   at + len(oldStr),
			newStart: newStart,
			newEnd:   out.Len(),
		})
		last = at + len(oldStr)
		i = last
		if !all {
			break
		}
	}
	out.WriteString(content[last:])
	return out.String(), occs
}

// noMatchError explains a failed match, because "not found" on an exact-match
// tool is the least actionable error there is.
//
// The two causes worth naming are the two that actually happen: line endings,
// where a caller composed old_string with LF against a file checked out with
// CRLF, and whitespace, where indentation was retyped rather than copied.
func (s *Service) noMatchError(path, content, oldStr string) error {
	if converted, ok := lineEndingMismatch(content, oldStr); ok {
		return status.Errorf(codes.FailedPrecondition,
			"old_string does not appear in %s, but it does once its line endings are converted to %s, which is what the file uses; resend old_string with the file's line endings",
			path, converted)
	}
	if line, ok := whitespaceNearMiss(content, oldStr); ok {
		return status.Errorf(codes.FailedPrecondition,
			"old_string does not appear in %s, but line %d differs from it only in whitespace; the match is exact, so indentation and trailing spaces have to be copied from the file rather than retyped",
			path, line)
	}
	return status.Errorf(codes.FailedPrecondition,
		"old_string does not appear in %s (%d lines, %d bytes); the first line looked for was %q",
		path, strings.Count(content, "\n")+1, len(content), firstLine(oldStr))
}

// lineEndingMismatch reports whether old_string would match if its line endings
// were converted, and to what.
func lineEndingMismatch(content, oldStr string) (string, bool) {
	if !strings.Contains(oldStr, "\n") {
		return "", false
	}
	if strings.Contains(content, toCRLF(oldStr)) {
		return "CRLF", true
	}
	if strings.Contains(content, toLF(oldStr)) {
		return "LF", true
	}
	return "", false
}

// checkNewLineEndings refuses a new_string whose line endings disagree with the
// file's.
//
// Writing it anyway would leave a file with mixed endings — a diff that touches
// every line for whoever commits it next, and on Windows a file some tools
// refuse. The agent's job is to not silently rewrite line endings, and quietly
// inserting the wrong ones is the same defect as quietly converting the rest.
func checkNewLineEndings(path, content, newStr string) error {
	if !strings.Contains(newStr, "\n") {
		return nil
	}
	crlf, lf := countLineEndings(content)
	newCRLF, newLF := countLineEndings(newStr)

	switch {
	case crlf > 0 && lf == 0 && newLF > 0:
		return status.Errorf(codes.InvalidArgument,
			"%s uses CRLF line endings but new_string contains %d bare LF; the agent will not mix line endings into a file, so send new_string with CRLF",
			path, newLF)
	case lf > 0 && crlf == 0 && newCRLF > 0:
		return status.Errorf(codes.InvalidArgument,
			"%s uses LF line endings but new_string contains %d CRLF; the agent will not mix line endings into a file, so send new_string with LF",
			path, newCRLF)
	}
	return nil
}

// countLineEndings counts CRLF terminators and bare LF terminators.
func countLineEndings(s string) (crlf, lf int) {
	for i := 0; i < len(s); i++ {
		if s[i] != '\n' {
			continue
		}
		if i > 0 && s[i-1] == '\r' {
			crlf++
			continue
		}
		lf++
	}
	return crlf, lf
}

func toLF(s string) string   { return strings.ReplaceAll(s, "\r\n", "\n") }
func toCRLF(s string) string { return strings.ReplaceAll(toLF(s), "\n", "\r\n") }

// whitespaceNearMiss reports the first line whose content matches old_string
// once horizontal whitespace is normalised away.
func whitespaceNearMiss(content, oldStr string) (int, bool) {
	normalizedOld := normalizeWhitespace(oldStr)
	if normalizedOld == "" {
		return 0, false
	}
	normalized := normalizeWhitespace(content)
	idx := strings.Index(normalized, normalizedOld)
	if idx < 0 {
		return 0, false
	}
	// Normalisation preserves newlines, so line numbers map across unchanged.
	return strings.Count(normalized[:idx], "\n") + 1, true
}

// normalizeWhitespace trims each line and collapses runs of spaces and tabs,
// keeping the line structure so a match maps back to a line number.
func normalizeWhitespace(s string) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	for i, line := range lines {
		lines[i] = strings.Join(strings.Fields(line), " ")
	}
	return strings.Join(lines, "\n")
}

// occurrenceLines returns the line numbers of the first few matches, as
// strings, so an ambiguity error can point at them.
func occurrenceLines(content, oldStr string, limit int) []string {
	var out []string
	for i := 0; len(out) < limit; {
		j := strings.Index(content[i:], oldStr)
		if j < 0 {
			break
		}
		at := i + j
		out = append(out, fmt.Sprintf("%d", strings.Count(content[:at], "\n")+1))
		i = at + len(oldStr)
	}
	return out
}

// firstLine returns the first line of s, shortened, for an error message.
func firstLine(s string) string {
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		s = s[:idx]
	}
	s = strings.TrimRight(s, "\r")
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}
