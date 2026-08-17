package fs

import (
	"fmt"
	"sort"
	"strings"
)

// diffContextLines is how many unchanged lines surround each change in the diff
// EditFile returns.
//
// Three, not the whole file. The diff goes into a model's context, where a
// hundred unchanged lines are a hundred lines of budget spent confirming
// nothing happened to them.
const diffContextLines = 3

// diffMaxBodyLines caps the diff body. A replace_all across a large file can
// produce hundreds of hunks, and a diff nobody can read is worse than one that
// says how much it left out.
const diffMaxBodyLines = 160

// diffMaxLineBytes caps one rendered diff line.
//
// The line cap above bounds how many lines the diff holds and said nothing about
// how long one of them may be. A hunk is expanded to whole lines on both sides,
// so a file whose "line" is megabytes — minified JavaScript, a packed JSON
// document, a base64 blob — put that line in the diff twice for a six-byte
// replacement: an 8 MiB single-line file produced a 16 MiB diff, and at the
// 16 MiB edit ceiling it exceeds the 32 MiB gRPC message limit outright. The
// edit has already been committed by then, so the caller sees the write fail
// when it did not, and retries an edit that already happened.
//
// The elision is marked rather than silent, so a long line reads as trimmed
// instead of as the file's actual contents.
const diffMaxLineBytes = 512

// occurrence is one replacement, as byte ranges in the old and new contents.
type occurrence struct {
	oldStart, oldEnd int
	newStart, newEnd int
}

// span is one line's byte range, including its terminator.
type span struct{ start, end int }

// unifiedDiff renders the replacements as a unified diff, trimmed to
// diffContextLines of context around each change.
//
// It is exact rather than inferred: the caller knows precisely which byte
// ranges it replaced, so there is no diff algorithm here and no chance of one
// guessing a different alignment than the edit actually made.
func unifiedDiff(path string, oldContent, newContent []byte, occs []occurrence) string {
	if len(occs) == 0 {
		return ""
	}
	sort.Slice(occs, func(i, j int) bool { return occs[i].oldStart < occs[j].oldStart })

	oldLines := lineSpans(oldContent)
	groups := groupOccurrences(occs, oldLines)

	var b strings.Builder
	fmt.Fprintf(&b, "--- %s\n", path)
	fmt.Fprintf(&b, "+++ %s\n", path)

	body := 0
	newLineDrift := 0
	truncated := false

	for _, g := range groups {
		firstLine := max(g.firstLine-diffContextLines, 0)
		lastLine := min(g.lastLine+diffContextLines, len(oldLines)-1)

		// The changed region, expanded to whole lines on both sides. The old
		// side's line boundaries map onto the new side by the byte drift the
		// earlier replacements accumulated, which is exact because everything
		// between the groups is untouched.
		changedStart := oldLines[g.firstLine].start
		changedOld := oldContent[changedStart:oldLines[g.lastLine].end]
		changedNew := newContent[changedStart+g.driftBefore : oldLines[g.lastLine].end+g.driftAfter]
		// Where the first replacement sits inside each rendered block. A line too
		// long to print whole is trimmed around this rather than around its
		// middle, so what the diff keeps is the change itself.
		removed := renderLines(changedOld, g.firstOldStart-changedStart)
		added := renderLines(changedNew, g.firstNewStart-(changedStart+g.driftBefore))

		before := renderLines(oldContent[oldLines[firstLine].start:oldLines[g.firstLine].start], -1)
		var after []string
		if lastLine >= g.lastLine+1 {
			after = renderLines(oldContent[oldLines[g.lastLine].end:oldLines[lastLine].end], -1)
		}

		oldCount := len(before) + len(removed) + len(after)
		newCount := len(before) + len(added) + len(after)
		fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n",
			firstLine+1, oldCount,
			firstLine+1+newLineDrift, newCount)

		for _, line := range before {
			if truncated = writeDiffLine(&b, " ", line, &body); truncated {
				break
			}
		}
		if !truncated {
			for _, line := range removed {
				if truncated = writeDiffLine(&b, "-", line, &body); truncated {
					break
				}
			}
		}
		if !truncated {
			for _, line := range added {
				if truncated = writeDiffLine(&b, "+", line, &body); truncated {
					break
				}
			}
		}
		if !truncated {
			for _, line := range after {
				if truncated = writeDiffLine(&b, " ", line, &body); truncated {
					break
				}
			}
		}

		newLineDrift += len(added) - len(removed)
		if truncated {
			fmt.Fprintf(&b, "... diff trimmed at %d lines\n", diffMaxBodyLines)
			break
		}
	}
	return b.String()
}

// writeDiffLine emits one diff line and reports whether the cap was reached.
func writeDiffLine(b *strings.Builder, prefix, line string, body *int) bool {
	if *body >= diffMaxBodyLines {
		return true
	}
	b.WriteString(prefix)
	b.WriteString(line)
	b.WriteString("\n")
	*body++
	return false
}

// elideLongLine shortens a line that is too long to belong in a diff, keeping a
// window around focus and saying how much came out on each side.
//
// The window is centred on the change rather than on the line, because a diff
// that trims a megabyte line to its first and last few hundred bytes shows the
// caller everything except the thing it did. focus is a byte offset into the
// line, or negative for a line with no change in it — a context line — where the
// beginning is the useful end to keep.
//
// The cuts are made valid UTF-8 afterwards, because slicing at a byte offset can
// land inside a rune, and the diff travels in a proto3 string field: an invalid
// one does not fail to render, it fails to marshal, which turns an over-long
// line into a failed RPC for an edit that already happened.
func elideLongLine(line string, focus int) string {
	if len(line) <= diffMaxLineBytes {
		return line
	}
	half := diffMaxLineBytes / 2
	if focus < 0 {
		focus = half
	}
	start := max(min(focus-half, len(line)-diffMaxLineBytes), 0)
	end := start + diffMaxLineBytes

	var b strings.Builder
	if start > 0 {
		fmt.Fprintf(&b, "…%d bytes elided… ", start)
	}
	b.WriteString(strings.ToValidUTF8(line[start:end], ""))
	if end < len(line) {
		fmt.Fprintf(&b, " …%d bytes elided…", len(line)-end)
	}
	return b.String()
}

// changeGroup is a run of occurrences close enough to share one hunk.
type changeGroup struct {
	firstLine, lastLine     int
	driftBefore, driftAfter int
	// firstOldStart and firstNewStart are where the group's first replacement
	// begins on each side, so an over-long line can be trimmed around the change
	// instead of around its own middle.
	firstOldStart, firstNewStart int
}

// groupOccurrences turns byte ranges into line ranges, merging any that would
// otherwise produce overlapping hunks — including two occurrences on one line,
// which must be one hunk or the second would re-remove a line the first already
// removed.
func groupOccurrences(occs []occurrence, oldLines []span) []changeGroup {
	var groups []changeGroup
	for _, occ := range occs {
		first := lineOfOffset(oldLines, occ.oldStart)
		last := lineOfOffset(oldLines, max(occ.oldEnd-1, occ.oldStart))
		driftBefore := occ.newStart - occ.oldStart
		driftAfter := occ.newEnd - occ.oldEnd

		if n := len(groups); n > 0 {
			// Merge when the hunks, context included, would touch or overlap.
			if first <= groups[n-1].lastLine+2*diffContextLines+1 {
				groups[n-1].lastLine = max(groups[n-1].lastLine, last)
				groups[n-1].driftAfter = driftAfter
				continue
			}
		}
		groups = append(groups, changeGroup{
			firstLine:     first,
			lastLine:      last,
			driftBefore:   driftBefore,
			driftAfter:    driftAfter,
			firstOldStart: occ.oldStart,
			firstNewStart: occ.newStart,
		})
	}
	return groups
}

// lineSpans indexes every line of b, including its terminator. A trailing line
// without a terminator is a line.
func lineSpans(b []byte) []span {
	spans := make([]span, 0, 16)
	start := 0
	for i := 0; i < len(b); i++ {
		if b[i] == '\n' {
			spans = append(spans, span{start: start, end: i + 1})
			start = i + 1
		}
	}
	if start < len(b) {
		spans = append(spans, span{start: start, end: len(b)})
	}
	if len(spans) == 0 {
		spans = append(spans, span{})
	}
	return spans
}

// lineOfOffset returns the index of the line containing off.
func lineOfOffset(spans []span, off int) int {
	i := sort.Search(len(spans), func(i int) bool { return spans[i].end > off })
	if i >= len(spans) {
		return len(spans) - 1
	}
	return i
}

// renderLines splits a byte range into display lines, dropping the terminators
// the diff format supplies itself and trimming any line too long to print.
//
// focus is a byte offset into b marking where the change begins, so the line
// containing it keeps that part rather than its own middle. Pass a negative
// offset for a block with no change in it.
//
// The carriage return of a CRLF file goes with the terminator. It is stripped
// from the display only; nothing here touches the file, and the edit itself
// preserves whatever endings the file had.
func renderLines(b []byte, focus int) []string {
	if len(b) == 0 {
		return nil
	}
	out := make([]string, 0, 8)
	for _, s := range lineSpans(b) {
		line := strings.TrimRight(string(b[s.start:s.end]), "\r\n")
		lineFocus := -1
		if focus >= s.start && focus < s.end {
			lineFocus = focus - s.start
		}
		out = append(out, elideLongLine(line, lineFocus))
	}
	return out
}
