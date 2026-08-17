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
		changedOld := oldContent[oldLines[g.firstLine].start:oldLines[g.lastLine].end]
		changedNew := newContent[oldLines[g.firstLine].start+g.driftBefore : oldLines[g.lastLine].end+g.driftAfter]
		removed := renderLines(changedOld)
		added := renderLines(changedNew)

		before := renderLines(oldContent[oldLines[firstLine].start:oldLines[g.firstLine].start])
		var after []string
		if lastLine >= g.lastLine+1 {
			after = renderLines(oldContent[oldLines[g.lastLine].end:oldLines[lastLine].end])
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

// changeGroup is a run of occurrences close enough to share one hunk.
type changeGroup struct {
	firstLine, lastLine     int
	driftBefore, driftAfter int
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
			firstLine:   first,
			lastLine:    last,
			driftBefore: driftBefore,
			driftAfter:  driftAfter,
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
// the diff format supplies itself.
//
// The carriage return of a CRLF file goes with the terminator. It is stripped
// from the display only; nothing here touches the file, and the edit itself
// preserves whatever endings the file had.
func renderLines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	out := make([]string, 0, 8)
	for _, s := range lineSpans(b) {
		out = append(out, strings.TrimRight(string(b[s.start:s.end]), "\r\n"))
	}
	return out
}
