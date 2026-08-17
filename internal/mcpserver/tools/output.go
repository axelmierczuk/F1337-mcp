package tools

import (
	"bytes"
	"fmt"
	"strings"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
)

// Truncation reports output that was cut short, and by how much.
//
// It is present on every result that could be capped, and absent only when
// nothing was. That asymmetry is the point: a model shown a partial result
// that looks complete draws confident, wrong conclusions from it — "the test
// suite passes" from a log whose failures were the bytes that got dropped.
// Note says which cap bit and which argument raises it, so the model can act
// rather than guess.
type Truncation struct {
	// Truncated is always true when this field is present.
	Truncated bool `json:"truncated" jsonschema:"true when output was cut short"`
	// BytesOmitted is how much content was dropped, when it is known.
	BytesOmitted uint64 `json:"bytes_omitted,omitempty" jsonschema:"bytes dropped, when the cap could count them"`
	// LinesOmitted is how many lines were dropped, when it is known.
	LinesOmitted uint64 `json:"lines_omitted,omitempty" jsonschema:"lines dropped, when the cap could count them"`
	// Note names the cap that bit and the argument that raises it.
	Note string `json:"note,omitempty" jsonschema:"which limit was hit and how to ask for more"`
}

// truncationFrom renders an agent-side Truncation, returning nil when nothing
// was cut. A nil result is what keeps an untruncated response from carrying a
// field whose only content is "false".
func truncationFrom(t *sandboxdv1.Truncation, note string) *Truncation {
	if !t.GetTruncated() {
		return nil
	}
	return &Truncation{
		Truncated:    true,
		BytesOmitted: t.GetBytesOmitted(),
		LinesOmitted: t.GetLinesOmitted(),
		Note:         note,
	}
}

// merge folds another truncation into this one, summing what each dropped.
//
// Two caps can bite on one call — the agent's own and this server's — and
// reporting only the one that happened to be checked last would understate
// how much is missing.
func (t *Truncation) merge(other *Truncation) *Truncation {
	switch {
	case other == nil:
		return t
	case t == nil:
		return other
	}
	t.BytesOmitted += other.BytesOmitted
	t.LinesOmitted += other.LinesOmitted
	if other.Note != "" && !strings.Contains(t.Note, other.Note) {
		t.Note = strings.TrimSpace(t.Note + " " + other.Note)
	}
	return t
}

// boundedBuffer accumulates up to a limit and counts everything past it.
//
// Writes never fail and never short-write. That is deliberate and it is the
// constraint the exec stream imposes: a consumer that stops reading stalls the
// agent's Send, and the agent then kills the command and ends the call with
// Aborted — losing the result of a command that already ran. So this keeps
// draining after the cap and counts what it drops, which is also what makes
// "megabytes of output does not blow up the MCP server" true of a sandbox that
// ignores the cap it was given.
type boundedBuffer struct {
	limit int
	buf   bytes.Buffer

	omittedBytes uint64
	omittedLines uint64
}

func newBoundedBuffer(limit int) *boundedBuffer {
	if limit < 0 {
		limit = 0
	}
	return &boundedBuffer{limit: limit}
}

// Write stores what still fits and counts the rest. It always reports the full
// write as accepted.
func (b *boundedBuffer) Write(p []byte) (int, error) {
	room := b.limit - b.buf.Len()
	if room > 0 {
		if room > len(p) {
			room = len(p)
		}
		b.buf.Write(p[:room])
	} else {
		room = 0
	}
	dropped := p[room:]
	b.omittedBytes += u64(len(dropped))
	b.omittedLines += u64(bytes.Count(dropped, []byte{'\n'}))
	return len(p), nil
}

// String returns what was kept.
func (b *boundedBuffer) String() string { return b.buf.String() }

// Bytes returns what was kept, without copying it into a string first.
func (b *boundedBuffer) Bytes() []byte { return b.buf.Bytes() }

// Len returns how much was kept.
func (b *boundedBuffer) Len() int { return b.buf.Len() }

// truncated reports whether anything was dropped.
func (b *boundedBuffer) truncated() bool { return b.omittedBytes > 0 }

// truncation renders what this buffer dropped, or nil if it dropped nothing.
func (b *boundedBuffer) truncation(note string) *Truncation {
	if !b.truncated() {
		return nil
	}
	return &Truncation{
		Truncated:    true,
		BytesOmitted: b.omittedBytes,
		LinesOmitted: b.omittedLines,
		Note:         note,
	}
}

// notes collects the sentences a result appends to its note field, in the
// order they were added and with no duplicates.
//
// A note is the one place a tool can say something the schema has no field
// for — that the command produced nothing at all, that a default limit
// applied, that the line endings on disk are not the ones rendered here. It is
// joined into a single string rather than a list because it is prose the model
// reads, not data it indexes.
type notes []string

func (n *notes) add(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if msg == "" {
		return
	}
	for _, existing := range *n {
		if existing == msg {
			return
		}
	}
	*n = append(*n, msg)
}

func (n notes) String() string { return strings.Join(n, " ") }

// u64 converts a non-negative size or count to the unsigned form the wire and
// these results use, yielding zero rather than a number near 2^64 for a
// negative that should be impossible.
func u64[T int | int64](n T) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

// clip bounds one line of rendered output, cutting on a rune boundary.
//
// A single line of a minified bundle or a packed data file is megabytes long,
// and one of them in a grep result is the whole result. The cut is marked, so
// a model never reads a clipped line as a whole one.
func clip(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// isRuneStart reports whether b begins a UTF-8 encoded rune.
func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// relativeTo renders path relative to root, for a listing that already names
// the root once.
//
// It compares on both separators because the sandbox may be a Windows host
// answering a Unix workstation, and the path in the response is spelled the
// remote way. A path that is not under root is returned unchanged rather than
// mangled into a relative form it does not have.
func relativeTo(root, path string) string {
	if root == "" || path == "" {
		return path
	}
	trimmed := strings.TrimRight(root, `/\`)
	if !strings.HasPrefix(path, trimmed) {
		return path
	}
	rest := path[len(trimmed):]
	if rest == "" {
		return path
	}
	if rest[0] != '/' && rest[0] != '\\' {
		return path
	}
	return rest[1:]
}
