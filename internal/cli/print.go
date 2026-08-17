// Package cli holds the output plumbing shared by the fleet binaries.
package cli

import (
	"fmt"
	"io"
)

// Printer writes command output, remembering the first write error.
//
// Commands print several lines in sequence, and checking every one inline
// would bury the logic. Recording the first failure and reporting it once, at
// the end, means a command whose output went nowhere — a closed pipe, a full
// disk — exits non-zero instead of silently claiming success.
type Printer struct {
	w   io.Writer
	err error
}

// NewPrinter returns a Printer writing to w.
func NewPrinter(w io.Writer) *Printer { return &Printer{w: w} }

// Printf writes a formatted line.
func (p *Printer) Printf(format string, args ...any) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintf(p.w, format, args...)
}

// Println writes a line.
func (p *Printer) Println(args ...any) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintln(p.w, args...)
}

// write emits raw bytes, for output that is a file's contents rather than a
// formatted line.
func (p *Printer) Write(b []byte) {
	if p.err != nil {
		return
	}
	_, p.err = p.w.Write(b)
}

// Err returns the first write error, if any.
func (p *Printer) Err() error { return p.err }
