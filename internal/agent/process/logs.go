package process

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	sandboxdv1 "github.com/axelmierczuk/sandboxd-mcp/gen/go/sandboxd/v1"
)

// Following is always bounded. Always.
//
// A tool call that never returns is indistinguishable from a hung agent, and
// the model on the other end has no way to recover from it — it does not retry,
// it stops. So every path out of a follow has a deadline on it, including the
// ones that look like they cannot block: a process producing no output at all
// still gets its summary at the deadline, with follow_deadline_reached set.
//
// follow_duration is clamped to the agent's configured maximum rather than
// honoured. A caller asking for an hour gets max_follow_duration and a summary
// saying the deadline was reached — a bounded answer they can act on, rather
// than an unbounded wait they cannot.

// clampFollow resolves a requested follow duration against the agent's maximum.
// Zero means "as long as you allow", which is the maximum, not forever.
func (s *Supervisor) clampFollow(requested time.Duration) time.Duration {
	maxFollow := s.cfg.maxFollowDuration
	if maxFollow <= 0 {
		maxFollow = time.Minute
	}
	if requested <= 0 || requested > maxFollow {
		return maxFollow
	}
	return requested
}

// replay assembles the buffered output a GetProcessLogs call starts with.
//
// snap is the ring's contents, taken atomically with the follower's
// subscription, so nothing appended between the two is missed or duplicated.
//
// dropped is the retention shortfall: how many lines inside the window the
// caller asked for no longer exist anywhere the agent can read them. It is
// counted on the sequence axis, before filtering, because that is the axis on
// which lines are actually lost — a filter excluding a line is not a gap in the
// log, and reporting it as one would make every filtered read look like data
// loss.
func (r *record) replay(sel selector, snap []logLine) (lines []logLine, dropped uint64) {
	_, _, produced := r.buf.stats()
	oldestRing, haveRing := r.buf.oldestRetainedSeq()

	candidates := snap
	oldestAvailable := produced
	if haveRing {
		oldestAvailable = oldestRing
	}

	// The ring is the fast path and covers almost every call. The on-disk
	// history is read only when the ring cannot cover the request — which is
	// the whole reason a size-capped rotating file exists: a crash twenty
	// minutes ago is still diagnosable after the ring has turned over.
	if oldestAvailable > 0 && countMatching(candidates, sel) < sel.tail {
		if disk, err := readSegments(r.buf.segments(), 0); err == nil && len(disk) > 0 {
			older := make([]logLine, 0, len(disk))
			for _, line := range disk {
				if line.Seq < oldestAvailable {
					older = append(older, line)
				}
			}
			if len(older) > 0 {
				oldestAvailable = older[0].Seq
				candidates = append(older, candidates...)
			}
		}
	}

	filtered := make([]logLine, 0, len(candidates))
	for _, line := range candidates {
		if sel.matches(line) {
			filtered = append(filtered, line)
		}
	}
	if sel.tail > 0 && len(filtered) > sel.tail {
		filtered = filtered[len(filtered)-sel.tail:]
	}

	// What the caller asked for that no longer exists. Their window starts at
	// produced-tail; everything below oldestAvailable is gone.
	if sel.tail > 0 && oldestAvailable > 0 && len(filtered) < sel.tail {
		tail := uint64(sel.tail) //nolint:gosec // positive, checked on the line above, and capped at tail_lines' uint32 range when the request was resolved
		var windowStart uint64
		if produced > tail {
			windowStart = produced - tail
		}
		if oldestAvailable > windowStart {
			dropped = oldestAvailable - windowStart
		}
	}
	return filtered, dropped
}

// countMatching is replay's cheap "can the ring cover this?" question.
func countMatching(lines []logLine, sel selector) int {
	n := 0
	for _, line := range lines {
		if sel.matches(line) {
			n++
		}
	}
	return n
}

// logSender is the half of the gRPC stream this package uses. Narrowing it to
// one method is what lets a test drive exactly the code the server runs without
// standing up a gRPC connection for every log assertion.
type logSender interface {
	Send(*sandboxdv1.GetProcessLogsResponse) error
}

// logRequest is a resolved GetProcessLogs request.
type logRequest struct {
	sel       selector
	follow    bool
	followFor time.Duration
}

// streamLogs serves one call: replay, then follow to the deadline, then a
// terminal summary. The summary is sent on every path that reaches the end of
// the stream, because a reader with no summary cannot tell a completed follow
// from a truncated one.
func (s *Supervisor) streamLogs(ctx context.Context, r *record, req logRequest, out logSender) error {
	var (
		snap []logLine
		sub  *subscriber
	)
	if req.follow {
		// Subscribe and read the ring under one lock. In two steps there is a
		// window in which a line appended between them is either lost or sent
		// twice, and a follower missing the line it was waiting for is exactly
		// the failure this call exists to avoid.
		snap, sub = r.buf.snapshot()
		defer r.buf.unsubscribe(sub)
	} else {
		snap = r.buf.ringLines()
	}

	replayed, shortfall := r.replay(req.sel, snap)

	returned, dropped := uint64(0), shortfall
	pending := shortfall
	for _, line := range replayed {
		if err := sendLine(out, line, pending); err != nil {
			return err
		}
		pending = 0
		returned++
	}

	deadlineReached := false
	if req.follow {
		followed, followDrops, reached, err := s.followLines(ctx, r, req, sub, out)
		returned += followed
		dropped += followDrops
		deadlineReached = reached
		if err != nil {
			return err
		}
	}

	return out.Send(&sandboxdv1.GetProcessLogsResponse{
		Event: &sandboxdv1.GetProcessLogsResponse_Summary{
			Summary: &sandboxdv1.LogSummary{
				LinesReturned:         returned,
				LinesDropped:          dropped,
				FollowDeadlineReached: deadlineReached,
				State:                 r.currentState(),
			},
		},
	})
}

// followLines streams new output until the deadline elapses, the process
// finishes, the record is removed, or the caller goes away.
//
// The deadline timer is started before anything else and is never reset. A
// process that produces one line a second for an hour and a process that
// produces nothing at all both return at the same moment, which is the property
// that makes this call safe to hand a model.
func (s *Supervisor) followLines(ctx context.Context, r *record, req logRequest, sub *subscriber, out logSender) (returned, dropped uint64, deadlineReached bool, err error) {
	deadline := time.NewTimer(s.clampFollow(req.followFor))
	defer deadline.Stop()

	// pending carries drops forward across lines the filter excludes, so the
	// gap is reported on the next line the caller actually sees rather than
	// vanishing with the line it happened to precede.
	var pending uint64

	for {
		// Re-read the state each time round. A process that reaches a terminal
		// state ends the follow promptly with the final state in the summary,
		// rather than making the caller wait out a deadline for news that has
		// already arrived.
		changed, state := r.wait()
		if isTerminal(state) {
			return returned, dropped, false, nil
		}

		select {
		case <-ctx.Done():
			// The caller hung up. Their stream is gone; there is nothing to
			// send and nothing to report.
			return returned, dropped, false, ctx.Err()

		case <-deadline.C:
			return returned, dropped, true, nil

		case <-s.ctx.Done():
			// The agent is shutting down. The process is not: it keeps running
			// and keeps writing, and the next agent picks its logs back up.
			return returned, dropped, false, nil

		case d, ok := <-sub.ch:
			if !ok {
				// The record was removed underneath the follow.
				return returned, dropped, false, nil
			}
			dropped += d.dropped
			pending += d.dropped
			if !req.sel.matches(d.line) {
				// A dropped line still counts even when the line that would
				// have followed it is filtered out: the gap is in the log, not
				// in the filter.
				continue
			}
			if err := sendLine(out, d.line, pending); err != nil {
				return returned, dropped, false, err
			}
			pending = 0
			returned++

		case <-changed:
		}
	}
}

// sendLine writes one line to the stream.
func sendLine(out logSender, line logLine, droppedBefore uint64) error {
	return out.Send(&sandboxdv1.GetProcessLogsResponse{
		Event: &sandboxdv1.GetProcessLogsResponse_Line{
			Line: &sandboxdv1.LogLine{
				Stream:        line.Stream,
				Timestamp:     timestamppb.New(line.At),
				Text:          line.Text,
				DroppedBefore: droppedBefore,
				Continued:     line.Cont,
			},
		},
	})
}
