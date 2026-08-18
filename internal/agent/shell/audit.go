package shell

import (
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	"github.com/axelmierczuk/fleet-mcp/internal/security/policy"
)

// sessionAudit is everything the audit log may learn about a shell session.
//
// It is a type rather than a policy.Record built up in place, and that is the
// package's one structural defence against the failure this feature could most
// easily have: a log that captures what the operator typed. Nothing here can
// hold a byte of the session. There is no field for it, [Service.finish] is the
// only writer of records in this package and takes nothing else, and the code
// that does touch session bytes is handed neither this value nor the log. See
// the package comment.
//
// Adding a field that could carry session content — an "output tail" for
// diagnostics, a "last command" scraped from the stream — would defeat all of
// it, and is exactly the kind of well-meant addition the shape is here to make
// someone argue for out loud.
type sessionAudit struct {
	// started is when the request arrived, and duration how long the session
	// then ran. The end of a session is started+duration; that is the same
	// arrangement ForwardService records a connection with, and the reason is
	// the same — the record is written when the thing ends, so both facts are
	// known at once and an explicit second timestamp would restate one of them.
	started  time.Time
	duration time.Duration

	// principal is who the daemon resolved this session's caller to be, and how
	// it knows: the common name from a verified client certificate, or — on an
	// agent serving without mTLS — the peer address, named as unauthenticated.
	// Either way it is derived from the connection, never from anything the
	// caller sends.
	principal agent.Principal

	// argv is the command the session ran, and path the executable it resolved
	// to. This is the one place a caller can put a secret into this file — a
	// session opened as `mysql -pHUNTER2` writes it down — which is the same
	// limitation, for the same reason, that policy.Record documents for exec.
	argv []string
	path string
	dir  string

	outcome policy.Outcome
	// rule is the setting or policy entry that refused the session.
	rule string
	// failure is the reason the caller was told, written by the agent. It is
	// never echoed from the session.
	failure string

	// exitCode is a pointer so that "exited 0" and "never started" are
	// different records rather than the same one.
	exitCode *int32
	signal   string
	// idle records that the agent ended the session because nothing had
	// happened on it for shell.idle_timeout.
	idle bool
}

// record renders the session as the line that goes into the audit log.
func (a sessionAudit) record() policy.Record {
	return policy.Record{
		Time: a.started,
		// The name and what established it, always together. See
		// policy.Record.PrincipalSource.
		Principal:       a.principal.String(),
		PrincipalSource: a.principal.Source(),
		RPC:             shellMethod,
		Outcome:         a.outcome,
		Argv:            a.argv,
		Path:            a.path,
		WorkingDir:      a.dir,
		ExitCode:        a.exitCode,
		Signal:          a.signal,
		TimedOut:        a.idle,
		DurationMS:      a.duration.Milliseconds(),
		Rule:            a.rule,
		Error:           a.failure,
	}
}

// finish writes the session's audit record and returns the error the RPC ends
// with.
//
// This is where audit.required is a real choice rather than a label, on the
// same terms as exec's finish: with it set, a session whose record could not be
// written fails the call. That matters more here than anywhere else — an agent
// configured to act only when it can record what it did must not hand out an
// unrecorded terminal — but it cannot be a refusal *before* the fact, because
// by the time this runs the session has already happened. What it withholds is
// the clean ending.
func (s *Service) finish(rec sessionAudit, rpcErr error) error {
	err := s.audit.Write(rec.record())
	if err == nil {
		return rpcErr
	}

	s.log.Error("audit record was not written",
		"path", s.audit.Path(),
		"required", s.audit.Required(),
		"rpc", shellMethod,
		"outcome", rec.outcome,
		"principal", rec.principal,
		"error", err)

	if !s.audit.Required() {
		return rpcErr
	}
	if rpcErr != nil {
		return status.Errorf(codes.Internal,
			"audit.required is set and this session's record could not be written (%v); the call had already failed: %s",
			err, status.Convert(rpcErr).Message())
	}
	return status.Errorf(codes.Internal,
		"audit.required is set and this session's record could not be written, so its result is withheld: %v", err)
}
