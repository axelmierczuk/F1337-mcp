package policy

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/axelmierczuk/sandboxd-mcp/internal/platform"
)

var (
	// ErrDenied reports a command refused by the deny list, or one absent from
	// a non-empty allow list. Callers map it to codes.PermissionDenied.
	ErrDenied = errors.New("policy: command refused")

	// ErrTimeoutTooLong reports a requested timeout above the agent's maximum.
	//
	// It is refused rather than clamped. A clamped timeout comes back as
	// timed_out at the agent's limit, which is indistinguishable from the
	// command genuinely overrunning the limit the caller asked for — so the
	// caller cannot tell "your command is slow" from "your request was
	// rewritten". The error names the maximum, which is actionable.
	ErrTimeoutTooLong = errors.New("policy: requested timeout exceeds the agent maximum")

	// ErrTooManyProcesses reports that the central concurrency cap is full.
	ErrTooManyProcesses = errors.New("policy: too many concurrent processes on this agent")
)

// Caps are the resource limits this agent enforces centrally, so that exec and
// the process supervisor cannot disagree about them.
type Caps struct {
	// DefaultTimeout applies to a request that names no timeout.
	DefaultTimeout time.Duration
	// MaxTimeout is the ceiling on a requested timeout. Zero means no ceiling.
	MaxTimeout time.Duration
	// MaxOutputBytes caps buffered command output. A request may ask for less;
	// asking for more is clamped to this.
	MaxOutputBytes int64
	// MaxConcurrent bounds how many processes this agent runs at once, across
	// every service that spawns one. Zero or less means unbounded.
	MaxConcurrent int
}

// Config builds a Policy. Both command lists are optional; both empty is
// default-allow.
type Config struct {
	// Allow, when non-empty, is an allow list: a command that matches nothing
	// in it is refused.
	Allow []string
	// Deny refuses matching commands. It is evaluated before Allow, so an
	// entry in both is denied.
	Deny []string
	// Caps are the central resource limits.
	Caps Caps
}

// Policy is the command policy and the central caps. It is safe for concurrent
// use and is meant to be shared by every service that spawns a process.
type Policy struct {
	allow []string
	deny  []string
	caps  Caps

	// slots is the concurrency limiter, nil when MaxConcurrent is unset. A
	// buffered channel rather than a counter so a caller can wait for a slot
	// with a context instead of polling.
	slots chan struct{}
}

// New builds a Policy, refusing a configuration it could not enforce as
// written.
//
// A malformed pattern is an error rather than an entry that never matches. A
// deny list is written by an operator who believes it is in force, and one
// silently-dead entry in it is the difference between "rm is denied" and "rm
// runs" — that must not be discoverable only in the audit log afterwards.
func New(cfg Config) (*Policy, error) {
	allow, err := checkRules("allow_commands", cfg.Allow)
	if err != nil {
		return nil, err
	}
	deny, err := checkRules("deny_commands", cfg.Deny)
	if err != nil {
		return nil, err
	}

	if cfg.Caps.MaxTimeout > 0 && cfg.Caps.DefaultTimeout > cfg.Caps.MaxTimeout {
		return nil, fmt.Errorf("policy: default timeout %s exceeds the maximum %s",
			cfg.Caps.DefaultTimeout, cfg.Caps.MaxTimeout)
	}
	// A negative cap is not "unlimited" — zero already means that — so it can
	// only be a misconfiguration, and one that would otherwise become an
	// enormous unsigned limit at the wire boundary.
	if cfg.Caps.MaxOutputBytes < 0 {
		return nil, fmt.Errorf("policy: max output bytes %d is negative; use 0 for no cap", cfg.Caps.MaxOutputBytes)
	}

	p := &Policy{allow: allow, deny: deny, caps: cfg.Caps}
	if cfg.Caps.MaxConcurrent > 0 {
		p.slots = make(chan struct{}, cfg.Caps.MaxConcurrent)
	}
	return p, nil
}

// checkRules normalises a rule list and rejects entries that cannot match.
func checkRules(field string, rules []string) ([]string, error) {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		trimmed := strings.TrimSpace(rule)
		if trimmed == "" {
			return nil, fmt.Errorf("policy: %s contains an empty entry", field)
		}
		// filepath.Match reports ErrBadPattern for an unterminated character
		// class, and only when it actually reaches it — so probe with a string
		// that cannot match anything else.
		if _, err := filepath.Match(trimmed, "\x00"); err != nil {
			return nil, fmt.Errorf("policy: %s entry %q is not a valid pattern: %w", field, rule, err)
		}
		out = append(out, trimmed)
	}
	return out, nil
}

// Caps returns the limits this policy enforces.
func (p *Policy) Caps() Caps { return p.caps }

// Rules reports the configured lists, for diagnostics and for the startup log.
func (p *Policy) Rules() (allow, deny []string) {
	return slices.Clone(p.allow), slices.Clone(p.deny)
}

// Restricted reports whether either list is non-empty. A false result means
// every command is allowed, which is the default and is documented as such.
func (p *Policy) Restricted() bool { return len(p.allow) > 0 || len(p.deny) > 0 }

// Decision is the outcome of evaluating a command against the lists.
type Decision struct {
	// Allowed is false when the command must be refused.
	Allowed bool
	// Rule is the list entry that decided it, empty when nothing matched.
	Rule string
	// Reason explains the decision in terms an operator can act on. It is
	// safe to return to the caller: it names the command and the rule, never
	// anything from the environment.
	Reason string
}

// Evaluate applies the deny list and then the allow list to a resolved
// command.
//
// Matching is on every name the command answers to — the argument as given,
// the path it resolved to, the path that resolves to after symlinks, and the
// base name of each — plus the whole argv joined by spaces, so an entry may
// name a subcommand ("go test") rather than only an executable. Entries are
// exact matches or filepath.Match globs, compared case-insensitively where the
// platform's paths are.
//
// Matching the resolved path rather than the string as given is the point: a
// deny entry for "sh" that only compared argv[0] is walked past by
// "/bin/../bin/sh", and by any other spelling of the same file.
//
// Two consequences are worth stating plainly, because they are the reason this
// is a guardrail and not a boundary:
//
//   - A name is not an identity. An allow list holding "python3" admits any
//     file named python3 anywhere on the host, including one the caller just
//     wrote. Prefer absolute paths in an allow list.
//   - An allowed interpreter allows everything it can run. "python3" on an
//     allow list is a shell by another name.
func (p *Policy) Evaluate(cmd Command) Decision {
	names := cmd.names()

	if rule, ok := matchAny(p.deny, names); ok {
		return Decision{
			Rule:   rule,
			Reason: fmt.Sprintf("command %q matches the deny rule %q", cmd.describe(), rule),
		}
	}
	if len(p.allow) == 0 {
		return Decision{Allowed: true}
	}
	if rule, ok := matchAny(p.allow, names); ok {
		return Decision{Allowed: true, Rule: rule}
	}
	return Decision{
		Reason: fmt.Sprintf("command %q is not in this agent's allow list", cmd.describe()),
	}
}

// Check is Evaluate as an error, for a caller that only wants the refusal.
func (p *Policy) Check(cmd Command) error {
	if d := p.Evaluate(cmd); !d.Allowed {
		return fmt.Errorf("%w: %s", ErrDenied, d.Reason)
	}
	return nil
}

func matchAny(rules []string, names []string) (string, bool) {
	for _, rule := range rules {
		folded := fold(rule)
		for _, name := range names {
			if name == "" {
				continue
			}
			candidate := fold(name)
			if folded == candidate {
				return rule, true
			}
			// An invalid pattern was refused at construction, so the error
			// here can only be ErrBadPattern for a rule that never made it
			// into the list.
			if ok, err := filepath.Match(folded, candidate); err == nil && ok {
				return rule, true
			}
		}
	}
	return "", false
}

// fold lowercases ASCII where the platform's paths are case-insensitive.
//
// ASCII only, for the same reason internal/platform folds that way: Windows
// compares filenames through an upcase table that Go's Unicode simple folding
// is not, and over-folding would let a rule match a name it does not name.
// Under-folding can only fail to match a rule, which is the direction an
// operator can see and fix.
func fold(s string) string {
	if !platform.CaseInsensitivePaths {
		return s
	}
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// Timeout resolves a requested wall-clock limit against the caps.
//
// Zero means the agent default. Above the maximum is ErrTimeoutTooLong rather
// than a silent clamp; see the error's documentation.
func (p *Policy) Timeout(requested time.Duration) (time.Duration, error) {
	if requested < 0 {
		return 0, fmt.Errorf("policy: timeout %s is negative", requested)
	}
	if requested == 0 {
		requested = p.caps.DefaultTimeout
	}
	if p.caps.MaxTimeout > 0 && requested > p.caps.MaxTimeout {
		return 0, fmt.Errorf("%w: asked for %s, the maximum is %s", ErrTimeoutTooLong, requested, p.caps.MaxTimeout)
	}
	if requested <= 0 {
		return 0, errors.New("policy: no timeout configured and none requested")
	}
	return requested, nil
}

// OutputCap resolves a requested output limit against the caps.
//
// Zero means the agent default. A request for more than the agent allows is
// clamped rather than refused: the result already carries a Truncation saying
// output was cut, so the caller is told what happened and still gets the work
// product — which is not true of a refused call.
func (p *Policy) OutputCap(requested uint64) uint64 {
	maxBytes := uint64(0)
	if p.caps.MaxOutputBytes > 0 {
		maxBytes = uint64(p.caps.MaxOutputBytes) //nolint:gosec // G115: positive here, and New refuses a negative cap outright
	}
	if requested == 0 || (maxBytes > 0 && requested > maxBytes) {
		return maxBytes
	}
	return requested
}

// Acquire takes a slot in the central concurrency limit, blocking until one is
// free or ctx is done.
//
// The returned release function must be called exactly once, and is safe to
// defer immediately: it is a no-op when the call returned an error.
func (p *Policy) Acquire(ctx context.Context) (release func(), err error) {
	if p.slots == nil {
		return func() {}, nil
	}
	select {
	case p.slots <- struct{}{}:
		// sync.Once rather than a bool: a release that ran twice would hand
		// out a slot nobody holds, and the limit would drift upwards over the
		// life of the daemon rather than failing visibly.
		var once sync.Once
		return func() { once.Do(func() { <-p.slots }) }, nil
	case <-ctx.Done():
		return func() {}, fmt.Errorf("%w (limit %d): %w", ErrTooManyProcesses, p.caps.MaxConcurrent, ctx.Err())
	}
}

// InUse reports how many slots of the concurrency limit are taken.
func (p *Policy) InUse() int { return len(p.slots) }
