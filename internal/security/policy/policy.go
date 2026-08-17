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
	"unicode/utf8"

	"github.com/axelmierczuk/fleet-mcp/internal/platform"
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
		if err := checkPattern(trimmed); err != nil {
			return nil, fmt.Errorf("policy: %s entry %q is not a valid pattern: %w", field, rule, err)
		}
		out = append(out, trimmed)
	}
	return out, nil
}

// errBadClass is the one thing filepath.Match's syntax can get wrong.
var errBadClass = errors.New("a [ ] character class is empty, unterminated, or has a stray - or ]")

// checkPattern reports whether filepath.Match can evaluate a pattern to
// completion.
//
// It walks the pattern rather than probing Match with a sample string, because
// Match reports a malformed pattern only when its scan actually reaches the
// malformed part and the scan stops at the first literal mismatch. Probing
// "rm[" with anything finds the error; probing "/usr/bin/*[" finds nothing,
// because the leading literal fails against every sample. That rule would then
// have been accepted at startup and matched nothing at all — a deny list entry
// an operator believes is in force and is not.
//
// The two rules mirrored here are Match's own: a backslash escapes the next
// byte, except on Windows where it is a path separator, and a character class
// must be closed, non-empty, and free of a leading or trailing range dash.
func checkPattern(p string) error {
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '\\':
			if patternEscapes {
				if i+1 >= len(p) {
					return errors.New("a trailing backslash escapes nothing")
				}
				i++
			}
		case '[':
			rest, err := checkClass(p[i+1:])
			if err != nil {
				return err
			}
			i = len(p) - len(rest) - 1
		}
	}
	return nil
}

// checkClass consumes one [...] character class and returns what follows it.
func checkClass(s string) (string, error) {
	s = strings.TrimPrefix(s, "^")
	items := 0
	for {
		// A ']' closes the class, but only once it has something in it: Match
		// reads a leading ']' as a malformed range, not as a literal.
		if len(s) > 0 && s[0] == ']' && items > 0 {
			return s[1:], nil
		}
		var err error
		if s, err = classItem(s); err != nil {
			return "", err
		}
		if len(s) > 0 && s[0] == '-' {
			if s, err = classItem(s[1:]); err != nil {
				return "", err
			}
		}
		items++
	}
}

// classItem consumes one character of a class and returns what follows it. An
// item that reaches the end of the pattern means the class was never closed.
func classItem(s string) (string, error) {
	if s == "" || s[0] == '-' || s[0] == ']' {
		return "", errBadClass
	}
	if s[0] == '\\' && patternEscapes {
		s = s[1:]
		if s == "" {
			return "", errBadClass
		}
	}
	_, n := utf8.DecodeRuneInString(s)
	if s[n:] == "" {
		return "", errBadClass
	}
	return s[n:], nil
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
// base name of each — and on the leading runs of the argv built from each of
// those, so an entry may name a subcommand ("go test") rather than only an
// executable. Entries are exact matches or filepath.Match globs, compared
// case-insensitively where the platform's paths are.
//
// Matching the resolved path rather than the string as given is the point: a
// deny entry for "sh" that only compared argv[0] is walked past by
// "/bin/../bin/sh", and by any other spelling of the same file. The command
// lines are built from every one of those spellings for the same reason — a
// rule reading "go test" that saw only the caller's own argv[0] would be
// walked past by "/usr/local/go/bin/go test", which is the same command.
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
	// Folded once here rather than inside matchAny's rule loop. The names are
	// built from the argv, so on a platform that folds they are the one thing
	// in this comparison whose size the caller chooses — refolding them per
	// rule multiplies a request's own argv by the length of the operator's
	// list, and does it twice over for an agent with both lists set.
	names := foldAll(cmd.names())

	rule, matched, err := matchAny(p.deny, names)
	if err != nil {
		return unevaluable("deny_commands", rule, err)
	}
	if matched {
		return Decision{
			Rule:   rule,
			Reason: fmt.Sprintf("command %q matches the deny rule %q", cmd.describe(), rule),
		}
	}

	if len(p.allow) == 0 {
		return Decision{Allowed: true}
	}
	rule, matched, err = matchAny(p.allow, names)
	if err != nil {
		return unevaluable("allow_commands", rule, err)
	}
	if matched {
		return Decision{Allowed: true, Rule: rule}
	}
	return Decision{
		Reason: fmt.Sprintf("command %q is not in this agent's allow list", cmd.describe()),
	}
}

// unevaluable refuses a command because a rule could not be applied to it.
//
// Fail closed, loudly. New rejects a malformed pattern at construction, so
// reaching this means one got past that check — and the alternative, treating
// a rule that cannot be evaluated as one that did not match, silently turns a
// deny list entry into nothing. That is the failure mode this package exists
// to avoid: an operator reading their config sees a rule that is not in force.
func unevaluable(field, rule string, err error) Decision {
	return Decision{
		Rule: rule,
		Reason: fmt.Sprintf("this agent's %s cannot be applied to this command (%s), so it is refused; "+
			"fix the rule and the agent will run commands again", field, err),
	}
}

// Check is Evaluate as an error, for a caller that only wants the refusal.
func (p *Policy) Check(cmd Command) error {
	if d := p.Evaluate(cmd); !d.Allowed {
		return fmt.Errorf("%w: %s", ErrDenied, d.Reason)
	}
	return nil
}

// foldAll folds every name once, dropping the empty ones.
func foldAll(names []string) []string {
	folded := make([]string, 0, len(names))
	for _, name := range names {
		if name != "" {
			folded = append(folded, fold(name))
		}
	}
	return folded
}

// matchAny reports the first rule that matches any of the command's names,
// which must already be folded.
//
// A pattern that cannot be evaluated is returned as an error rather than read
// as a non-match. Match reports a malformed pattern only for the candidates its
// scan reaches, so the same rule can error against one name and quietly match
// nothing against another — which would make a broken deny list look like an
// empty one for most commands and a working one for the occasional other.
func matchAny(rules []string, folded []string) (string, bool, error) {
	for _, rule := range rules {
		pattern := fold(rule)
		for _, candidate := range folded {
			if pattern == candidate {
				return rule, true, nil
			}
			ok, err := filepath.Match(pattern, candidate)
			if err != nil {
				return rule, false, fmt.Errorf("rule %q: %w", rule, err)
			}
			if ok {
				return rule, true, nil
			}
		}
	}
	return "", false, nil
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
