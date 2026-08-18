package registry

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Registering a sandbox, in one place.
//
// Two front ends register a fleet member: `fleetctl add` for the operator and
// the fleet_add MCP tool for the model. They are deliberately separate
// commands — minting credentials is an operator action and the model may not do
// it — but "what may be written into the registry" is one rule, and a rule with
// two copies is a rule that agrees on the day it was written and drifts after.
// So the checks, the trimming, the refusal to overwrite and the sentence about
// what registering did not do all live here, and each front end supplies only
// what is genuinely its own: its vocabulary for the remedy, and its output
// shape.
//
// [Registry.Add] stays as it was, unchecked, because enrollment writes through
// it: the name in an enrolled entry came out of a certificate subject that
// enrollment already bounded, and the labels came from the operator's own
// token. Register is for the two callers that take a name off a command line or
// out of a tool call.

// Bounds on what may be registered.
const (
	// MaxNameLength bounds the identifier that becomes a registry key and a
	// certificate subject. It matches the bound enrollment applies to the one
	// identifier an unauthenticated host can put into a certificate subject,
	// so a name registered here is a name that could have been enrolled.
	MaxNameLength = 128
	// MaxLabels, MaxLabelKeyLength and MaxLabelValueLength bound the free-form
	// metadata a registration attaches.
	//
	// Labels are the one part of a registration with no shape of their own,
	// and they are paid for twice: once in the registry file that every later
	// operation rewrites whole, and again in every fleet listing, which lands
	// in model context on every fleet check.
	MaxLabels           = 32
	MaxLabelKeyLength   = 64
	MaxLabelValueLength = 256
)

// maxEcho bounds how much of a rejected value an error may quote back. An
// oversized label key is still named in the message that rejects it — an
// operator has to know which one — but a 50 KB key must not arrive back as a
// 50 KB error.
const maxEcho = 160

// The sentence a registration ends with: what it did not do.
//
// It is the half a caller most often assumes. Registering writes one line to a
// file on this workstation; it does not install anything, does not issue
// anything, and does not make the host agree.
const (
	// NoteRegistered is what an mTLS registration says.
	NoteRegistered = "Registered locally only. This does not enroll the host: the agent must already hold a certificate from this fleet's CA, or calls to it will fail the mTLS handshake."
	// NoteRegisteredInsecure is what a registration without mTLS says.
	//
	// A different sentence, not a suffix. The mTLS note tells the caller what
	// still has to happen for this entry to work; this one tells them what will
	// never happen for it, which is the more important half.
	NoteRegisteredInsecure = "Registered locally only, and without mTLS: no client certificate will be presented to this host and its agent verifies none, so nothing in this fleet authenticates either end. That is only safe if the network between them does — a tailnet, a WireGuard mesh, a tight VPC. The agent must be running with tls.enabled false, or calls to it will fail."
)

// DuplicateError reports a registration refused because the name is taken.
//
// It carries the address already registered because that is the fact the caller
// needs and the one the failure is about: a name that resolves to somewhere
// else. Silently repointing it is how a later call reaches the wrong host, so
// registering never overwrites — and the remedy differs by front end
// (`fleetctl remove`, fleet_remove), which is why the message here names none.
type DuplicateError struct {
	// Name is the name that was already taken.
	Name string
	// Address is where that name already points.
	Address string
}

func (e *DuplicateError) Error() string {
	return fmt.Sprintf("sandbox %q is already registered at %s; registering does not overwrite", e.Name, e.Address)
}

// Unwrap makes a DuplicateError match ErrExists, so a caller that only wants to
// know "the name is taken" keeps working.
func (e *DuplicateError) Unwrap() error { return ErrExists }

// Registration is what registering did, and — in its note — what it did not.
type Registration struct {
	// Sandbox is the entry as it was written, after trimming.
	Sandbox Sandbox
	// Note states what registering did not do. Never empty.
	Note string
}

// Register validates sb and adds it to the registry.
//
// Every check runs before the registry is touched, so a malformed registration
// cannot leave a half-written entry behind.
func (r *Registry) Register(sb Sandbox) (Registration, error) {
	sb.Name = strings.TrimSpace(sb.Name)
	sb.Address = strings.TrimSpace(sb.Address)

	if err := CheckName(sb.Name); err != nil {
		return Registration{}, err
	}
	if err := CheckAddress(sb.Address); err != nil {
		return Registration{}, err
	}
	if err := CheckLabels(sb.Labels); err != nil {
		return Registration{}, err
	}

	if err := r.Add(sb); err != nil {
		if errors.Is(err, ErrExists) {
			// Read back rather than assumed: the caller is about to be told
			// where the name already points, and that is only useful if it is
			// the address the registry actually holds.
			if existing, getErr := r.Get(sb.Name); getErr == nil {
				return Registration{}, &DuplicateError{Name: sb.Name, Address: existing.Address}
			}
		}
		return Registration{}, err
	}

	note := NoteRegistered
	if sb.Insecure {
		note = NoteRegisteredInsecure
	}
	return Registration{Sandbox: sb, Note: note}, nil
}

// CheckName bounds the identifier that becomes a registry key, a certificate
// subject, and a line in a table.
func CheckName(name string) error {
	if name == "" {
		return errors.New("name is required")
	}
	if len(name) > MaxNameLength {
		return fmt.Errorf("name is %d bytes, limit is %d", len(name), MaxNameLength)
	}
	for _, r := range name {
		// Printable, non-space ASCII: a sandbox name is typed on a command
		// line and printed in a table.
		if r <= ' ' || r > '~' {
			return fmt.Errorf("name contains an invalid character %q; use printable ASCII with no spaces", r)
		}
	}
	if strings.HasPrefix(name, "sbx_") {
		return fmt.Errorf("name %q collides with the handle prefix sbx_; choose another", name)
	}
	return nil
}

// CheckAddress validates host:port before the registry is touched. The host
// half becomes the TLS server name the agent's certificate is verified
// against, so an address that is not host:port is a configuration error that
// should be named as one here rather than surfacing later as a handshake
// failure.
func CheckAddress(address string) error {
	if address == "" {
		return errors.New("address is required, as host:port")
	}
	if strings.Contains(address, "://") {
		return fmt.Errorf("address %q looks like a URL; give host:port, e.g. build-box.internal:8722", address)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("address %q is not host:port (e.g. build-box.internal:8722): %w", address, err)
	}
	if host == "" {
		return fmt.Errorf("address %q names no host; the host half is what the agent's certificate is checked against", address)
	}
	if strings.ContainsAny(host, "/\\ ") {
		return fmt.Errorf("address %q has an invalid host %q", address, host)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("address %q has an invalid port %q; expected 1-65535", address, port)
	}
	return nil
}

// CheckLabels bounds the free-form metadata a registration attaches. See
// [MaxLabels].
func CheckLabels(labels map[string]string) error {
	if len(labels) > MaxLabels {
		return fmt.Errorf("%d labels given, limit is %d", len(labels), MaxLabels)
	}
	for key, value := range labels {
		if key == "" {
			return errors.New(`a label key is empty; labels are key=value metadata, e.g. {"arch":"arm64"}`)
		}
		if len(key) > MaxLabelKeyLength {
			return fmt.Errorf("label key %q is %d bytes, limit is %d", echo(key), len(key), MaxLabelKeyLength)
		}
		for _, r := range key {
			// A key is typed into the label filter as key=value and printed in
			// a table, so it carries the same restriction a name does.
			if r <= ' ' || r > '~' {
				return fmt.Errorf("label key %q contains an invalid character %q; use printable ASCII with no spaces",
					echo(key), r)
			}
		}
		if len(value) > MaxLabelValueLength {
			return fmt.Errorf("label %q has a %d-byte value, limit is %d", key, len(value), MaxLabelValueLength)
		}
		for _, r := range value {
			if !unicode.IsPrint(r) {
				return fmt.Errorf("label %q has a value containing an unprintable character %q", key, r)
			}
		}
	}
	return nil
}

// echo bounds a rejected value quoted back in an error.
func echo(s string) string {
	if len(s) <= maxEcho {
		return s
	}
	// Cut on a rune boundary: slicing mid-rune would put invalid UTF-8 into
	// the error.
	cut := maxEcho
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
