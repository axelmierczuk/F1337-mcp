package ca

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Files a staged rotation adds to the CA directory. They exist only between
// [Stage] and [Activate].
const (
	nextCertFileName = "ca-next.crt"
	nextKeyFileName  = "ca-next.key"
)

// Rotating the CA is three operator steps, not one command, and the ordering is
// the whole security property.
//
// A fleet member trusts the roots in the bundle it was given and presents a leaf
// signed by whichever root was issuing when it enrolled. So two trust directions
// have to be kept working at once: the control plane verifying an agent's leaf,
// and the agent verifying the control plane's. Issuing under a new root before
// every agent trusts that root breaks the second one — every agent rejects the
// control plane, and an agent that has stopped answering is an agent you cannot
// push a fix to over this transport.
//
// Hence: distribute trust first, switch issuers second, drop the old root third.
//
//	Stage     new root generated, added to the bundle, NOT issuing.
//	          Operator copies the bundle to every agent and restarts them.
//	Activate  new root becomes the issuer. Old leaves still verify, because
//	          the old root is still in everyone's bundle.
//	          Operator re-issues leaves at leisure.
//	Retire    old roots leave the bundle. Anything still holding a leaf under
//	          one of them stops verifying, which is why this step is last and
//	          explicit.
//
// There is deliberately no single command that does all three. The middle step
// is an operator distributing a file to machines this tool cannot reach, and a
// `rotate` that pretended otherwise would brick a fleet on its way to a green
// exit code.

var (
	// ErrRotationStaged reports that a rotation is already staged.
	ErrRotationStaged = errors.New("ca: a CA rotation is already staged")
	// ErrNoRotationStaged reports that no rotation is staged to act on.
	ErrNoRotationStaged = errors.New("ca: no CA rotation is staged")
)

// Rotation is where a CA directory sits in the stage → activate → retire
// sequence.
type Rotation struct {
	// Issuer is the CA signing new leaves right now.
	Issuer *x509.Certificate
	// Staged is the incoming CA: trusted by anything holding the current
	// bundle, but not yet issuing. Nil when no rotation is staged.
	Staged *x509.Certificate
	// Superseded are roots that still verify existing leaves but have stopped
	// issuing. They are what [Retire] removes.
	Superseded []*x509.Certificate
}

// Staging reports whether a rotation is staged and waiting to be activated.
func (r Rotation) Staging() bool { return r.Staged != nil }

// Overlapping reports whether more than one root is currently trusted, which is
// the state a rotation passes through and must not be left in indefinitely.
func (r Rotation) Overlapping() bool { return r.Staged != nil || len(r.Superseded) > 0 }

// Status reports the rotation state of the CA in dir.
func Status(dir string) (Rotation, error) {
	authority, err := Load(dir)
	if err != nil {
		return Rotation{}, err
	}
	return authority.rotation()
}

// rotation classifies this CA's trust bundle. Everything after the issuer is a
// root that no longer issues; the one that matches ca-next.crt, if any, is the
// staged incoming CA rather than a superseded outgoing one.
func (c *CA) rotation() (Rotation, error) {
	staged, err := readStagedCert(c.dir)
	if err != nil {
		return Rotation{}, err
	}

	out := Rotation{Issuer: c.cert, Staged: staged}
	for _, root := range c.trusted[1:] {
		if staged != nil && root.Equal(staged) {
			continue
		}
		out.Superseded = append(out.Superseded, root)
	}
	// A staged certificate that is not in the bundle is a stage that was
	// interrupted between writing the file and rewriting the bundle. Say so
	// rather than reporting a rotation whose root nothing trusts.
	if staged != nil && !containsCert(c.trusted, staged) {
		return out, fmt.Errorf("ca: %s holds a staged CA that is missing from %s; re-run the rotation after removing %s",
			filepath.Join(c.dir, nextCertFileName), filepath.Join(c.dir, certFileName), nextCertFileName)
	}
	return out, nil
}

// Stage generates the next CA and adds it to the trust bundle without making it
// the issuer. Nothing is signed under it yet, so this step cannot invalidate a
// certificate: it only widens what the fleet accepts.
//
// The operator's job between here and [Activate] is to get the widened bundle
// onto every agent, which is the step no tool can do for them.
func Stage(dir string) (Rotation, error) {
	current, err := Load(dir)
	if err != nil {
		return Rotation{}, err
	}
	state, err := current.rotation()
	if err != nil {
		return Rotation{}, err
	}
	if state.Staging() {
		return state, fmt.Errorf("%w in %s: activate it with `ca rotate --activate`, or discard it by deleting %s and %s",
			ErrRotationStaged, dir, nextCertFileName, nextKeyFileName)
	}

	_, cert, certPEM, keyPEM, err := generate()
	if err != nil {
		return Rotation{}, err
	}

	// Key, then certificate, then bundle. A crash before the certificate lands
	// leaves an orphan key that the next Stage overwrites; a crash before the
	// bundle lands is reported by rotation() rather than silently activated.
	if err := writeFileAtomic(filepath.Join(dir, nextKeyFileName), keyPEM, 0o600); err != nil {
		return Rotation{}, err
	}
	if err := writeFileAtomic(filepath.Join(dir, nextCertFileName), certPEM, 0o644); err != nil {
		return Rotation{}, err
	}
	if err := writeBundle(dir, append(current.TrustedRoots(), cert)); err != nil {
		return Rotation{}, err
	}

	return Rotation{Issuer: current.cert, Staged: cert, Superseded: state.Superseded}, nil
}

// Activate promotes the staged CA to issuer. Leaves already signed by the
// outgoing CA keep verifying, because the outgoing root stays in the bundle
// until [Retire].
//
// The outgoing private key is not kept. Every leaf it would sign can be signed
// by the new one, and a spare CA signing key left on disk is exactly the thing
// the split between this directory and everything else exists to avoid.
func Activate(dir string) (Rotation, error) {
	current, err := Load(dir)
	if err != nil {
		return Rotation{}, err
	}
	state, err := current.rotation()
	if err != nil {
		return Rotation{}, err
	}
	if !state.Staging() {
		return state, fmt.Errorf("%w in %s: run `ca rotate` first, then distribute the bundle before activating", ErrNoRotationStaged, dir)
	}

	nextKeyPEM, err := os.ReadFile(filepath.Join(dir, nextKeyFileName)) //nolint:gosec // dir is operator-supplied, not attacker input
	if err != nil {
		return Rotation{}, fmt.Errorf("ca: read %s: %w", filepath.Join(dir, nextKeyFileName), err)
	}
	if err := checkKeyMatches(nextKeyPEM, state.Staged); err != nil {
		return Rotation{}, fmt.Errorf("ca: %s does not match %s: %w",
			filepath.Join(dir, nextKeyFileName), filepath.Join(dir, nextCertFileName), err)
	}

	// The bundle is rebuilt from scratch rather than reordered in place, so an
	// interrupted Stage that never reached the bundle still activates onto a
	// bundle that holds the root now doing the issuing.
	roots := append([]*x509.Certificate{state.Staged, current.cert}, state.Superseded...)

	// Key first: a crash between the two writes leaves a certificate that does
	// not match its key, which Load refuses — and re-running Activate repairs
	// it, because the staged files are removed only once both writes are done.
	if err := writeFileAtomic(filepath.Join(dir, keyFileName), nextKeyPEM, 0o600); err != nil {
		return Rotation{}, err
	}
	if err := writeBundle(dir, roots); err != nil {
		return Rotation{}, err
	}
	if err := discardStaged(dir); err != nil {
		return Rotation{}, err
	}

	return Rotation{Issuer: state.Staged, Superseded: roots[1:]}, nil
}

// Retire drops every root but the issuer from the trust bundle. It is the step
// that can break a fleet member — anything still holding a leaf signed by a
// dropped root stops verifying — so it is separate, last, and never implied.
func Retire(dir string) (Rotation, error) {
	current, err := Load(dir)
	if err != nil {
		return Rotation{}, err
	}
	state, err := current.rotation()
	if err != nil {
		return Rotation{}, err
	}
	if state.Staging() {
		return state, fmt.Errorf("%w in %s: activate it or discard it before retiring the old roots", ErrRotationStaged, dir)
	}
	if len(state.Superseded) == 0 {
		return state, nil
	}
	if err := writeBundle(dir, []*x509.Certificate{current.cert}); err != nil {
		return Rotation{}, err
	}
	return Rotation{Issuer: current.cert}, nil
}

// writeBundle replaces ca.crt with roots, de-duplicated, issuer first.
func writeBundle(dir string, roots []*x509.Certificate) error {
	var unique []*x509.Certificate
	for _, root := range roots {
		if root != nil && !containsCert(unique, root) {
			unique = append(unique, root)
		}
	}
	return writeFileAtomic(filepath.Join(dir, certFileName), encodeBundle(unique), 0o644)
}

// readStagedCert returns the staged CA certificate, or nil when none is staged.
func readStagedCert(dir string) (*x509.Certificate, error) {
	path := filepath.Join(dir, nextCertFileName)
	data, err := os.ReadFile(path) //nolint:gosec // dir is operator-supplied, not attacker input
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("ca: read %s: %w", path, err)
	}
	certs, err := decodeBundle(data)
	if err != nil {
		return nil, fmt.Errorf("ca: parse %s: %w", path, err)
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("ca: %s holds %d certificates, expected exactly one", path, len(certs))
	}
	return certs[0], nil
}

// discardStaged removes the staged rotation's files.
func discardStaged(dir string) error {
	for _, name := range []string{nextKeyFileName, nextCertFileName} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("ca: remove %s: %w", filepath.Join(dir, name), err)
		}
	}
	return nil
}

// checkKeyMatches verifies that a PEM private key belongs to cert, for the same
// reason Load does: promoting a certificate whose key is not beside it produces
// a CA that cannot sign anything, discovered at the next enrollment.
func checkKeyMatches(keyPEM []byte, cert *x509.Certificate) error {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return errors.New("no PEM key found")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !key.PublicKey.Equal(pub) {
		return errors.New("the key does not belong to this certificate")
	}
	return nil
}

func containsCert(certs []*x509.Certificate, want *x509.Certificate) bool {
	for _, cert := range certs {
		if cert.Equal(want) {
			return true
		}
	}
	return false
}
