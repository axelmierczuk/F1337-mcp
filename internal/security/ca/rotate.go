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
//
// It reads the trust bundle rather than loading the CA, and so answers for a
// directory whose signing key does not match its certificate. That is not an
// exotic case: it is what an activation interrupted between its two writes
// leaves behind, and it is the one state in which an operator most needs to be
// told where in a rotation they are. Insisting on Load here put the description
// of the damage behind the damage, and with it [Activate], the repair — see the
// comment there.
func Status(dir string) (Rotation, error) {
	trusted, err := readBundle(dir)
	if err != nil {
		return Rotation{}, err
	}
	return classify(dir, trusted)
}

// rotation classifies this CA's trust bundle.
func (c *CA) rotation() (Rotation, error) { return classify(c.dir, c.trusted) }

// classify sorts a trust bundle into the rotation state it represents.
// Everything after the issuer is a root that no longer issues; the one that
// matches ca-next.crt, if any, is the staged incoming CA rather than a
// superseded outgoing one.
//
// It takes the bundle rather than a loaded CA because [Activate] has to be able
// to classify a directory whose signing key does not match its certificate; see
// the comment there.
func classify(dir string, trusted []*x509.Certificate) (Rotation, error) {
	staged, err := readStagedCert(dir)
	if err != nil {
		return Rotation{}, err
	}

	out := Rotation{Issuer: trusted[0], Staged: staged}
	for _, root := range trusted[1:] {
		if staged != nil && root.Equal(staged) {
			continue
		}
		out.Superseded = append(out.Superseded, root)
	}
	// A staged certificate that is not in the bundle is a stage that was
	// interrupted between writing the file and rewriting the bundle. Say so
	// rather than reporting a rotation whose root nothing trusts.
	if staged != nil && !containsCert(trusted, staged) {
		return out, fmt.Errorf("ca: %s holds a staged CA that is missing from %s; re-run the rotation after removing %s",
			filepath.Join(dir, nextCertFileName), filepath.Join(dir, certFileName), nextCertFileName)
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
	// The bundle is read directly rather than through Load, and the outgoing
	// signing key is deliberately neither read nor required to match it.
	//
	// That is what makes the repair below possible. Activate replaces ca.key,
	// so a crash between its two writes leaves the incoming key beside the
	// outgoing certificate — precisely the mismatch Load refuses. Loading first
	// meant the one command that could finish an interrupted activation was the
	// one command that could not run, and the CA directory stayed unloadable:
	// not just `ca rotate`, but `ca fingerprint`, `serve`, `enroll mint` and
	// `list` too, because all of them go through Load.
	//
	// Everything Activate actually needs — the bundle, and the staged
	// certificate and key — is still on disk in that state, and the pair it
	// writes is checked below, so the invariant Load enforces is re-established
	// by this function rather than assumed by it.
	trusted, err := readBundle(dir)
	if err != nil {
		return Rotation{}, err
	}
	state, err := classify(dir, trusted)
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
	//
	// Deduplicated here rather than only on the way to disk, because the state
	// this function returns has to describe the bundle it wrote. Re-running
	// Activate to finish one interrupted between its two writes classifies the
	// already-promoted root as both the issuer and the staged CA, and the
	// undeduplicated list then reported the CA that is doing the signing to the
	// operator as a superseded root — the exact opposite of what "also trusted,
	// so certificates already issued under them keep working" means.
	roots := dedupeCerts(append([]*x509.Certificate{state.Staged, state.Issuer}, state.Superseded...))

	// Key first, and the staged files are removed only once both writes are
	// done, so re-running Activate finishes an activation that was interrupted
	// between them: it recomputes the same roots from the same inputs and
	// rewrites both files.
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
	return writeFileAtomic(filepath.Join(dir, certFileName), encodeBundle(dedupeCerts(roots)), 0o644)
}

// dedupeCerts drops nils and repeats, keeping first-occurrence order.
func dedupeCerts(roots []*x509.Certificate) []*x509.Certificate {
	var unique []*x509.Certificate
	for _, root := range roots {
		if root != nil && !containsCert(unique, root) {
			unique = append(unique, root)
		}
	}
	return unique
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

// mismatchedPairError explains a ca.crt that does not match the ca.key beside
// it, naming the repair when the rotation machinery is what produced the pair.
//
// Usually there is nothing to name: a certificate and a key from different CAs
// is a half-restored backup, and no command in this tree puts it right. But
// [Activate] writes the incoming key and then the widened bundle, so a crash
// between those two leaves exactly this pair — a state re-running Activate
// finishes. Every command goes through [Load] to reach here, so without this an
// operator whose CA is one command from whole is told only that it holds two
// different CAs, which reads like the end of the fleet rather than the middle
// of a rotation.
func mismatchedPairError(dir string, keyPEM []byte) error {
	base := fmt.Errorf("ca: %s does not match the key in %s; this CA directory holds a certificate and a key from different CAs",
		filepath.Join(dir, certFileName), filepath.Join(dir, keyFileName))
	staged, err := readStagedCert(dir)
	if err != nil || staged == nil || checkKeyMatches(keyPEM, staged) != nil {
		return base
	}
	return fmt.Errorf("%w; a CA rotation was interrupted after its new key was written — finish it with `ca rotate --activate`", base)
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
