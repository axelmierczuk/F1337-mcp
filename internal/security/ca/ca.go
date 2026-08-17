package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/axelmierczuk/fleet-mcp/internal/fsutil"
)

const (
	certFileName = "ca.crt"
	keyFileName  = "ca.key"

	// caLifetime is long relative to leaf lifetimes: rotating the CA itself
	// is an operator action (a new `ca init --force`), not something this
	// package schedules on its own.
	caLifetime = 10 * 365 * 24 * time.Hour

	// DefaultLeafTTL is used by SignCSR when SignOptions.TTL is zero.
	DefaultLeafTTL = 90 * 24 * time.Hour
)

// ErrNotInitialized reports that a directory holds no certificate authority at
// all, as distinct from holding a broken one.
//
// It exists so every caller can turn "there is no CA yet" into the one sentence
// that helps — the command that makes one — instead of surfacing a bare
// "no such file or directory" naming a path the operator never typed.
var ErrNotInitialized = errors.New("ca: no fleet certificate authority here")

// CA is a loaded fleet certificate authority: the certificate and private key
// used to sign leaves, plus any additional root that must still be trusted.
type CA struct {
	dir     string
	cert    *x509.Certificate
	certPEM []byte
	key     *ecdsa.PrivateKey
	// trusted is every root in ca.crt, the issuing one first. It has more than
	// one entry only during a rotation, while the outgoing and incoming CAs are
	// both live; see rotate.go.
	trusted []*x509.Certificate
}

// Init generates a new ECDSA P-256 CA keypair and self-signed certificate
// under dir, and persists it: the private key at ca.key (mode 0600), the
// certificate at ca.crt, and dir itself at mode 0700.
//
// Init refuses to overwrite an existing CA unless force is true. Silently
// replacing a CA orphans every certificate it ever issued, which is every
// identity in the fleet.
func Init(dir string, force bool) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("ca: create %s: %w", dir, err)
	}
	// MkdirAll does not change the mode of a directory that already existed,
	// so enforce it explicitly. 0700 is intentional here: it's a directory,
	// which needs the execute bit to be traversable, not a secret file.
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // directory mode, not a credential file
		return nil, fmt.Errorf("ca: set permissions on %s: %w", dir, err)
	}

	certPath := filepath.Join(dir, certFileName)
	keyPath := filepath.Join(dir, keyFileName)
	if !force {
		// Both paths are checked, not just the certificate: a directory
		// holding a key but no certificate is a half-restored backup or an
		// interrupted init, and silently overwriting the key there destroys
		// the only copy of the CA's identity just as thoroughly as
		// overwriting a complete CA would.
		for _, path := range []string{certPath, keyPath} {
			if _, err := os.Stat(path); err == nil {
				return nil, fmt.Errorf("ca: %s already exists; use force to overwrite and orphan every certificate it issued", path)
			} else if !os.IsNotExist(err) {
				return nil, fmt.Errorf("ca: stat %s: %w", path, err)
			}
		}
	}

	priv, cert, certPEM, keyPEM, err := generate()
	if err != nil {
		return nil, err
	}

	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}
	// A --force init is a hard reset, so a rotation half-staged into the old CA
	// must not survive it: leaving ca-next.* behind would let a later
	// `ca rotate --activate` promote a root that has nothing to do with the CA
	// now in this directory.
	if err := discardStaged(dir); err != nil {
		return nil, err
	}

	return &CA{dir: dir, cert: cert, certPEM: certPEM, key: priv, trusted: []*x509.Certificate{cert}}, nil
}

// generate produces a fresh self-signed CA: the key, the parsed certificate,
// and the PEM encoding of each. Init and rotation both need exactly this, and a
// second CA that differed from the first in lifetime or key usage would be a
// rotation that quietly changed the terms.
func generate() (key *ecdsa.PrivateKey, cert *x509.Certificate, certPEM, keyPEM []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("ca: generate CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "fleet CA",
			Organization: []string{"fleet"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// Leaves signed by this CA must not themselves be able to sign.
		MaxPathLen:     0,
		MaxPathLenZero: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("ca: create CA certificate: %w", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("ca: parse generated CA certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("ca: marshal CA key: %w", err)
	}

	return priv,
		cert,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		nil
}

// Load reads an existing CA from dir.
//
// ca.crt is read as a bundle rather than as a single certificate: its first
// block is the CA that signs new leaves, and any block after it is a root that
// must still be trusted but no longer issues. That is the state a rotation
// leaves behind while the outgoing and incoming CAs are both live, and it needs
// no change anywhere downstream — the agent's trust store and internal/client's
// both build their pool with AppendCertsFromPEM, which has always taken every
// certificate in the file.
func Load(dir string) (*CA, error) {
	certPath := filepath.Join(dir, certFileName)
	keyPath := filepath.Join(dir, keyFileName)

	certPEM, err := os.ReadFile(certPath) //nolint:gosec // dir is operator-supplied, not attacker input
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrNotInitialized, dir)
		}
		return nil, fmt.Errorf("ca: read %s: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath) //nolint:gosec // dir is operator-supplied, not attacker input
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrNotInitialized, dir)
		}
		return nil, fmt.Errorf("ca: read %s: %w", keyPath, err)
	}

	trusted, err := parseBundle(certPath, certPEM)
	if err != nil {
		return nil, err
	}
	cert := trusted[0]

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("ca: %s does not contain a PEM key", filepath.Join(dir, keyFileName))
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse %s: %w", filepath.Join(dir, keyFileName), err)
	}

	// A certificate beside a key that does not belong to it is a half-restored
	// backup or a directory two CAs were written into. Nothing about that pair
	// is usable: `ca fingerprint` would print — and the operator would then
	// distribute — the fingerprint of a CA this process cannot sign for, and
	// every enrollment would fail deep inside x509.CreateCertificate, after the
	// token was spent. Refusing at load puts the failure where an operator can
	// act on it.
	certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !key.PublicKey.Equal(certPub) {
		return nil, fmt.Errorf("ca: %s does not match the key in %s; this CA directory holds a certificate and a key from different CAs",
			filepath.Join(dir, certFileName), filepath.Join(dir, keyFileName))
	}

	return &CA{dir: dir, cert: cert, certPEM: certPEM, key: key, trusted: trusted}, nil
}

// Certificate returns the parsed CA certificate — the one that signs new
// leaves. During a rotation that is not the only root the fleet trusts; see
// [CA.TrustedRoots].
func (c *CA) Certificate() *x509.Certificate { return c.cert }

// TrustedRoots returns every root in this CA's trust bundle, the issuing one
// first. It has more than one entry only mid-rotation.
func (c *CA) TrustedRoots() []*x509.Certificate {
	out := make([]*x509.Certificate, len(c.trusted))
	copy(out, c.trusted)
	return out
}

// readBundle reads ca.crt as a trust bundle, without the signing key beside it.
//
// [Load] is what almost every caller wants, because a CA that cannot sign is no
// use to them. Rotation is the exception: [Activate] replaces the signing key,
// so it has to be able to read a directory in which the key and the certificate
// have not yet been brought back into agreement.
func readBundle(dir string) ([]*x509.Certificate, error) {
	certPath := filepath.Join(dir, certFileName)
	certPEM, err := os.ReadFile(certPath) //nolint:gosec // dir is operator-supplied, not attacker input
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrNotInitialized, dir)
		}
		return nil, fmt.Errorf("ca: read %s: %w", certPath, err)
	}
	return parseBundle(certPath, certPEM)
}

// parseBundle decodes a trust bundle read from path, refusing an empty one:
// a ca.crt with no certificate in it names no authority at all.
func parseBundle(path string, certPEM []byte) ([]*x509.Certificate, error) {
	trusted, err := decodeBundle(certPEM)
	if err != nil {
		return nil, fmt.Errorf("ca: parse %s: %w", path, err)
	}
	if len(trusted) == 0 {
		return nil, fmt.Errorf("ca: %s does not contain a PEM certificate", path)
	}
	return trusted, nil
}

// decodeBundle parses every CERTIFICATE block in a PEM bundle, in file order.
//
// A block that is not a certificate is an error rather than something to skip:
// this file decides which authorities the whole fleet trusts, and quietly
// ignoring part of it would mean a root the operator believes is distributed is
// silently not.
func decodeBundle(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out, nil
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected %q block in a certificate bundle", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, cert)
	}
}

// encodeBundle renders roots as a PEM bundle, in the order given.
func encodeBundle(roots []*x509.Certificate) []byte {
	var out []byte
	for _, cert := range roots {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return out
}

// CertPEM returns the PEM-encoded CA certificate, suitable for distribution
// as the trust bundle.
func (c *CA) CertPEM() []byte {
	out := make([]byte, len(c.certPEM))
	copy(out, c.certPEM)
	return out
}

// Dir returns the directory this CA is persisted under.
func (c *CA) Dir() string { return c.dir }

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("ca: generate serial number: %w", err)
	}
	return serial, nil
}

// writeFileAtomic writes data to path via a temp file in the same directory
// followed by a rename, so a reader never observes a partially written
// certificate or key.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := fsutil.WriteAtomic(path, data, mode); err != nil {
		return fmt.Errorf("ca: write %s: %w", path, err)
	}
	return nil
}
