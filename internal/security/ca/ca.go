package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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

// CA is a loaded fleet certificate authority: its self-signed certificate
// and the private key used to sign leaf certificates.
type CA struct {
	dir     string
	cert    *x509.Certificate
	certPEM []byte
	key     *ecdsa.PrivateKey
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

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: generate CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("ca: create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ca: parse generated CA certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("ca: marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}

	return &CA{dir: dir, cert: cert, certPEM: certPEM, key: priv}, nil
}

// Load reads an existing CA from dir.
func Load(dir string) (*CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, certFileName)) //nolint:gosec // dir is operator-supplied, not attacker input
	if err != nil {
		return nil, fmt.Errorf("ca: read %s: %w", filepath.Join(dir, certFileName), err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, keyFileName)) //nolint:gosec // dir is operator-supplied, not attacker input
	if err != nil {
		return nil, fmt.Errorf("ca: read %s: %w", filepath.Join(dir, keyFileName), err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("ca: %s does not contain a PEM certificate", filepath.Join(dir, certFileName))
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse %s: %w", filepath.Join(dir, certFileName), err)
	}

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

	return &CA{dir: dir, cert: cert, certPEM: certPEM, key: key}, nil
}

// Certificate returns the parsed CA certificate.
func (c *CA) Certificate() *x509.Certificate { return c.cert }

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
