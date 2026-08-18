package mcpserver

import (
	"fmt"
	"log/slog"
	"os"
	"sync"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/client"
	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver/tools"
)

// credentialPaths locates the mTLS material the control plane presents to
// agents.
type credentialPaths struct {
	caCert string
	cert   string
	key    string
}

// lazyPool builds the gRPC client pool on first use.
//
// The pool needs a CA bundle and a control leaf to exist before it can dial an
// mTLS sandbox, and on a fresh workstation neither does. Building it eagerly
// would mean the MCP server refuses to start on exactly the machine where the
// user most needs it to start and tell them why. Building it lazily means
// fleet_list and fleet_add keep working, and the first call that actually
// has to reach an agent fails with a message naming the missing file.
//
// A missing credential is no longer fatal even then. A fleet whose members all
// run without mTLS has no CA and no control leaf and never will, and on that
// workstation the files are not missing — they are not part of the deployment.
// So the loader's failure is carried into the pool and surfaces only on a dial
// to a sandbox that is *not* marked insecure, where it still names the file and
// the command that creates it. See client.Config.CredentialErr.
//
// Construction failures are not cached: certificates appear while a server is
// running (the user goes and issues one), and a session that has to be
// restarted to notice is a session the user will assume is broken.
type lazyPool struct {
	paths  credentialPaths
	logger *slog.Logger

	mu     sync.Mutex
	pool   *client.Pool
	closed bool
}

var _ tools.Clients = (*lazyPool)(nil)

func newLazyPool(paths credentialPaths, logger *slog.Logger) *lazyPool {
	return &lazyPool{paths: paths, logger: logger}
}

// get returns the pool for one target, building it if this is the first call
// that needs it.
//
// The target is a parameter because whether a credential-less pool is good
// enough depends on where the call is going. A pool built before the operator
// issued themselves a leaf serves every insecure sandbox perfectly and can
// serve no other, so a later call to an mTLS sandbox looks for the credentials
// again rather than reporting the answer from before they existed — which is
// the same "certificates appear while a server is running" case the lazy build
// was written for, one layer down.
func (l *lazyPool) get(t client.Target) (*client.Pool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// A handler can still be running when the session ends and Close runs.
	// Without this it would build a *fresh* pool on the way out — new
	// channels, new background health goroutines, and nothing left to close
	// them, since Server.Close has already dropped its closers.
	if l.closed {
		return nil, fmt.Errorf("the MCP server is shutting down")
	}

	if l.pool != nil {
		if t.Insecure || l.pool.CredentialErr() == nil {
			return l.pool, nil
		}
		// This pool cannot reach an mTLS sandbox and the call is to one. Try
		// the files again before answering with a stale "no certificate".
		if _, _, _, err := l.credentials(); err != nil {
			return l.pool, nil
		}
		// They exist now. The pool being replaced holds only insecure channels
		// — an mTLS dial through it was refused before it reached the network —
		// so closing it costs at most a redial of one of those.
		if err := l.pool.Close(); err != nil {
			l.logger.Debug("closing the credential-less client pool", "error", err)
		}
		l.pool = nil
	}

	cfg := client.Config{Log: l.logger}
	caCert, cert, key, credErr := l.credentials()
	if credErr != nil {
		// Carried, not returned. Every sandbox the registry marks insecure is
		// still reachable, and this becomes the error for the ones that are
		// not. Loading nothing rather than part of a set, because half a
		// credential is a pool that cannot be built at all.
		cfg.CredentialErr = credErr
	} else {
		cfg.CACertPEM, cfg.CertPEM, cfg.KeyPEM = caCert, cert, key
	}

	pool, err := client.NewPool(cfg)
	if err != nil {
		return nil, err
	}
	l.pool = pool
	if credErr != nil {
		l.logger.Debug("gRPC client pool ready without mTLS credentials; only sandboxes registered as insecure can be reached", "error", credErr)
	} else {
		l.logger.Debug("gRPC client pool ready", "ca", l.paths.caCert, "cert", l.paths.cert)
	}
	return pool, nil
}

// credentials loads the three files the control plane presents to an mTLS
// agent, or reports why it could not.
func (l *lazyPool) credentials() (caCert, cert, key []byte, err error) {
	if caCert, err = readCredential(l.paths.caCert, "fleet CA certificate", "fleetctl ca init"); err != nil {
		return nil, nil, nil, err
	}
	if cert, err = readCredential(l.paths.cert, "control certificate", "fleetctl ca sign --profile control"); err != nil {
		return nil, nil, nil, err
	}
	if key, err = readCredential(l.paths.key, "control private key", "fleetctl ca sign --profile control"); err != nil {
		return nil, nil, nil, err
	}
	return caCert, cert, key, nil
}

// readCredential loads a PEM file, turning "no such file" into a message that
// names both the path and the command that creates it.
func readCredential(path, what, remedy string) ([]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the path is this server's own configuration
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no %s at %s: run `%s` on this workstation, then retry", what, path, remedy)
		}
		return nil, fmt.Errorf("read %s at %s: %w", what, path, err)
	}
	return data, nil
}

func (l *lazyPool) Host(t client.Target) (sandboxdv1.HostServiceClient, error) {
	p, err := l.get(t)
	if err != nil {
		return nil, err
	}
	return p.Host(t)
}

func (l *lazyPool) Exec(t client.Target) (sandboxdv1.ExecServiceClient, error) {
	p, err := l.get(t)
	if err != nil {
		return nil, err
	}
	return p.Exec(t)
}

func (l *lazyPool) Files(t client.Target) (sandboxdv1.FileServiceClient, error) {
	p, err := l.get(t)
	if err != nil {
		return nil, err
	}
	return p.Files(t)
}

func (l *lazyPool) Process(t client.Target) (sandboxdv1.ProcessServiceClient, error) {
	p, err := l.get(t)
	if err != nil {
		return nil, err
	}
	return p.Process(t)
}

func (l *lazyPool) Forward(t client.Target) (sandboxdv1.ForwardServiceClient, error) {
	p, err := l.get(t)
	if err != nil {
		return nil, err
	}
	return p.Forward(t)
}

// Health reports cached health, and false when nothing has been dialed —
// including when the pool has never been built. fleet_list without refresh
// must not be the thing that forces a certificate to exist.
func (l *lazyPool) Health(name string) (client.HealthStatus, bool) {
	l.mu.Lock()
	pool := l.pool
	l.mu.Unlock()
	if pool == nil {
		return client.HealthStatus{}, false
	}
	return pool.Health(name)
}

// Remove drops a pooled channel, if the pool exists at all.
func (l *lazyPool) Remove(name string) {
	l.mu.Lock()
	pool := l.pool
	l.mu.Unlock()
	if pool != nil {
		pool.Remove(name)
	}
}

// Close tears the pool down if it was ever built, and stops a later call from
// building another one.
func (l *lazyPool) Close() error {
	l.mu.Lock()
	pool := l.pool
	l.pool = nil
	l.closed = true
	l.mu.Unlock()
	if pool == nil {
		return nil
	}
	return pool.Close()
}
