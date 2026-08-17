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
// The pool needs a CA bundle and a control leaf to exist before it can be
// constructed, and on a fresh workstation neither does. Building it eagerly
// would mean the MCP server refuses to start on exactly the machine where the
// user most needs it to start and tell them why. Building it lazily means
// sandbox_list and sandbox_add keep working, and the first call that actually
// has to reach an agent fails with a message naming the missing file.
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

// get returns the pool, building it if this is the first call that needs it.
func (l *lazyPool) get() (*client.Pool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pool != nil {
		return l.pool, nil
	}
	// A handler can still be running when the session ends and Close runs.
	// Without this it would build a *fresh* pool on the way out — new
	// channels, new background health goroutines, and nothing left to close
	// them, since Server.Close has already dropped its closers.
	if l.closed {
		return nil, fmt.Errorf("the MCP server is shutting down")
	}

	caCert, err := readCredential(l.paths.caCert, "fleet CA certificate", "fleetctl ca init")
	if err != nil {
		return nil, err
	}
	cert, err := readCredential(l.paths.cert, "control certificate", "fleetctl ca sign --profile control")
	if err != nil {
		return nil, err
	}
	key, err := readCredential(l.paths.key, "control private key", "fleetctl ca sign --profile control")
	if err != nil {
		return nil, err
	}

	pool, err := client.NewPool(client.Config{CACertPEM: caCert, CertPEM: cert, KeyPEM: key})
	if err != nil {
		return nil, err
	}
	l.pool = pool
	l.logger.Debug("gRPC client pool ready", "ca", l.paths.caCert, "cert", l.paths.cert)
	return pool, nil
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

func (l *lazyPool) Host(name, address string) (sandboxdv1.HostServiceClient, error) {
	p, err := l.get()
	if err != nil {
		return nil, err
	}
	return p.Host(name, address)
}

func (l *lazyPool) Exec(name, address string) (sandboxdv1.ExecServiceClient, error) {
	p, err := l.get()
	if err != nil {
		return nil, err
	}
	return p.Exec(name, address)
}

func (l *lazyPool) Files(name, address string) (sandboxdv1.FileServiceClient, error) {
	p, err := l.get()
	if err != nil {
		return nil, err
	}
	return p.Files(name, address)
}

func (l *lazyPool) Process(name, address string) (sandboxdv1.ProcessServiceClient, error) {
	p, err := l.get()
	if err != nil {
		return nil, err
	}
	return p.Process(name, address)
}

func (l *lazyPool) Forward(name, address string) (sandboxdv1.ForwardServiceClient, error) {
	p, err := l.get()
	if err != nil {
		return nil, err
	}
	return p.Forward(name, address)
}

// Health reports cached health, and false when nothing has been dialed —
// including when the pool has never been built. sandbox_list without refresh
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
