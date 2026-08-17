// Package mcpserver hosts the MCP server: transport setup, tool
// registration, and the wiring that connects the fleet registry and the gRPC
// client pool to the tool handlers.
//
// # stdout is reserved for JSON-RPC
//
// The server speaks newline-delimited JSON-RPC over stdin and stdout. Every
// log line, warning, and diagnostic goes to stderr. A single stray write to
// stdout corrupts the protocol stream, and the symptom the user sees is a
// client that mysteriously disconnects — not an error message naming the
// print statement that caused it. Nothing in this package or its
// dependencies writes to stdout, and a test asserts it during a debug-level
// run.
package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver/selection"
	"github.com/axelmierczuk/fleet-mcp/internal/mcpserver/tools"
	"github.com/axelmierczuk/fleet-mcp/internal/registry"
	"github.com/axelmierczuk/fleet-mcp/internal/version"
)

// ServerName is the implementation name reported at initialize.
const ServerName = "sandboxd"

// Instructions is what a client that surfaces server instructions shows the
// model. It carries the select-then-act workflow once, here, instead of
// repeating it in nineteen tool descriptions that are paid for on every
// request.
const Instructions = `sandboxd gives you tools on remote development machines ("sandboxes") over mTLS.

Select before you act. Call sandbox_list to see the fleet, then sandbox_select to
choose a target; every later call acts on that selection. Pass "sandbox" on a call
to override it for that call only. Nothing is ever targeted implicitly: with no
selection and no argument a call fails with the list of available sandboxes, even
when the fleet has exactly one member.

Every result carries "sandbox", the host that actually served the call. Check it
if you are unsure where you are running.

Paths are on the sandbox, not on this workstation. sandbox_select and
sandbox_info report the roots the agent allows writes under; if they instead
report "unconfined", the agent enforces no path jail and every path is writable,
which is not the same as none being writable. Use sandbox_process_start, not
sandbox_exec, for anything meant to outlive the call.

Registering a sandbox does not enroll it: minting credentials is an operator
action via fleetctl.`

// Options configures a Server. The zero value is usable: every path defaults
// under the user's config directory.
type Options struct {
	// ConfigDir overrides where the registry and credentials are read from.
	// Empty resolves through registry.ConfigDir, which honours
	// SANDBOXD_CONFIG_DIR.
	ConfigDir string
	// RegistryPath overrides the registry file. Empty is
	// <config dir>/registry.yaml.
	RegistryPath string
	// CACertPath is the fleet CA bundle. Empty is <config dir>/ca/ca.crt.
	CACertPath string
	// CertPath and KeyPath are the control leaf this server presents to
	// agents. Empty is <config dir>/control.crt and control.key.
	CertPath string
	KeyPath  string

	// LogLevel is the minimum level written to LogWriter.
	LogLevel slog.Level
	// LogWriter receives every log line. Nil means stderr. It must never be
	// stdout.
	LogWriter io.Writer

	// Clients overrides the gRPC client pool. Tests set it to a fake so they
	// do not have to mint a certificate chain to exercise a tool.
	Clients tools.Clients

	// FallbackIdentity overrides the client identity used when a request
	// carries none.
	FallbackIdentity string

	// ProbeTimeout bounds one health probe. Zero uses the tools default.
	ProbeTimeout time.Duration
	// CallTimeout bounds a unary call with no timeout of its own. Zero uses
	// the tools default.
	CallTimeout time.Duration
}

// Server is a configured sandboxd MCP server, not yet connected to a
// transport.
type Server struct {
	mcp       *mcp.Server
	registrar *tools.Registrar
	fleet     *registry.Registry
	clients   tools.Clients
	logger    *slog.Logger

	// closeMu guards closers. Run closes the server from a defer, and a
	// caller that drives Run in a goroutine will reasonably also write
	// `defer server.Close()` — so two closes can genuinely overlap, and
	// read-modify-writing the slice without a lock is a data race.
	closeMu sync.Mutex
	closers []func() error
}

// New builds a server: opens the registry, prepares the client pool, and
// registers every tool.
//
// It deliberately does not require credentials to exist. A workstation that
// has run `fleetctl ca init` but not yet issued itself a control leaf can
// still list, add and remove sandboxes; the missing certificate surfaces as a
// tool error on the first call that actually needs to reach an agent, naming
// the file and the command that creates it. Failing at startup instead would
// give the user a server that will not start and no way to ask it why.
func New(opts Options) (*Server, error) {
	logger := NewLogger(opts.LogWriter, opts.LogLevel)

	dir := opts.ConfigDir
	if dir == "" {
		var err error
		if dir, err = registry.ConfigDir(); err != nil {
			return nil, err
		}
	}

	registryPath := opts.RegistryPath
	if registryPath == "" {
		registryPath = filepath.Join(dir, "registry.yaml")
	}
	fleet, err := registry.Open(registryPath)
	if err != nil {
		return nil, err
	}

	s := &Server{fleet: fleet, logger: logger}

	s.clients = opts.Clients
	if s.clients == nil {
		pool := newLazyPool(credentialPaths{
			caCert: orDefault(opts.CACertPath, filepath.Join(dir, "ca", "ca.crt")),
			cert:   orDefault(opts.CertPath, filepath.Join(dir, "control.crt")),
			key:    orDefault(opts.KeyPath, filepath.Join(dir, "control.key")),
		}, logger)
		s.clients = pool
		s.closers = append(s.closers, pool.Close)
	}

	resolver := selection.NewResolver(fleet, &selection.Options{FallbackIdentity: opts.FallbackIdentity})

	s.mcp = mcp.NewServer(&mcp.Implementation{
		Name:        ServerName,
		Title:       "sandboxd",
		Version:     version.Version,
		Description: "Development tools on remote sandbox machines.",
	}, &mcp.ServerOptions{
		Instructions: Instructions,
		Logger:       logger,
	})

	s.registrar = tools.Register(s.mcp, tools.Deps{
		Fleet:        fleet,
		Clients:      s.clients,
		Resolver:     resolver,
		Logger:       logger,
		ProbeTimeout: opts.ProbeTimeout,
		CallTimeout:  opts.CallTimeout,
	})
	// Some tools own state that outlives the call that created it —
	// sandbox_forward's local listeners, which is the whole point of a
	// forward. Released here, so a listener cannot survive the process that
	// opened it and hold its port against the next one.
	s.closers = append(s.closers, s.registrar.Close)

	logger.Debug("mcp server ready",
		"registry", registryPath, "tools", len(s.registrar.Registrations()))
	return s, nil
}

// Run serves MCP over stdio until stdin closes or ctx is cancelled.
//
// The client going away closes stdin, which ends the session and returns
// here; the process must not outlive its client, because nothing will ever
// connect to it again.
func (s *Server) Run(ctx context.Context) error {
	defer func() {
		if err := s.Close(); err != nil {
			s.logger.Warn("shutdown", "error", err)
		}
	}()

	s.logger.Info("serving MCP over stdio", "version", version.Version)
	if err := s.mcp.Run(ctx, &mcp.StdioTransport{}); err != nil && !isNormalDisconnect(err) {
		return fmt.Errorf("mcpserver: %w", err)
	}
	s.logger.Info("client disconnected, shutting down")
	return nil
}

// codeServerClosing is the JSON-RPC error code the SDK reports when the
// session ends because the connection went away.
const codeServerClosing = -32004

// isNormalDisconnect reports whether err is the ordinary end of a stdio
// session rather than a failure.
//
// The client closing its end of the pipe is how every stdio session ends, and
// the SDK surfaces it as an error. Passing that through would mean the binary
// exits non-zero every single time it is used correctly, which trains the
// user to ignore its exit code — and then to miss the one time it means
// something.
func isNormalDisconnect(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) || errors.Is(err, mcp.ErrConnectionClosed) {
		return true
	}
	var wire *jsonrpc.Error
	return errors.As(err, &wire) && wire.Code == codeServerClosing
}

// Connect serves one session over t, for callers that supply their own
// transport (tests, and any future non-stdio front end).
func (s *Server) Connect(ctx context.Context, t mcp.Transport) (*mcp.ServerSession, error) {
	return s.mcp.Connect(ctx, t, nil)
}

// Registrations returns every tool registered, for tests that walk them.
func (s *Server) Registrations() []tools.Registration { return s.registrar.Registrations() }

// Close releases the client pool. It is safe to call more than once and from
// more than one goroutine; every call after the first is a no-op.
func (s *Server) Close() error {
	s.closeMu.Lock()
	closers := s.closers
	s.closers = nil
	s.closeMu.Unlock()

	// In reverse, so what was built last is released first. The client pool is
	// registered before the tools that use it, and the registrar's own Close
	// joins the goroutines carrying forwarded connections over the pool's
	// channels — closing the pool underneath them first would drop every one of
	// those connections with an RPC error on the way out, and would leave the
	// forward's listener accepting new ones onto a channel that is already
	// gone. Releasing in the order things were created is a shutdown that tears
	// the transport out from under its users.
	var firstErr error
	for i := len(closers) - 1; i >= 0; i-- {
		if err := closers[i](); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// NewLogger returns a logger writing to w, or to stderr when w is nil.
//
// Never pass os.Stdout: it carries the JSON-RPC stream.
func NewLogger(w io.Writer, level slog.Level) *slog.Logger {
	if w == nil {
		w = os.Stderr
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
}

func orDefault(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
