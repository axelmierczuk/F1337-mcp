package agent

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/axelmierczuk/sandboxd-mcp/internal/fsutil"
)

// DefaultListen is the address the agent serves gRPC on when the config names
// none. Port 8722 is what the MCP server's registry records by default.
const DefaultListen = "0.0.0.0:8722"

// DefaultClientOU is the organizational unit an incoming client certificate
// must carry. It matches ca.ProfileControl's OU: a leaf issued to another
// agent carries "sandboxd-agent" and is refused.
const DefaultClientOU = "sandboxd-control"

// ErrNoAllowedRoots is returned by Config.Validate when the config confines
// the agent to nothing and the operator has not explicitly accepted that.
//
// An empty root list is not a small misconfiguration: it is the difference
// between a service that can touch a workspace and one that can touch the
// whole filesystem, so it has to be asked for by name.
var ErrNoAllowedRoots = errors.New("agent: allowed_roots is empty, which disables the path jail entirely; pass --no-jail to start anyway")

// Config is the agent's on-disk configuration, as documented in
// examples/agent.yaml.
type Config struct {
	// Name is the sandbox name this host enrolled under. It is informational
	// here — the authoritative identity is the common name in the leaf
	// certificate the agent presents.
	Name string `yaml:"name,omitempty"`

	// Listen is the address the gRPC server binds, as host:port.
	Listen string `yaml:"listen"`

	TLS TLSConfig `yaml:"tls"`

	// AllowedRoots are the absolute paths the jail confines filesystem access
	// to. Empty means no jail, which Validate refuses unless AllowNoJail is
	// set on the ValidateOptions.
	AllowedRoots []string `yaml:"allowed_roots"`

	Exec    ExecConfig    `yaml:"exec"`
	Process ProcessConfig `yaml:"process"`
	Audit   AuditConfig   `yaml:"audit"`
	Log     LogConfig     `yaml:"log"`

	// StateDir is where supervised process records and other daemon state are
	// persisted. It survives uninstall, so re-installing rejoins the fleet
	// with its process history intact.
	StateDir string `yaml:"state_dir,omitempty"`

	// EnrolledAt and Addresses are recorded by `sandboxd-agent enroll` for
	// operator diagnostics.
	EnrolledAt string   `yaml:"enrolled_at,omitempty"`
	Addresses  []string `yaml:"addresses,omitempty"`

	// Legacy top-level certificate paths, written by the M0 enroll command
	// before the TLS block existed. Read-only: Load folds them into TLS so a
	// host enrolled against M0 still starts, and Save never writes them back.
	LegacyCertFile string `yaml:"cert_file,omitempty"`
	LegacyKeyFile  string `yaml:"key_file,omitempty"`
	LegacyCAFile   string `yaml:"ca_file,omitempty"`

	// path records where this config was loaded from, for error messages and
	// for resolving relative paths inside it.
	path string `yaml:"-"`
}

// TLSConfig names the identity the agent serves with and the CA it
// authenticates clients against.
type TLSConfig struct {
	// Certificate is the agent's server-auth leaf, issued during enrollment.
	Certificate string `yaml:"certificate"`
	// PrivateKey is the key generated on this host at enrollment. It has
	// never left the machine.
	PrivateKey string `yaml:"private_key"`
	// CABundle is the fleet CA. Client certificates must chain to it.
	CABundle string `yaml:"ca_bundle"`
	// RequireClientOU is the organizational unit a client leaf must carry on
	// top of chaining to the fleet CA. Empty means DefaultClientOU; it never
	// means "any OU".
	RequireClientOU string `yaml:"require_client_ou"`
}

// ExecConfig bounds one-shot command execution (#7) and is enforced centrally
// by the policy layer (#17).
type ExecConfig struct {
	DefaultTimeout Duration `yaml:"default_timeout"`
	MaxTimeout     Duration `yaml:"max_timeout"`
	MaxOutputBytes int64    `yaml:"max_output_bytes"`
	// DenyCommands and AllowCommands are the optional command policy. Both
	// empty is default-allow, which is honest about what this service is.
	DenyCommands  []string `yaml:"deny_commands"`
	AllowCommands []string `yaml:"allow_commands,omitempty"`
}

// ProcessConfig bounds the background process supervisor (#11–#15).
type ProcessConfig struct {
	MaxConcurrent      int      `yaml:"max_concurrent"`
	MaxLogBytes        int64    `yaml:"max_log_bytes"`
	RingBufferLines    int      `yaml:"ring_buffer_lines"`
	DefaultGracePeriod Duration `yaml:"default_grace_period"`
	MaxFollowDuration  Duration `yaml:"max_follow_duration"`
}

// AuditConfig configures the forensic record written by #17.
type AuditConfig struct {
	Path    string `yaml:"path"`
	Enabled bool   `yaml:"enabled"`
	// Required fails an RPC whose audit record could not be written, rather
	// than proceeding unrecorded.
	Required bool `yaml:"required,omitempty"`
	// MaxBytes is the size at which the log rotates, and RetainSegments how
	// many rotated segments are kept.
	MaxBytes       int64 `yaml:"max_bytes,omitempty"`
	RetainSegments int   `yaml:"retain_segments,omitempty"`
}

// LogConfig configures the daemon's own structured logging.
type LogConfig struct {
	// Level is one of debug, info, warn, error.
	Level string `yaml:"level,omitempty"`
	// Format is "text" or "json".
	Format string `yaml:"format,omitempty"`
}

// Duration is a time.Duration that round-trips through YAML as the string
// form examples/agent.yaml uses ("120s", "1h"). gopkg.in/yaml.v3 has no
// built-in duration type, and decoding these as integer nanoseconds would
// make every value in the shipped example wrong by nine orders of magnitude.
type Duration time.Duration

// UnmarshalYAML decodes a duration string ("120s", "1h") or a bare number,
// which is read as seconds.
//
// The bare-number case is not permissiveness for its own sake: yaml.v3 decodes
// an unquoted 30 into a string just as happily as into a number, so without it
// an operator who wrote `default_timeout: 30` gets "missing unit in duration"
// rather than the two minutes they plainly meant.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("agent: %q is not a duration", node.Value)
	}
	if parsed, err := time.ParseDuration(s); err == nil {
		*d = Duration(parsed)
		return nil
	}
	secs, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return fmt.Errorf("agent: %q is not a duration: want a value like \"120s\" or \"1h\", or a bare number of seconds", s)
	}
	*d = Duration(time.Duration(secs * float64(time.Second)))
	return nil
}

// MarshalYAML writes the duration back in its string form.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// Duration returns the value as a time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// String renders the duration.
func (d Duration) String() string { return time.Duration(d).String() }

// Path returns the file this config was loaded from, or "" for one built in
// memory.
func (c *Config) Path() string { return c.path }

// Load reads and validates the agent config at path.
//
// Relative certificate, key, CA, state and audit paths are resolved against
// the config file's own directory: an operator who moves an enrollment
// directory wholesale should not have to rewrite every path inside it.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is operator-supplied configuration, not caller input
	if err != nil {
		return nil, fmt.Errorf("agent: read config %s: %w", path, err)
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("agent: parse config %s: %w", path, err)
	}
	cfg.path = path
	cfg.applyDefaults()
	cfg.resolveRelativePaths(filepath.Dir(path))
	return cfg, nil
}

// Save writes the config to path atomically at mode 0600. The file names the
// private key and the roots the agent will serve; it is not world-readable.
//
// Defaults are applied before writing, so the file shows the limits that will
// actually be in force. Writing the zero values out instead would produce a
// config reading `max_output_bytes: 0` on an agent whose real cap is 2 MiB —
// an operator would have no way to tell an unset field from a disabled one.
func (c *Config) Save(path string) error {
	// The legacy aliases exist only so an M0-era file still loads. Writing
	// them back would keep two sources of truth for the same three paths.
	out := *c
	out.applyDefaults()
	out.LegacyCertFile, out.LegacyKeyFile, out.LegacyCAFile = "", "", ""
	data, err := yaml.Marshal(&out)
	if err != nil {
		return fmt.Errorf("agent: encode config: %w", err)
	}
	if err := fsutil.WriteAtomic(path, data, 0o600); err != nil {
		return fmt.Errorf("agent: write config %s: %w", path, err)
	}
	c.path = path
	return nil
}

// applyDefaults fills in every field the shipped example documents a default
// for, and folds the M0 top-level certificate paths into the TLS block.
func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.TLS.Certificate == "" {
		c.TLS.Certificate = c.LegacyCertFile
	}
	if c.TLS.PrivateKey == "" {
		c.TLS.PrivateKey = c.LegacyKeyFile
	}
	if c.TLS.CABundle == "" {
		c.TLS.CABundle = c.LegacyCAFile
	}
	if c.TLS.RequireClientOU == "" {
		c.TLS.RequireClientOU = DefaultClientOU
	}
	if c.Exec.DefaultTimeout <= 0 {
		c.Exec.DefaultTimeout = Duration(120 * time.Second)
	}
	if c.Exec.MaxTimeout <= 0 {
		c.Exec.MaxTimeout = Duration(3600 * time.Second)
	}
	if c.Exec.MaxOutputBytes <= 0 {
		c.Exec.MaxOutputBytes = 2 * 1024 * 1024
	}
	if c.Process.MaxConcurrent <= 0 {
		c.Process.MaxConcurrent = 32
	}
	if c.Process.MaxLogBytes <= 0 {
		c.Process.MaxLogBytes = 32 * 1024 * 1024
	}
	if c.Process.RingBufferLines <= 0 {
		c.Process.RingBufferLines = 2000
	}
	if c.Process.DefaultGracePeriod <= 0 {
		c.Process.DefaultGracePeriod = Duration(10 * time.Second)
	}
	if c.Process.MaxFollowDuration <= 0 {
		c.Process.MaxFollowDuration = Duration(60 * time.Second)
	}
	if c.Audit.MaxBytes <= 0 {
		c.Audit.MaxBytes = 64 * 1024 * 1024
	}
	if c.Audit.RetainSegments <= 0 {
		c.Audit.RetainSegments = 5
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "text"
	}
	if c.StateDir == "" {
		c.StateDir = DefaultStateDir()
	}
	if c.Audit.Path == "" {
		c.Audit.Path = filepath.Join(DefaultLogDir(), "audit.jsonl")
	}
}

// resolveRelativePaths makes every path in the config absolute relative to
// base, which is the config file's directory.
func (c *Config) resolveRelativePaths(base string) {
	for _, p := range []*string{
		&c.TLS.Certificate, &c.TLS.PrivateKey, &c.TLS.CABundle,
		&c.StateDir, &c.Audit.Path,
	} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
	for i, root := range c.AllowedRoots {
		if root != "" && !filepath.IsAbs(root) {
			c.AllowedRoots[i] = filepath.Join(base, root)
		}
	}
}

// ValidateOptions carries the decisions an operator makes on the command line
// rather than in the config file.
type ValidateOptions struct {
	// AllowNoJail permits an empty allowed_roots list. It is `serve
	// --no-jail`, and the daemon logs a warning on every start when it is set.
	AllowNoJail bool
}

// Validate reports whether the config can actually run a daemon.
func (c *Config) Validate(opts ValidateOptions) error {
	var problems []string

	if c.Listen == "" {
		problems = append(problems, "listen is empty")
	}
	if c.TLS.Certificate == "" {
		problems = append(problems, "tls.certificate is not set")
	}
	if c.TLS.PrivateKey == "" {
		problems = append(problems, "tls.private_key is not set")
	}
	if c.TLS.CABundle == "" {
		problems = append(problems, "tls.ca_bundle is not set; there is no plaintext mode")
	}
	if c.TLS.RequireClientOU == "" {
		problems = append(problems, "tls.require_client_ou is empty; an empty OU would accept any leaf the fleet CA ever signed, including another agent's")
	}
	for _, root := range c.AllowedRoots {
		if !filepath.IsAbs(root) {
			problems = append(problems, fmt.Sprintf("allowed root %q is not absolute", root))
		}
	}
	if c.Exec.MaxTimeout > 0 && c.Exec.DefaultTimeout > c.Exec.MaxTimeout {
		problems = append(problems, fmt.Sprintf("exec.default_timeout (%s) exceeds exec.max_timeout (%s)",
			c.Exec.DefaultTimeout, c.Exec.MaxTimeout))
	}
	if _, err := parseLevel(c.Log.Level); err != nil {
		problems = append(problems, err.Error())
	}

	if len(problems) > 0 {
		return fmt.Errorf("agent: invalid config %s: %s", c.describe(), strings.Join(problems, "; "))
	}

	// Checked last and on its own, so the caller can match on it: this is the
	// one failure with a documented override rather than a typo to fix.
	if len(c.AllowedRoots) == 0 && !opts.AllowNoJail {
		return ErrNoAllowedRoots
	}
	return nil
}

func (c *Config) describe() string {
	if c.path == "" {
		return "(in memory)"
	}
	return c.path
}

// Logger builds the daemon's slog logger from the config, writing to w.
func (c *Config) Logger(w *os.File) (*slog.Logger, error) {
	level, err := parseLevel(c.Log.Level)
	if err != nil {
		return nil, err
	}
	opts := &slog.HandlerOptions{Level: level}
	if strings.EqualFold(c.Log.Format, "json") {
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	}
	return slog.New(slog.NewTextHandler(w, opts)), nil
}

func parseLevel(name string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("log.level %q is not one of debug, info, warn, error", name)
	}
}
