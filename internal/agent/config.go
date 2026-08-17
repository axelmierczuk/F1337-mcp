package agent

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/axelmierczuk/fleet-mcp/internal/fsutil"
)

// DefaultListen is the address the agent serves gRPC on when the config names
// none. Port 8722 is what the MCP server's registry records by default.
const DefaultListen = "0.0.0.0:8722"

// DefaultClientOU is the organizational unit an incoming client certificate
// must carry. It matches ca.ProfileControl's OU: a leaf issued to another
// agent carries "sandboxd-agent" and is refused.
//
// It keeps its pre-rebrand name because it is matched against certificates
// already issued to enrolled agents; see ca.Profile.OrganizationalUnit.
const DefaultClientOU = "sandboxd-control"

// ErrNoAllowedRoots is returned by Config.Validate when the jail is enforced,
// the config confines the agent to nothing, and the operator has not explicitly
// accepted that.
//
// On an agent with exec disabled, an empty root list is not a small
// misconfiguration: it is the difference between a service that can touch a
// workspace and one that can touch the whole filesystem, so it has to be asked
// for by name. On an exec-enabled agent it is not a condition at all — see
// Config.JailEnforced.
var ErrNoAllowedRoots = errors.New("agent: exec is disabled and allowed_roots is empty, which leaves no path jail; pass --no-jail to start anyway")

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
	// to.
	//
	// They apply only to an agent with exec disabled. See ExecConfig.Enabled:
	// a caller who can run commands does not need FileService to reach a path,
	// so on an exec-enabled agent these are ignored rather than enforced
	// half-way. When they do apply, an empty list means no jail, which Validate
	// refuses unless AllowNoJail is set on the ValidateOptions.
	AllowedRoots []string `yaml:"allowed_roots"`

	Exec    ExecConfig    `yaml:"exec"`
	Process ProcessConfig `yaml:"process"`
	Forward ForwardConfig `yaml:"forward"`
	Audit   AuditConfig   `yaml:"audit"`
	Log     LogConfig     `yaml:"log"`

	// StateDir is where supervised process records and other daemon state are
	// persisted. It survives uninstall, so re-installing rejoins the fleet
	// with its process history intact.
	StateDir string `yaml:"state_dir,omitempty"`

	// EnrolledAt and Addresses are recorded by `fleet-agent enroll` for
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
	// Enabled turns ExecService on. It defaults to true — running commands is
	// what this product is for — and turning it off is the only configuration
	// in which the path jail is a boundary rather than a decoration.
	//
	// A pointer because the default is true: a plain bool cannot tell
	// "enabled: false" from a key the operator never wrote.
	Enabled *bool `yaml:"enabled,omitempty"`

	DefaultTimeout Duration `yaml:"default_timeout"`
	MaxTimeout     Duration `yaml:"max_timeout"`
	MaxOutputBytes int64    `yaml:"max_output_bytes"`
	// DenyCommands and AllowCommands are the optional command policy. Both
	// empty is default-allow, which is honest about what this service is.
	DenyCommands  []string `yaml:"deny_commands"`
	AllowCommands []string `yaml:"allow_commands,omitempty"`
}

// IsEnabled reports whether ExecService is on. An unset field means yes.
func (e ExecConfig) IsEnabled() bool { return e.Enabled == nil || *e.Enabled }

// JailEnforced reports whether the path jail actually confines this agent.
//
// It does so only when exec is disabled. With ExecService available, a caller
// never has to go through FileService to reach a path:
//
//	argv: ["sh", "-c", "echo pwned > /etc/passwd"]
//
// needs no shell flag and no write RPC, and `tee`, `cp`, `dd` and `python -c`
// all do the same job. A path check that stops nobody while looking like a
// security control is worse than no check, because it is what operators plan
// around — so the jail is wired in only where it is real.
func (c *Config) JailEnforced() bool { return !c.Exec.IsEnabled() }

// ProcessConfig bounds the background process supervisor (#11–#15).
type ProcessConfig struct {
	// MaxConcurrent is an agent-wide cap, not a per-service one. It is spelled
	// under process.* because supervised processes are what it was written
	// for, but what it bounds is how many processes this agent has running on
	// somebody's host, and that is one quantity however many services can
	// spawn one. Every such service takes its slots from the single limiter
	// built from it; see Deps.Policy.
	MaxConcurrent      int      `yaml:"max_concurrent"`
	MaxLogBytes        int64    `yaml:"max_log_bytes"`
	RingBufferLines    int      `yaml:"ring_buffer_lines"`
	DefaultGracePeriod Duration `yaml:"default_grace_period"`
	MaxFollowDuration  Duration `yaml:"max_follow_duration"`
}

// ForwardConfig bounds the port forwarder (#26).
//
// The one setting that matters here is AllowedHosts, and its default of "none"
// is a security decision rather than a conservative-looking blank. See the
// field.
type ForwardConfig struct {
	// Enabled turns ForwardService on. It defaults to true — forwarding a dev
	// server's port to the workstation is what closes the remote dev loop —
	// and an operator who wants the agent to do no networking on a caller's
	// behalf sets it to false.
	//
	// A pointer because the default is true: a plain bool cannot tell
	// "enabled: false" from a key the operator never wrote.
	Enabled *bool `yaml:"enabled,omitempty"`

	// AllowedHosts are the non-loopback hosts a forward may target on this
	// host's network. It is empty by default, and that default is the point.
	//
	// A forward to loopback reaches only what this agent's own machine is
	// serving. A forward to an arbitrary host reaches anything the machine's
	// network reaches — so an agent with no restriction is a general-purpose
	// network pivot into whatever it sits in, available to anyone who can call
	// it. On a fleet spanning a laptop, a home lab and a cloud VPC that is a
	// genuinely bad default, and it is bad in a way nobody notices until it is
	// used, because forwarding to loopback works perfectly without it.
	//
	// An entry is a hostname, an IP address, or a CIDR block. A hostname is
	// matched literally against the requested host, case-insensitively. An
	// address or a block is matched against the addresses the target resolves
	// to, so listing 10.0.4.7 permits it under any name it answers to — the
	// packets reach the same machine either way, which is the thing the
	// operator actually decided.
	//
	// Anything not matched must resolve entirely to loopback addresses or the
	// connection is refused. "Entirely" is the whole check: a name resolving to
	// both a permitted address and one outside the list is refused, because
	// passing on the strength of whichever came back first is not a decision
	// anyone made.
	//
	// This is the `allow_hosts` of #45, under the name #26 shipped it as. One
	// list, not two: an operator deciding which network this agent may reach is
	// making one decision, and a second list would let a host be reachable one
	// way and not the other for no reason a reader could recover.
	AllowedHosts []string `yaml:"allowed_hosts,omitempty"`

	// SocksEnabled permits SOCKS5-proxied connections through this agent —
	// `fleetctl socks` and fleet_socks. It defaults to false, and that default
	// is the security posture of the whole feature.
	//
	// A port forward reaches a host and port the caller named up front. A proxy
	// reaches whatever a client asks for, connection by connection, which makes
	// the agent a general-purpose route into its network rather than a route to
	// one service on it. Those are different grants, so they are different
	// settings: an agent with AllowedHosts set still forwards to exactly the
	// hosts it always did, and serves no proxy at all, until an operator turns
	// this on.
	//
	// With it on and AllowedHosts empty, a proxied connection may reach any host
	// this machine can. That is a legitimate choice for a throwaway lab box and
	// a bad one everywhere else, so the agent says so in its log at every start.
	//
	// A plain bool, unlike Enabled above: the default is false, so a key nobody
	// wrote and a key written as false mean the same thing and there is nothing
	// for a pointer to distinguish.
	SocksEnabled bool `yaml:"socks_enabled,omitempty"`

	// MaxConnections bounds the concurrent forwarded connections this agent
	// will carry. Zero means the default.
	MaxConnections int `yaml:"max_connections,omitempty"`

	// DialTimeout bounds the connection to the sandbox-side port. Zero means
	// the default.
	DialTimeout Duration `yaml:"dial_timeout,omitempty"`
}

// IsEnabled reports whether ForwardService is on. An unset field means yes.
func (f ForwardConfig) IsEnabled() bool { return f.Enabled == nil || *f.Enabled }

// HostAllowed reports whether host is named literally on the allow list.
//
// It answers only that question. A host that is not listed is not thereby
// refused — it is refused unless it resolves entirely to loopback or to
// addresses [ForwardConfig.AddressAllowed] accepts, which is the caller's
// check, because it needs a resolver and a context.
func (f ForwardConfig) HostAllowed(host string) bool {
	for _, allowed := range f.AllowedHosts {
		if strings.EqualFold(strings.TrimSpace(allowed), strings.TrimSpace(host)) {
			return true
		}
	}
	return false
}

// AddressAllowed reports whether ip is covered by an address or CIDR entry on
// the allow list.
//
// Hostname entries are ignored here on purpose. Resolving them to compare
// addresses would make the answer depend on what DNS said at this instant, for
// a name the operator wrote precisely because the name is the stable part —
// and it would turn one allow-list lookup into a resolver call per entry per
// connection. A name is matched as a name, by [ForwardConfig.HostAllowed]; an
// address is matched as an address, here.
//
// A malformed entry matches nothing. It cannot be rejected at load time
// without turning a typo in one line into a daemon that will not start, and
// failing open on an allow-list entry nobody can parse is the one direction
// that must not happen — so it is dropped here and reported at startup by
// [ForwardConfig.MalformedAllowedHosts].
func (f ForwardConfig) AddressAllowed(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, allowed := range f.AllowedHosts {
		entry := strings.TrimSpace(allowed)
		if _, block, err := net.ParseCIDR(entry); err == nil {
			if block.Contains(ip) {
				return true
			}
			continue
		}
		if listed := net.ParseIP(entry); listed != nil && listed.Equal(ip) {
			return true
		}
	}
	return false
}

// MalformedAllowedHosts returns the allow-list entries that are neither a
// usable CIDR block nor anything a hostname may legally be.
//
// An entry like "10.0.0.0/33" or "10.0.0.0 /8" parses as neither a block nor an
// address, so it silently becomes a hostname that no request will ever match —
// an allow list that reads as permitting a subnet and permits nothing. That is
// a configuration worth a line in the log, and it is not worth refusing to
// start over: the failure is closed, and an agent that will not boot because of
// a stray character in a setting it may never use is a worse outcome than one
// that boots and says so.
func (f ForwardConfig) MalformedAllowedHosts() []string {
	var bad []string
	for _, allowed := range f.AllowedHosts {
		entry := strings.TrimSpace(allowed)
		if entry == "" {
			bad = append(bad, allowed)
			continue
		}
		// Only entries that look like an attempt at a block or an address are
		// judged. Anything else is a hostname, and this package does not get to
		// have an opinion about what names an operator's resolver knows.
		if strings.ContainsAny(entry, "/ ") || looksNumeric(entry) {
			if _, _, err := net.ParseCIDR(entry); err == nil {
				continue
			}
			if net.ParseIP(entry) != nil {
				continue
			}
			bad = append(bad, allowed)
		}
	}
	return bad
}

// WidenedAllowedHosts returns the allow-list entries whose CIDR block covers
// more than the address written in front of the mask, each rendered as the
// block it actually permits.
//
// "10.0.4.7/24" is a valid block and a plausible way to write "this one host",
// and it permits two hundred and fifty-four others. Nothing in
// [ForwardConfig.MalformedAllowedHosts] can see it — net.ParseCIDR succeeds,
// because the entry is not malformed, only wider than it reads. The cost of
// getting it wrong is an operator who believes they narrowed the pivot to one
// machine and narrowed it to a subnet, which is exactly the mistake this whole
// setting exists to prevent.
//
// So it is a line in the log rather than a refusal to start: the semantics are
// the ones every other tool applies to a CIDR, and an agent that would not boot
// over a mask an operator meant is worse than one that boots and says what the
// mask means.
func (f ForwardConfig) WidenedAllowedHosts() []string {
	var widened []string
	for _, allowed := range f.AllowedHosts {
		entry := strings.TrimSpace(allowed)
		ip, block, err := net.ParseCIDR(entry)
		if err != nil || ip.Equal(block.IP) {
			continue
		}
		widened = append(widened, fmt.Sprintf("%s permits all of %s", entry, block.String()))
	}
	return widened
}

// looksNumeric reports whether an entry is made only of the characters an IP
// address is spelled with, which is what makes "10.0.4.256" a broken address
// rather than an unusual hostname.
func looksNumeric(entry string) bool {
	for _, r := range entry {
		if (r < '0' || r > '9') && r != '.' && r != ':' {
			return false
		}
	}
	return true
}

// SocksAllowsAnyHost reports the one configuration in which this agent is an
// unrestricted network pivot: proxying on, with nothing narrowing where it may
// go.
func (f ForwardConfig) SocksAllowsAnyHost() bool {
	return f.SocksEnabled && len(f.AllowedHosts) == 0
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
	if c.Exec.Enabled == nil {
		enabled := true
		c.Exec.Enabled = &enabled
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
	if c.Forward.Enabled == nil {
		enabled := true
		c.Forward.Enabled = &enabled
	}
	if c.Forward.MaxConnections <= 0 {
		c.Forward.MaxConnections = 64
	}
	if c.Forward.DialTimeout <= 0 {
		c.Forward.DialTimeout = Duration(10 * time.Second)
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
	//
	// It only bites when the jail is enforced. On an exec-enabled agent there
	// is no jail for allowed_roots to be missing from, so refusing to start
	// would be demanding a setting that changes nothing.
	if c.JailEnforced() && len(c.AllowedRoots) == 0 && !opts.AllowNoJail {
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
