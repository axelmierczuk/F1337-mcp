package exec

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// A command runs with a documented base environment plus whatever the request
// asks for on top of it.
//
// # Why there is a base at all
//
// The daemon's own environment is not inherited. It holds whatever the thing
// that installed the service was holding — a CI runner's registry token, an
// operator's AWS credentials, a GITHUB_TOKEN from the shell that ran the
// installer — and handing that to every command a model asks for is a
// credential leak with a remote trigger. The systemd unit and the launchd job
// this repository installs do not scrub it either, and neither would a
// hand-rolled `nohup fleet-agent &`.
//
// So the base is an allowlist, and each entry earns its place:
//
//   - PATH, or nothing runs. Taken from the daemon so that a host's toolchain
//     installs are visible, falling back to a platform default when the
//     service manager started the daemon without one.
//   - HOME, because every toolchain caches under it — ~/.cache/go-build,
//     ~/.npm, ~/.cargo — and a build with no HOME either fails or writes into
//     whatever it falls back to, usually /.
//   - TMPDIR, so temporary files land where the operator's disk layout and
//     systemd's PrivateTmp expect them rather than in the process's idea of /tmp.
//   - The locale variables, so tools that format output for a terminal agree
//     with the caller about encoding. Passed through only when set; this
//     package does not invent a locale.
//
// Windows adds the variables a process genuinely cannot start without; see
// basePassthrough there.

// localeVars are passed through from the daemon when set. They describe how to
// render text, and nothing else.
var localeVars = []string{"LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES"}

// BaseEnv returns the documented base environment for this host.
func BaseEnv() []string { return buildBaseEnv(os.Getenv) }

// buildBaseEnv is BaseEnv with the lookup injected, so the allowlist can be
// asserted from a test on any platform rather than only on the one it matters
// for.
func buildBaseEnv(get func(string) string) []string {
	env := make([]string, 0, 8+len(localeVars)+len(basePassthrough))

	env = append(env, "PATH="+basePath(get))
	if home := baseHome(get); home != "" {
		env = append(env, homeVar+"="+home)
	}
	for _, name := range tempVars {
		if value := get(name); value != "" {
			env = append(env, name+"="+value)
		}
	}
	for _, name := range localeVars {
		if value := get(name); value != "" {
			env = append(env, name+"="+value)
		}
	}
	for _, name := range basePassthrough {
		if value := get(name); value != "" {
			env = append(env, name+"="+value)
		}
	}
	return env
}

func basePath(get func(string) string) string {
	if p := get("PATH"); p != "" {
		return p
	}
	return defaultPath
}

func baseHome(get func(string) string) string {
	if h := get(homeVar); h != "" {
		return h
	}
	// os.UserHomeDir reads the same variable, so it only helps on the platforms
	// where it has another source. Ignoring the error is deliberate: a host
	// with no discoverable home directory gets a base environment without one,
	// which is honest, rather than a synthesised path that does not exist.
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return ""
}

// mergeEnv applies a request's KEY=VALUE entries over the base.
//
// Later entries win, and a request entry replaces the base entry with the same
// key rather than appending a second one: execve is happy to carry two PATHs
// and the resolution then depends on which the libc scan finds first, so
// "applied on top" has to mean replacement to mean anything.
//
// Keys are compared case-insensitively on Windows, where the environment is.
func mergeEnv(base, overrides []string) ([]string, error) {
	merged := make([]string, 0, len(base)+len(overrides))
	index := make(map[string]int, len(base)+len(overrides))

	set := func(entry string) {
		key := envKey(entry)
		if at, ok := index[key]; ok {
			merged[at] = entry
			return
		}
		index[key] = len(merged)
		merged = append(merged, entry)
	}

	for _, entry := range base {
		set(entry)
	}
	for _, entry := range overrides {
		if err := checkEnvEntry(entry); err != nil {
			return nil, err
		}
		set(entry)
	}
	return merged, nil
}

// checkEnvEntry refuses an entry the OS would either reject or misread.
//
// A malformed entry is an error rather than something to drop: a caller that
// wrote "PATH" meaning "PATH=..." has a bug, and silently running with the
// agent's PATH instead produces a command that works on one host and not
// another for reasons nothing reports.
func checkEnvEntry(entry string) error {
	key, _, ok := strings.Cut(entry, "=")
	if !ok {
		return fmt.Errorf("environment entry %q is not KEY=VALUE", entry)
	}
	if key == "" {
		return fmt.Errorf("environment entry %q has an empty name", entry)
	}
	if strings.ContainsRune(entry, 0) {
		return fmt.Errorf("environment entry for %q contains a NUL byte", key)
	}
	return nil
}

// envKey returns the comparison key for an entry.
func envKey(entry string) string {
	key, _, _ := strings.Cut(entry, "=")
	if caseInsensitiveEnv {
		return strings.ToUpper(key)
	}
	return key
}

// envValue returns the value of name in env, and whether it was present.
func envValue(env []string, name string) (string, bool) {
	want := name
	if caseInsensitiveEnv {
		want = strings.ToUpper(name)
	}
	// Last wins, matching mergeEnv's replacement order.
	for i := len(env) - 1; i >= 0; i-- {
		if envKey(env[i]) == want {
			_, value, _ := strings.Cut(env[i], "=")
			return value, true
		}
	}
	return "", false
}

// sortedKeys is a diagnostic helper: the names in an environment, sorted, with
// no values. Used in log lines, which must never carry a value.
func sortedKeys(env []string) []string {
	keys := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
