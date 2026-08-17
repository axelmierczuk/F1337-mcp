package host

import "os"

// probeEnv is the environment a toolchain version probe runs with.
//
// The daemon's own environment is not inherited: it may hold credentials from
// whatever installed the service, and a version probe has no business seeing
// them. PATH is passed through because some toolchains shell out to their own
// helpers to answer, plus whatever else the platform genuinely cannot start a
// process without — see probePassthrough.
func probeEnv() []string { return buildProbeEnv(os.Getenv) }

// buildProbeEnv is probeEnv with the lookup injected, so the allowlist can be
// asserted from a test on any platform rather than only on the one it matters
// for.
func buildProbeEnv(get func(string) string) []string {
	env := make([]string, 0, len(probePassthrough)+1)
	env = append(env, "PATH="+get("PATH"))
	for _, name := range probePassthrough {
		if value := get(name); value != "" {
			env = append(env, name+"="+value)
		}
	}
	return env
}
