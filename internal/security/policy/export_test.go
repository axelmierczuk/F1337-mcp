package policy

// SetRulesForTest replaces a policy's rule lists after construction.
//
// It exists to reach the one state New refuses to build: a pattern
// filepath.Match cannot evaluate. Evaluate's behaviour there is the backstop
// for anything New's walk over the pattern misses, and a backstop that cannot
// be tested is a backstop nobody knows the shape of.
func SetRulesForTest(p *Policy, allow, deny []string) {
	p.allow, p.deny = allow, deny
}
