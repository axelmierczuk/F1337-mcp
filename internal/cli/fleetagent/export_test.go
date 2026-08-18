package fleetagent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/kardianos/service"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/agent"
	"github.com/axelmierczuk/fleet-mcp/internal/cli"
	"github.com/axelmierczuk/fleet-mcp/internal/platform"
)

// EnrollRequestForTest is the message `enroll` sends about this host.
//
// Exported alongside ServerOptionsForTest so a test can compare what the two
// paths say about the same host without an enrollment or a running daemon.
func EnrollRequestForTest(token string, csrDER []byte, requestedName string, addresses []string) *sandboxdv1.EnrollRequest {
	return enrollRequest(token, csrDER, requestedName, addresses)
}

// ServerOptionsForTest is what `serve` builds the daemon from.
func ServerOptionsForTest(cfg *agent.Config, log *slog.Logger, drain time.Duration) agent.Options {
	return serverOptions(cfg, log, serveOptions{drain: drain})
}

// ServeAllowsUnauthenticatedPublicForTest reports whether the options `serve`
// hands the daemon carry the operator's --allow-unauthenticated-public.
//
// It exists because that flag reaching agent.New is the whole of the second
// half of #85's first guard: the command checks the posture itself, and a flag
// that stopped being passed on would leave the daemon's own check refusing a
// start the operator had explicitly authorised.
func ServeAllowsUnauthenticatedPublicForTest(cfg *agent.Config, log *slog.Logger, allow bool) bool {
	return serverOptions(cfg, log, serveOptions{allowPublic: allow}).AllowUnauthenticatedPublic
}

// EnrollmentMaterialForTest is the set of files `service install` has to hand
// to the account the daemon will run as.
func EnrollmentMaterialForTest(cfg *agent.Config, configPath string) []string {
	return enrollmentMaterial(cfg, configPath)
}

// EnrollmentDirIsOursForTest reports whether install may take ownership of a
// directory, which it may only do for the ones `enroll` creates.
func EnrollmentDirIsOursForTest(dir string) bool { return enrollmentDirIsOurs(dir) }

// GrantServiceUserAccessForTest exposes the ownership handover so it can be
// exercised against a real directory. Chowning to one's own account needs no
// privilege, which is what makes the success path testable at all.
func GrantServiceUserAccessForTest(name, dir string, files []string) error {
	return grantServiceUserAccess(name, dir, files)
}

// DefaultServiceUserForTest exposes the platform's default service account, so
// the "never a superuser" property can be asserted without an install.
func DefaultServiceUserForTest() (string, error) { return defaultServiceUser() }

// LegacyServiceNoteForTest exposes what an operator is told when this host
// still carries a service registered under the pre-rebrand name.
//
// The presence answer is supplied rather than read: no test can register a
// pre-rebrand service with a real service manager, and CI cannot register one
// at all.
func LegacyServiceNoteForTest(present bool) string { return legacyServiceNote(present) }

// LegacyServiceNameForTest is the pre-rebrand service name, so the test asserts
// on the same constant the note is built from.
const LegacyServiceNameForTest = legacyServiceName

// IsElevatedForTest reports whether this process can install a service.
//
// The tests that assert the *unprivileged* path have to skip when it is not,
// and they must ask the same question the code does. A test-local
// `runtime.GOOS == "windows" → false` is wrong on exactly the machine that
// matters: GitHub's Windows runners are administrators, so those tests ran
// elevated and failed against an error message meant for someone who is not.
func IsElevatedForTest() bool { return isElevated() }

// ResolveMechanismForTest exposes the rule that decides how a host registers
// the agent, with the platform supplied rather than read.
//
// The rule is the whole of #74: on Windows it decides whether the daemon lands
// in the operator's session or in session 0, and it has to be assertable from
// the runners that are not Windows.
func ResolveMechanismForTest(requested Mechanism, goos, account string) (Mechanism, error) {
	return resolveMechanism(requested, goos, account)
}

// ServiceNeedsPasswordForTest exposes when the SCM will refuse an account
// without its password.
func ServiceNeedsPasswordForTest(m Mechanism, goos, account string) bool {
	return serviceNeedsPassword(m, goos, account)
}

// MechanismNotesForTest exposes what `install` tells an operator about the
// mechanism it just gave them, with the platform supplied rather than read.
//
// Everything in here is a thing that would otherwise be found out afterwards:
// an agent that vanishes at logout, a stop that kills every supervised process,
// a built-in identity that cannot see a toolchain, and an account the SCM will
// refuse to log on. Which of them applies is a rule, and a rule checked only on
// a Windows runner is one two thirds of CI never sees.
func MechanismNotesForTest(m Mechanism, goos, account string, logonVerified bool) []string {
	return mechanismNotes(m, goos, account, logonVerified)
}

// DryRunNotesForTest exposes what a dry run says about the steps the plan
// itself cannot show — the two prompts — with the platform supplied rather than
// read.
func DryRunNotesForTest(m Mechanism, goos, account string, choice AccountChoiceForTest) []string {
	return dryRunNotes(m, goos, account, accountChoice(choice))
}

// AccountChoiceForTest is where install gets the account it registers.
type AccountChoiceForTest int

// The four answers, named so a test compares against the same values the
// command switches on.
const (
	AccountFromFlagForTest    = AccountChoiceForTest(accountFromFlag)
	AccountFromDefaultForTest = AccountChoiceForTest(accountFromDefault)
	AccountFromPromptForTest  = AccountChoiceForTest(accountFromPrompt)
	AccountUnaskableForTest   = AccountChoiceForTest(accountUnaskable)
)

// ResolveAccountChoiceForTest exposes #84's central rule — whether `install`
// stops to ask which account it is about to register — with the platform
// supplied rather than read.
//
// It decides whether an operator on a workstation is asked for a credential
// they do not need, and whether a script's install hangs on a prompt or
// refuses. Both are answers about the rule, and a rule only the Windows runner
// can reach is a rule only that runner checks.
func ResolveAccountChoiceForTest(requested Mechanism, goos, userFlag string, passwordStdin bool) AccountChoiceForTest {
	return AccountChoiceForTest(resolveAccountChoice(requested, goos, userFlag, passwordStdin))
}

// PromptServiceAccountForTest drives the account prompt against a supplied
// stream, which is the only way the prompt itself — as opposed to the rule that
// fires it — is reachable off Windows.
func PromptServiceAccountForTest(in io.Reader, out io.Writer, suggestion string) (string, error) {
	return promptServiceAccount(in, out, suggestion)
}

// ReadInputLineForTest exposes the one-line read both prompts share.
//
// The two properties it has to keep are invisible from either caller: it must
// consume exactly one line, or the account prompt eats the password typed after
// it; and end-of-stream must not look like an empty line, or a script that
// redirected stdin from nowhere gets the silent fallback to the invoking
// account that #84 exists to remove.
func ReadInputLineForTest(in io.Reader) (string, error) { return readInputLine(in) }

// Logon verdicts, named so a test compares against the same values the command
// switches on.
const (
	LogonOKForTest            = int(logonOK)
	LogonBadCredentialForTest = int(logonBadCredential)
	LogonRightMissingForTest  = int(logonRightMissing)
	LogonUnverifiableForTest  = int(logonUnverifiable)
	LogonUnknownForTest       = int(logonUnknown)
)

// ClassifyServiceLogonForTest exposes what install makes of the answer
// LogonUser gave.
//
// The classification is a rule over Win32 status codes, and the two codes that
// decide a refusal — 1326 and 1385 — are the difference between an install that
// stops and one that produces a service failing every start. No runner here can
// call LogonUser; every runner can check the rule.
func ClassifyServiceLogonForTest(err error) int { return int(classifyServiceLogon(err)) }

// ErrLogonUnverifiableForTest is what a platform with no SCM answers.
var ErrLogonUnverifiableForTest = errLogonUnverifiable

// SplitServiceAccountForTest exposes the split LogonUser needs, which has to
// agree with the spelling CreateService is handed or the check validates a
// different account from the one being registered.
func SplitServiceAccountForTest(name string) (account, domain string) {
	return splitServiceAccount(name)
}

// ServiceLogonRightNoteForTest and ServiceLogonRightRefusalForTest are the two
// renderings of #79's SeServiceLogonRight text, exposed so a test can hold them
// to being the same text.
func ServiceLogonRightNoteForTest(account string) []string { return serviceLogonRightNote(account) }

func ServiceLogonRightRefusalForTest(account string) string {
	return serviceLogonRightRefusal(account)
}

// CredentialLoopForTest drives the read-and-check sequence `install` performs
// before it touches the host, with both platform halves supplied.
//
// Neither half is reachable from any runner here: readPassword needs a Windows
// console, and the check needs a real LSA, a real account and that account's
// real password. What sits between them is where every decision is — which
// verdict refuses and which proceeds, whether a mistyped password is retyped or
// the command ends, and what the operator is told in between — and without this
// it is reachable from nothing.
func CredentialLoopForTest(out io.Writer, account string, attempts int, fromStdin bool, read func() (string, error), verify func(string) error) (password string, verified bool, err error) {
	p := cli.NewPrinter(out)
	password, verified, err = credentialLoop(p, account, attempts, fromStdin, read, verify)
	if err == nil {
		err = p.Err()
	}
	return password, verified, err
}

// InteractivePasswordAttemptsForTest is how many times an operator typing a
// password blind gets to type it again, so a test asserts against the same
// number the command uses.
const InteractivePasswordAttemptsForTest = interactivePasswordAttempts

// PasswordAttemptsForTest exposes the rule that decides it, which is also the
// rule that keeps --password-stdin from turning into a prompt.
func PasswordAttemptsForTest(fromStdin bool) int { return passwordAttempts(fromStdin) }

// SCMConfigFieldsForTest is every string the Windows service definition carries
// *except* the password field, so a test can assert where the password is not.
//
// It includes the Option values, which is where the rendered systemd unit and
// launchd plist live, so "the password is not in the service definition" is a
// claim about the whole definition rather than about the fields somebody
// remembered to look at.
func SCMConfigFieldsForTest(params UnitParams, goos, password string) []string {
	cfg := scmServiceConfig(params, goos, password)
	fields := []string{cfg.Name, cfg.DisplayName, cfg.Description, cfg.Executable, cfg.UserName}
	fields = append(fields, cfg.Arguments...)
	for key, value := range cfg.Option {
		if key == "Password" {
			continue
		}
		fields = append(fields, key, fmt.Sprint(value))
	}
	return fields
}

// PinServiceLogonForTest replaces the Windows logon check with a supplied
// answer, and records the account and password it was asked about.
//
// Nothing on any runner can perform a real service logon: it needs a real LSA,
// a real account, and that account's real password, none of which CI has or
// should have. Without this seam every decision built on the answer — refuse a
// bad credential, refuse a missing right, retry a mistyped password, stop
// warning about a right just proved present — is reachable by nothing, which is
// the state three audit rounds found the rest of `install` in.
func PinServiceLogonForTest(answer error) (asked func() (account, password string, calls int), restore func()) {
	previous := verifyServiceLogon
	var gotAccount, gotPassword string
	count := 0
	verifyServiceLogon = func(account, password string) error {
		gotAccount, gotPassword, count = account, password, count+1
		return answer
	}
	return func() (string, string, int) { return gotAccount, gotPassword, count },
		func() { verifyServiceLogon = previous }
}

// PinServiceLogonSequenceForTest is the same seam answering differently each
// time it is called, which is the only way the retry is observable: "a mistyped
// password is retyped at the prompt" is a claim about the second attempt.
func PinServiceLogonSequenceForTest(answers []error) (passwords func() []string, restore func()) {
	previous := verifyServiceLogon
	seen := &[]string{}
	verifyServiceLogon = func(_, password string) error {
		*seen = append(*seen, password)
		if i := len(*seen) - 1; i < len(answers) {
			return answers[i]
		}
		return nil
	}
	return func() []string { return append([]string(nil), *seen...) },
		func() { verifyServiceLogon = previous }
}

// SCMAccountForTest is the account `install` hands the service manager, taken
// off the configuration it actually builds rather than off the rule underneath
// it.
//
// CreateService reads a bare name as a domain account, so the difference
// between `build` and `.\build` is the difference between an install that works
// on a domain-joined host and one that fails naming an account that does not
// exist. No runner here has a domain, or an SCM.
func SCMAccountForTest(params UnitParams, goos, password string) string {
	return scmServiceConfig(params, goos, password).UserName
}

// SCMPasswordForTest is the password that configuration carries, so that "the
// SCM is the only thing that ever sees it" is a claim about a value something
// asserted rather than about a parameter name.
func SCMPasswordForTest(params UnitParams, goos, password string) (string, bool) {
	value, ok := scmServiceConfig(params, goos, password).Option["Password"]
	text, _ := value.(string)
	return text, ok
}

// ScheduledTaskForTest is the Windows Scheduled Task lifecycle.
type ScheduledTaskForTest interface {
	Install() error
	Uninstall() error
	Start() error
	Stop() error
	Restart() error
	Status() (service.Status, error)
}

// NewScheduledTaskForTest builds that lifecycle with the schtasks.exe
// invocation replaced by run.
//
// This is the seam the audit of #79 asked for. Registering a task needs an
// elevated token and a real Task Scheduler, so no runner here can let a single
// one of these invocations happen — which left the argv, and the bytes of the
// file the argv points schtasks at, asserted by nothing at all. run sees
// exactly what schtasks.exe would, including the temp file, which still exists
// while it is called.
func NewScheduledTaskForTest(params UnitParams, run func(args ...string) error) ScheduledTaskForTest {
	return &scheduledTask{params: params, run: run}
}

// NewScheduledTaskStatusForTest is the same lifecycle with the state directory
// Status reads supplied.
//
// Status is the answer `service status` prints and the answer `install` decides
// a replacement on, and both halves of it were unreachable from every runner:
// existence came from a free function in task_windows.go, so off Windows it was
// a compile-time false and on Windows it shelled out to a real schtasks.exe,
// and running-ness came from a state directory nothing could point anywhere.
func NewScheduledTaskStatusForTest(run func(args ...string) error, stateDir string) ScheduledTaskForTest {
	return &scheduledTask{run: run, stateDir: func() string { return stateDir }}
}

// NewScheduledTaskRestartForTest is the same lifecycle with the state directory
// supplied and Restart's wait for the ended instance bounded to budget.
//
// The wait is the half of Restart that makes the start mean anything: `/End`
// returns before the instance it ended is gone, and this definition's
// MultipleInstancesPolicy is IgnoreNew, so a `/Run` issued too early is dropped
// by the scheduler with schtasks still exiting zero. A budget is a parameter
// because the behaviour under test is "it waits", and a test that waits the
// shipped five seconds to prove it is a test nobody will keep.
func NewScheduledTaskRestartForTest(run func(args ...string) error, stateDir string, budget time.Duration) ScheduledTaskForTest {
	return &scheduledTask{run: run, endBudget: budget, stateDir: func() string { return stateDir }}
}

// NewScheduledTaskStateDirForTest builds the lifecycle the way `install` does —
// from UnitParams, with no state directory supplied — so that which directory
// Status reads is the thing under test.
func NewScheduledTaskStateDirForTest(params UnitParams, run func(args ...string) error) ScheduledTaskForTest {
	return &scheduledTask{params: params, run: run}
}

// StatusRunningForTest and friends name the states Status answers with, so a
// test compares against the same values the commands switch on.
const (
	StatusRunningForTest = service.StatusRunning
	StatusStoppedForTest = service.StatusStopped
	StatusUnknownForTest = service.StatusUnknown
)

// ErrTaskNotInstalledForTest is what Status returns for a task the scheduler
// does not have.
var ErrTaskNotInstalledForTest = service.ErrNotInstalled

// WindowsACLForTest is the set of icacls grants `install` applies on Windows,
// with the invocation replaced by run.
//
// The same seam, and the same reason, as NewScheduledTaskForTest: applying an
// ACL needs an elevated Windows token, so no runner here can let one happen,
// and the argv deciding whether the daemon can read its own private key was
// composed in a _windows.go file and asserted nowhere at all.
type WindowsACLForTest interface {
	GrantOwnedDir(dir, account string) error
	GrantEnrollment(account, dir string, files []string) error
}

// NewWindowsACLForTest builds that set with icacls.exe replaced by run, which
// is handed the complete argv icacls.exe would have been given — the object
// first, every option after it, exactly as the real invocation assembles it.
func NewWindowsACLForTest(run func(argv ...string) error) WindowsACLForTest {
	return aclForTest{serviceACL{run: run}}
}

type aclForTest struct{ acl serviceACL }

func (a aclForTest) GrantOwnedDir(dir, account string) error {
	return a.acl.grantOwnedDir(dir, account)
}

func (a aclForTest) GrantEnrollment(account, dir string, files []string) error {
	return a.acl.grantEnrollment(account, dir, files)
}

// ExecutableAccessOutcomeForTest exposes what `install` says about a binary the
// service account cannot read, and whether saying it ends the command, with the
// platform and the dry run supplied rather than read.
//
// The dry-run half of it was reachable from no runner: the check is fatal only
// on Windows, and a Windows runner had never driven `install --dry-run` against
// a binary inside a profile — so a dry run returning the refusal instead of the
// plan was invisible everywhere.
func ExecutableAccessOutcomeForTest(goos string, dryRun bool) (headline string, refuse bool) {
	return executableAccessOutcome(goos, dryRun)
}

// ExecutableAccessIsFatalForTest exposes the rule that decides whether a binary
// the service account cannot reach stops the install or only warns about it.
func ExecutableAccessIsFatalForTest(goos string) bool { return executableAccessIsFatal(goos) }

// InvokingServiceUserForTest exposes the default-account rule macOS has always
// used and Windows now does, including its one refusal.
func InvokingServiceUserForTest(current string) (string, error) {
	return invokingServiceUser(current)
}

// RunsInSessionZeroForTest reports whether an account is a built-in Windows
// service identity, which is to say one with no operator profile.
func RunsInSessionZeroForTest(account string) bool { return runsInSessionZero(account) }

// IsSuperuserForTest reports whether an account is the platform's all-powerful
// one, which is what decides whether `install` warns that every command the
// agent runs will run as it.
//
// Exported beside RunsInSessionZeroForTest because the two rules ask about the
// same accounts and used to normalise them differently, so one recognised a
// spelling the other let through.
func IsSuperuserForTest(account string) bool { return isSuperuser(account) }

// WindowsExecutableAccessProblemForTest exposes the check that stops `install`
// registering a binary the service account cannot read.
func WindowsExecutableAccessProblemForTest(exe, account, usersRoot string) string {
	return windowsExecutableAccessProblem(exe, account, usersRoot)
}

// ExecutableAccessAdviceForTest exposes the message that check produces.
func ExecutableAccessAdviceForTest(problem, exe, account, goos string) string {
	return executableAccessAdvice(problem, exe, account, goos)
}

// QuoteWindowsArgvForTest exposes the command-line quoting the Scheduled Task's
// <Arguments> element depends on.
func QuoteWindowsArgvForTest(argv []string) string { return quoteWindowsArgv(argv) }

// UserToolchainForTest is a program the per-user toolchain probe may execute.
type UserToolchainForTest = userToolchain

// ProfileProbeForTest runs the per-user toolchain probe against an explicit
// home directory and PATH.
//
// This is the probe that answers "can a command this agent spawns reach what
// the operator installed under their own profile", which is the question
// session 0 answers no to and which nothing in this repository used to ask.
func ProfileProbeForTest(home, pathEnv, goos string, tools []UserToolchainForTest) (visibility, ran string, unreachable []string) {
	result := profileProbe{Home: home, Path: pathEnv, GOOS: goos, Tools: tools}.probe(context.Background())
	return string(result.Visibility), result.Ran, result.Unreachable
}

// UserBinDirsForTest is the list of per-user directories the probe looks for,
// with the platform supplied rather than read.
//
// The list is data, and it is the probe's entire input: a Windows entry that is
// wrong, or missing, is a workstation reported as "unknown" or as "hidden" with
// nothing an operator can act on. Driven with runtime.GOOS the Windows half is
// read on one runner in three, and — because the two lists share every entry
// the tests happen to plant under — swapping one for the other changed no test
// at all.
func UserBinDirsForTest(goos string) []string { return userBinDirs(goos) }

// ProfileProbeBudgetForTest is the probe with an explicit deadline.
//
// The deadline is not a detail: the probe executes programs it found on disk,
// on the daemon's start path, before the listener is bound. One of them
// blocking — a shim waiting on a lock, a `node` on a stalled network mount —
// would hang the daemon in a way the service manager reports as "failed to
// start" and nothing explains. It has to be asserted that the bound is applied,
// not that the constant is a sensible number.
func ProfileProbeBudgetForTest(home, pathEnv, goos string, budget time.Duration, tools []UserToolchainForTest) (visibility, ran string) {
	result := profileProbe{Home: home, Path: pathEnv, GOOS: goos, Budget: budget, Tools: tools}.probe(context.Background())
	return string(result.Visibility), result.Ran
}

// Visibility values the probe reports, so a test names the same constants the
// code does.
const (
	ProfileVisibleForTest = string(profileVisible)
	ProfileHiddenForTest  = string(profileHidden)
	ProfileUnknownForTest = string(profileUnknown)
)

// RuntimeReportForTest is a daemon's record of the environment it was started
// in, in the shape a test needs to plant one.
type RuntimeReportForTest struct {
	PID         int
	StartID     string
	Account     string
	AccountSID  string
	Home        string
	SessionZero bool
	Visibility  string
	Ran         string
	Unreachable []string
}

func (r RuntimeReportForTest) internal() *runtimeReport {
	return &runtimeReport{
		PID:         r.PID,
		StartID:     r.StartID,
		StartedAt:   time.Now().UTC(),
		Executable:  "fleet-agent",
		Version:     "test",
		Account:     r.Account,
		AccountSID:  r.AccountSID,
		Home:        r.Home,
		SessionZero: r.SessionZero,
		Profile: profileResult{
			Visibility:  profileVisibility(r.Visibility),
			Ran:         r.Ran,
			Unreachable: r.Unreachable,
		},
	}
}

// ConfinementForTest exposes the judgement `service status` draws from a
// report: whether this agent can do the job it exists for.
func ConfinementForTest(rep *RuntimeReportForTest) (summary string, detail, remedy []string) {
	if rep == nil {
		if c := confinementFor(nil); c != nil {
			return c.Summary, c.Detail, c.Remedy
		}
		return "", nil, nil
	}
	c := confinementFor(rep.internal())
	if c == nil {
		return "", nil, nil
	}
	return c.Summary, c.Detail, c.Remedy
}

// WriteRuntimeReportForTest plants a report where `service status` reads one,
// through the same writer the daemon uses.
func WriteRuntimeReportForTest(stateDir string, rep RuntimeReportForTest) error {
	return writeRuntimeReport(stateDir, rep.internal())
}

// PinAccountIdentityForTest makes the daemon record the account a host would
// have reported, rather than the one the runner is.
//
// The account is the fact the whole of #74's verdict is drawn from, and the
// spelling a real Windows host reports is one no runner here can produce: a
// localised display name and a well-known SID. Pinning it is the only way to
// drive the collection with what a machine would actually give it.
func PinAccountIdentityForTest(name, sid string) (restore func()) {
	previous := currentIdentity
	currentIdentity = func() accountIdentity { return accountIdentity{Name: name, SID: sid} }
	return func() { currentIdentity = previous }
}

// ReportHomeForTest exposes which environment variable the daemon takes its
// home directory from, with the environment supplied rather than read.
//
// Windows sets USERPROFILE and never HOME, so this one lookup is what gives the
// probe somewhere to look and what the service-profile verdict is decided on.
// Driven with a real environment it is only ever distinguishable on a Windows
// runner; driven with a supplied one it is checkable everywhere.
func ReportHomeForTest(base []string) string { return reportHome(base) }

// LiveProcessIdentityForTest is this process's pid and start identity, which is
// what makes a planted report describe a daemon that is actually running.
func LiveProcessIdentityForTest() (pid int, startID string) {
	pid = os.Getpid()
	if info, err := platform.StatProcess(pid); err == nil {
		startID = info.StartID
	}
	return pid, startID
}

// CollectRuntimeReportForTest runs the daemon's own self-check against this
// process, which is what `serve` records at every start.
func CollectRuntimeReportForTest() (account, home, visibility, ran string, sessionZero bool) {
	rep := collectRuntimeReport(context.Background())
	return rep.Account, rep.Home, string(rep.Profile.Visibility), rep.Profile.Ran, rep.SessionZero
}

// PinElevatedForTest makes the elevation gate pass, for the commands that only
// remove or report.
//
// It is not a licence to drive `service install`: that one creates directories,
// grants access and registers with a real service manager, and none of those
// belong in a test run. `uninstall` touches nothing but the registrations it is
// given, which is what makes it safe here and is why it was worth reaching —
// the walk over every registration a host carries is exactly the behaviour an
// operator with two of them depends on. See the comment on requireElevated.
func PinElevatedForTest() (restore func()) {
	previous := requireElevated
	requireElevated = func(string) error { return nil }
	return func() { requireElevated = previous }
}

// PinRecordingRegistrationsForTest makes the `service` subcommands see a host
// registered under every named mechanism, and records what each one is asked to
// do.
//
// fail names the mechanisms whose control operations refuse. A host carrying
// two registrations is the one `stop` and `uninstall` exist to put right, and
// the question these commands have to answer is what they do when the first of
// the two will not co-operate.
func PinRecordingRegistrationsForTest(mechanisms []Mechanism, fail map[Mechanism]bool) (calls func() []string, restore func()) {
	previousList, previousNew := installedMechanisms, controlRegistration
	recorded := &[]string{}
	installedMechanisms = func() []Mechanism { return mechanisms }
	controlRegistration = func(m Mechanism) (registration, error) {
		return &recordingRegistration{mechanism: m, log: recorded, fails: fail[m]}, nil
	}
	return func() []string { return append([]string(nil), *recorded...) },
		func() { installedMechanisms, controlRegistration = previousList, previousNew }
}

// recordingRegistration is a registration that says what it was asked to do.
type recordingRegistration struct {
	mechanism Mechanism
	log       *[]string
	fails     bool
}

func (r *recordingRegistration) record(verb string) error {
	*r.log = append(*r.log, string(r.mechanism)+":"+verb)
	if r.fails {
		return fmt.Errorf("%s cannot %s here", r.mechanism, verb)
	}
	return nil
}

func (r *recordingRegistration) Install() error   { return r.record("install") }
func (r *recordingRegistration) Uninstall() error { return r.record("uninstall") }
func (r *recordingRegistration) Start() error     { return r.record("start") }
func (r *recordingRegistration) Stop() error      { return r.record("stop") }
func (r *recordingRegistration) Restart() error   { return r.record("restart") }

func (r *recordingRegistration) Status() (service.Status, error) {
	return service.StatusRunning, nil
}

// InstallHostForTest describes the host `service install` is about to be run
// on: what it already carries, what is running on it, and whether the service
// manager will accept the definition install writes.
type InstallHostForTest struct {
	// Installed is what the host already carries.
	Installed []Mechanism
	// Running names the mechanisms whose registration reports running.
	Running map[Mechanism]bool
	// FailInstall makes the registration install writes refuse to install,
	// which is the state that decides whether the host is left with anything
	// registered at all.
	FailInstall bool
	// FailBuild makes the definition itself impossible to assemble, which is
	// what a service manager this library cannot address produces — and which
	// has to be discovered before anything is removed.
	FailBuild bool
	// Legacy makes the host carry a service under the pre-rebrand name.
	Legacy bool
	// FailUninstall makes the removal refuse, which is what a manager that has
	// already been asked to stop the daemon leaves behind: an agent that is
	// down because of this command and a definition that is still there.
	FailUninstall bool
	// StopFails makes every stop refuse and leave the daemon running, which is
	// how a replacement can land with something still up under it: install
	// stops what it replaces, says so when it cannot, and carries on — a stop
	// that failed is not a reason to refuse to write the new definition.
	StopFails bool
}

// PinInstallForTest drives `service install` against that host, recording every
// lifecycle call the command makes — on the registrations it removes and on the
// one it writes — and the password it hands the service manager.
//
// This is the half of `install` three audit rounds named unreachable. Nothing
// on any runner may write a real systemd unit, launchd job, Windows service or
// Scheduled Task, so the seam is at newRegistration: the point where the
// command stops deciding and starts talking to the host. Everything above it —
// which registration is removed first, whether the daemon was running before
// the command started, what a failed write leaves behind, and whether the agent
// is running again when the command returns — is the real command, entered from
// the real argv, and it would notice if it stopped doing any of that.
//
// The steps a test must not let happen are kept out by what the caller passes,
// not by this seam: a config whose state and log directories are its own, and
// an account whose grants are no-ops. See installAccount in install_test.go.
func PinInstallForTest(host InstallHostForTest) (calls func() []string, password func() string, restore func()) {
	previous := struct {
		list     func() []Mechanism
		control  func(Mechanism) (registration, error)
		create   func(Mechanism, UnitParams, string) (registration, error)
		elevated func(string) error
		legacy   func() bool
	}{installedMechanisms, controlRegistration, newRegistration, requireElevated, legacyServiceInstalled}

	recorded := &[]string{}
	handed := new(string)
	installedMechanisms = func() []Mechanism { return host.Installed }
	controlRegistration = func(m Mechanism) (registration, error) {
		return newInstallRegistration(string(m), m, host, recorded, false), nil
	}
	newRegistration = func(m Mechanism, _ UnitParams, secret string) (registration, error) {
		*handed = secret
		if host.FailBuild {
			return nil, fmt.Errorf("prepare service definition: no %s can be assembled here", m)
		}
		return newInstallRegistration("new", m, host, recorded, host.FailInstall), nil
	}
	requireElevated = func(string) error { return nil }
	legacyServiceInstalled = func() bool { return host.Legacy }

	return func() []string { return append([]string(nil), *recorded...) },
		func() string { return *handed },
		func() {
			installedMechanisms, controlRegistration = previous.list, previous.control
			newRegistration, requireElevated, legacyServiceInstalled = previous.create, previous.elevated, previous.legacy
		}
}

// installRegistration is a registration that says what it was asked to do and
// answers Status from what has been done to it.
//
// Status is not recorded: it is a query, and `install` asks it more than once
// on purpose — the point of the recording is the sequence of things that change
// the machine.
//
// It carries state, and refuses the way the real service managers refuse,
// because the alternative hid a bug for a whole audit round. A fake whose Stop
// always succeeds and whose Restart always succeeds asserts only that the
// command called something; it cannot tell "restart what is running" from
// "restart what this command stopped two lines ago", and those are the same
// call with opposite outcomes. kardianos's Windows Restart is
// ControlService(STOP) followed by StartService and returns at the first
// failure, and stopping a service that is not running fails with
// ERROR_SERVICE_NOT_ACTIVE; launchd's is unload-then-load with the same shape.
// So a definition that has just been written and has never run cannot be
// restarted, and this fake says so.
type installRegistration struct {
	label         string
	mechanism     Mechanism
	log           *[]string
	failInstall   bool
	failUninstall bool
	stopFails     bool
	installed     bool
	running       bool
}

// newInstallRegistration starts one off in the state the host it addresses is
// really in.
func newInstallRegistration(label string, m Mechanism, host InstallHostForTest, log *[]string, failInstall bool) *installRegistration {
	r := &installRegistration{label: label, mechanism: m, log: log, failInstall: failInstall, failUninstall: host.FailUninstall, stopFails: host.StopFails}
	for _, installed := range host.Installed {
		if installed == m {
			r.installed = true
			r.running = host.Running[m]
		}
	}
	return r
}

func (r *installRegistration) record(verb string) error {
	*r.log = append(*r.log, r.label+":"+verb)
	return nil
}

func (r *installRegistration) Install() error {
	if r.failInstall {
		_ = r.record("install")
		return fmt.Errorf("this host will not register a %s", r.mechanism)
	}
	// A definition that has just been written is registered, and is running
	// only where the daemon it replaced was never actually stopped. That is
	// the state the choice between Start and Restart turns on.
	r.installed = true
	return r.record("install")
}

func (r *installRegistration) Uninstall() error {
	if r.failUninstall {
		_ = r.record("uninstall")
		return fmt.Errorf("%s: the specified service has been marked for deletion", r.mechanism)
	}
	r.installed = false
	return r.record("uninstall")
}

func (r *installRegistration) Start() error {
	r.running = true
	return r.record("start")
}

func (r *installRegistration) Stop() error {
	if r.stopFails {
		_ = r.record("stop")
		return fmt.Errorf("%s: this host would not stop it", r.mechanism)
	}
	if !r.running {
		_ = r.record("stop")
		// What ControlService answers for a service that is not running, and
		// what makes the Restart below give up.
		return fmt.Errorf("%s: the service has not been started", r.mechanism)
	}
	r.running = false
	return r.record("stop")
}

// Restart is stop-then-start, and it gives up when the stop fails — which is
// what kardianos's Windows Restart and launchd's both do, and is the whole
// reason a definition this command has just written and just stopped cannot be
// restarted back into life.
func (r *installRegistration) Restart() error {
	_ = r.record("restart")
	if !r.running {
		return fmt.Errorf("%s: the service has not been started", r.mechanism)
	}
	return nil
}

func (r *installRegistration) Status() (service.Status, error) {
	switch {
	case r.running:
		return service.StatusRunning, nil
	case r.installed:
		return service.StatusStopped, nil
	default:
		return service.StatusUnknown, service.ErrNotInstalled
	}
}

// ForeignConfigDirNoteForTest exposes what install says about a config
// directory it deliberately left alone, with the platform supplied rather than
// read.
//
// The message used to be composed inline behind a per-platform constant, so the
// half of it Windows needs was written for nobody: an operator whose --config
// is outside %ProgramData% got no traverse grant and no note, which is a daemon
// that fails every start on a config it cannot reach.
func ForeignConfigDirNoteForTest(dir, account, goos string) []string {
	return foreignConfigDirNote(dir, account, goos)
}

// DryRunAccountNotesForTest exposes what a dry run says about an account the
// host does not have, with the platform and the lookup supplied rather than
// read.
func DryRunAccountNotesForTest(account, goos string, create, exists bool) []string {
	return dryRunAccountNotes(account, goos, create, exists)
}

// PinInstalledForTest makes the `service` subcommands see a host with the agent
// registered under the given mechanisms, running or not.
//
// Nothing a test may do can register a real service or scheduled task, and the
// commands that report on one are exactly what #74 is about. See the comment on
// controlRegistration for why the seam is at the host lookup and not any higher.
func PinInstalledForTest(mechanisms []Mechanism, running bool) (restore func()) {
	previousList, previousNew := installedMechanisms, controlRegistration
	installedMechanisms = func() []Mechanism { return mechanisms }
	controlRegistration = func(Mechanism) (registration, error) {
		return fakeRegistration{running: running}, nil
	}
	return func() { installedMechanisms, controlRegistration = previousList, previousNew }
}

// fakeRegistration stands in for a service manager entry that a test cannot
// create. It answers the one question `service status` asks and refuses the
// rest, so a command that starts doing more than reporting fails here rather
// than silently acting on a host.
type fakeRegistration struct{ running bool }

func (f fakeRegistration) Install() error   { return errors.New("fakeRegistration: Install") }
func (f fakeRegistration) Uninstall() error { return errors.New("fakeRegistration: Uninstall") }
func (f fakeRegistration) Start() error     { return errors.New("fakeRegistration: Start") }
func (f fakeRegistration) Stop() error      { return errors.New("fakeRegistration: Stop") }
func (f fakeRegistration) Restart() error   { return errors.New("fakeRegistration: Restart") }

func (f fakeRegistration) Status() (service.Status, error) {
	if f.running {
		return service.StatusRunning, nil
	}
	return service.StatusStopped, nil
}
