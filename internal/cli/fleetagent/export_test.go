package fleetagent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/kardianos/service"

	sandboxdv1 "github.com/axelmierczuk/fleet-mcp/gen/go/sandboxd/v1"
	"github.com/axelmierczuk/fleet-mcp/internal/agent"
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
	return serverOptions(cfg, log, drain)
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

// ServiceAccessByOwnershipForTest reports whether this platform grants the
// service account access by ownership.
const ServiceAccessByOwnershipForTest = serviceAccessByOwnership

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
func MechanismNotesForTest(m Mechanism, goos, account string) []string {
	return mechanismNotes(m, goos, account)
}

// DryRunNotesForTest exposes what a dry run says about the step the plan itself
// cannot show — the password prompt — with the platform supplied rather than
// read.
func DryRunNotesForTest(m Mechanism, goos, account string) []string {
	return dryRunNotes(m, goos, account)
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
