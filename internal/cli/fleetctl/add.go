package fleetctl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/spf13/cobra"

	"github.com/axelmierczuk/fleet-mcp/internal/cli"
	"github.com/axelmierczuk/fleet-mcp/internal/client"
	"github.com/axelmierczuk/fleet-mcp/internal/registry"
)

// `fleetctl add` is the operator's half of registering a fleet member. The
// model's half is the fleet_add MCP tool, and both write through
// [registry.Registry.Register] — one set of bounds on what may be registered,
// one refusal to overwrite a name, one account of what registering did not do.
// Nothing about the entry is decided here.
//
// What is decided here is what happens *before* the write, and it is the whole
// reason this command is not a one-line wrapper:
//
// The registry says who is in the fleet and how this workstation reaches them.
// Until #85 an entry could only be created by enrollment, which proved both
// halves as a side effect of the handshake — the host existed, and it held a
// certificate from this CA. With mTLS off by default neither is proved by
// anything, and `add` is the only step left. So it does the proving itself,
// once, while the operator is still looking at the command:
//
//   - The posture is checked, not trusted. An entry that claims mTLS for a host
//     serving plaintext is the silent downgrade #85 exists to prevent, and the
//     reverse — --insecure on a host that does authenticate — is a fleet member
//     every later call fails against. Both are refused, and the refusal names
//     the flag that fixes it. See [postureMismatch].
//   - An address nothing answers at is refused too, because `add` is where a
//     typo is still cheap. `--no-probe` is how an operator registers a host
//     that is not up yet, which is the one legitimate reason to write an entry
//     nothing has confirmed.
//
// Both checks are bounded by --timeout, the same per-host deadline `list`
// probes under, and both are skipped entirely by --no-probe. Nothing about
// `fleetctl list` changes: it holds its own deadline and probes concurrently,
// and this command adds no work to it.

// addResult is what registering did. Health and detail are the same words
// `list` prints, from the same probe through the same client, so an operator
// who reads "serving" here and runs `list` a second later sees the same fleet.
type addResult struct {
	Name    string            `json:"name"`
	Address string            `json:"address"`
	Auth    string            `json:"auth"`
	Labels  map[string]string `json:"labels,omitempty"`
	// Health is what the probe found, or "unknown" when none was made.
	Health string `json:"health"`
	// Detail says why health is unknown, or what a reachable agent said about
	// itself.
	Detail string `json:"detail,omitempty"`
	// Note states what registering did not do. It comes from the registry, so
	// the operator and the model are told the same thing.
	Note string `json:"note"`
}

func newAddCommand(out io.Writer) *cobra.Command {
	var (
		flags        outputFlags
		control      controlFlags
		registryPath string
		address      string
		insecureHost bool
		labels       map[string]string
		noProbe      bool
	)
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Register an already-installed agent in the fleet",
		Long: "add records a host this workstation can reach: a name, an address, and\n" +
			"whether mTLS is in force for it.\n\n" +
			"It does not enroll and does not install anything. Enrollment mints a\n" +
			"certificate and is `fleetctl enroll`; add is for a host whose agent is\n" +
			"already running — one that enrolled against this CA, or one running with\n" +
			"tls.enabled false on a network that authenticates its own peers.\n\n" +
			"The host is contacted once before the entry is written, under --timeout.\n" +
			"An address nothing answers at, or one whose posture does not match the\n" +
			"flags, is refused and nothing is registered. Pass --no-probe to register a\n" +
			"host that is not up yet.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])
			addr := strings.TrimSpace(address)

			// Checked here, before anything is dialled, and with the registry's
			// own rules: a malformed address should be named as one rather than
			// spending --timeout failing to connect to it.
			if err := registry.CheckName(name); err != nil {
				return err
			}
			if err := registry.CheckAddress(addr); err != nil {
				return err
			}
			if err := registry.CheckLabels(labels); err != nil {
				return err
			}

			fleet, err := openRegistry(registryPath)
			if err != nil {
				return err
			}

			// A name that is already taken cannot be registered whatever the
			// host says, so it is answered before anything is dialled. Register
			// stays the authority — a name can be taken between here and
			// there — but an operator re-running a provisioning script should
			// not pay two probe deadlines to be told what the registry already
			// knew.
			if existing, getErr := fleet.Get(name); getErr == nil {
				return nameTaken(&registry.DuplicateError{Name: existing.Name, Address: existing.Address})
			} else if !errors.Is(getErr, registry.ErrNotFound) {
				return getErr
			}

			sb := registry.Sandbox{Name: name, Address: addr, Labels: labels, Insecure: insecureHost}
			health, err := confirmHost(cmd.Context(), sb, &control, warnTo(cmd.ErrOrStderr()), noProbe)
			if err != nil {
				return err
			}

			reg, err := fleet.Register(sb)
			var duplicate *registry.DuplicateError
			switch {
			case errors.As(err, &duplicate):
				return nameTaken(duplicate)
			case err != nil:
				return err
			}

			result := addResult{
				Name:    reg.Sandbox.Name,
				Address: reg.Sandbox.Address,
				Auth:    client.TargetFor(reg.Sandbox).AuthName(),
				Labels:  reg.Sandbox.Labels,
				Health:  health.status,
				Detail:  health.detail,
				Note:    reg.Note,
			}
			return flags.output(out).Emit(result, func(p *cli.Printer) {
				p.Printf("added %s (%s)\n", result.Name, result.Address)
				status := fmt.Sprintf("auth %s, health %s", result.Auth, result.Health)
				if result.Detail != "" {
					status += " — " + result.Detail
				}
				p.Println(status)
				p.Printf("\n%s\n", result.Note)
				p.Printf("\nSelect it with `fleetctl select %s`, or see the whole fleet with `fleetctl list`.\n", result.Name)
			})
		},
	}
	flags.register(cmd)
	control.register(cmd)
	cmd.Flags().StringVar(&address, "address", "", "the agent's address as host:port (required)")
	cmd.Flags().BoolVar(&insecureHost, "insecure", false,
		"this host's agent runs with tls.enabled false: reach it without mTLS, which is only safe on a network that authenticates its peers")
	cmd.Flags().StringToStringVar(&labels, "label", nil, "operator metadata as key=value; repeatable")
	cmd.Flags().BoolVar(&noProbe, "no-probe", false, "register without contacting the host, for one that is not up yet")
	cmd.Flags().StringVar(&registryPath, "registry", "", "path to the fleet registry (default: <config dir>/registry.yaml)")
	_ = cmd.MarkFlagRequired("address")
	return cmd
}

// nameTaken renders a taken name with the operator's remedy. The registry
// supplies the fact — the name, and where it already points — and this supplies
// the command an operator types, which is the one part of the refusal that
// differs from the model's.
func nameTaken(duplicate *registry.DuplicateError) error {
	return fmt.Errorf("%w. Deregister it with `fleetctl remove %s` first if the address has changed",
		duplicate, duplicate.Name)
}

// noProbeDetail is what a registration nobody confirmed reports as its health.
// It is a detail rather than a silence because "unknown" is also what a probe
// that failed to authenticate produces, and an operator reading the entry back
// has to be able to tell which.
const noProbeDetail = "not contacted: --no-probe was given"

// confirmHost contacts the host once, in the posture it was registered under,
// and returns what it found. A mismatch or a silence is an error and nothing is
// written.
//
// The deadline is --timeout, per attempt, which is the deadline `list` probes
// under. At most two attempts are made — the posture asked for, then the other
// one, and only to explain a failure — so the worst case is bounded at twice
// that and reached only when the first attempt has already failed.
func confirmHost(ctx context.Context, sb registry.Sandbox, control *controlFlags, warn *slog.Logger, noProbe bool) (healthView, error) {
	if noProbe {
		return healthView{status: client.HealthUnknown, detail: noProbeDetail}, nil
	}

	pool, err := control.pool(oneShotHealthInterval, warn)
	if err != nil {
		return healthView{}, err
	}
	defer func() { _ = pool.Close() }()

	timeout := control.probeTimeout()
	asked := probeOne(ctx, pool, sb, timeout)
	if asked.answered {
		return asked, nil
	}

	// The requested posture did not answer. Try the other one, so that the
	// operator is told which of the two failures they have — a wrong posture or
	// a wrong address — rather than being left to guess from "unreachable".
	// This is what #85 means by failing loudly in both directions: the check
	// runs whichever way the flag was set.
	//
	// The second probe really is a second connection: the pool keys a channel by
	// sandbox name but compares the whole target, and replaces one whose posture
	// changed. That is the property this depends on — without it both probes
	// would be answered by the first channel and this would compare a
	// connection with itself.
	other := sb
	other.Insecure = !sb.Insecure
	if probeOne(ctx, pool, other, timeout).answered {
		return healthView{}, postureMismatch(sb)
	}

	if asked.status == client.HealthUnknown {
		// Nothing was dialled in the posture asked for: this workstation holds
		// no control certificate, so the probe could not be made rather than
		// having been made and failed. That is a fact about this workstation,
		// not about the host, and refusing the registration over it would
		// answer a question about the fleet with a question about this
		// machine — the rule probeFleet already applies to `list`. The entry is
		// written, and says it was never confirmed.
		//
		// safeText rather than oneLine: this is a message about this
		// workstation, not an agent's account of itself, and it names the file
		// and the command that fixes it. `list` truncates its detail column
		// because it has a row per sandbox; add describes one host and can
		// afford the whole sentence, which is the same call `info` makes.
		detail := "not verified: " + safeText(pool.CredentialErr().Error())
		return healthView{status: client.HealthUnknown, detail: detail}, nil
	}
	return healthView{}, fmt.Errorf("nothing answered at %s within %s (%s). Nothing was registered: check the address, or pass --no-probe to register a host that is not up yet",
		sb.Address, timeout, asked.detail)
}

// postureMismatch is the refusal for a host that answered in the posture the
// operator did not ask for.
//
// Two sentences in both directions, because the cost differs and an operator
// acts on the cost. Registering mTLS for a plaintext host is the silent
// downgrade: the entry claims an identity check that nothing performs, and
// every view of the fleet will report auth mtls for a connection nothing
// authenticates. Registering --insecure for a host that does authenticate costs
// only failed calls, which is loud on its own — but it is still wrong, and #85
// was explicit that the posture must fail loudly in both directions.
func postureMismatch(sb registry.Sandbox) error {
	if sb.Insecure {
		return fmt.Errorf("%s answered over mTLS, but --insecure was given. Registering it that way would dial it in plaintext and every call would fail: drop --insecure. Nothing was registered",
			sb.Address)
	}
	return fmt.Errorf("%s answered without mTLS, but --insecure was not given. Registering it as authenticated would record an identity check nothing performs, and every view of this fleet would report auth mtls for a connection nothing authenticates: pass --insecure if that host's agent runs with tls.enabled false, or point --address at the host that does. Nothing was registered",
		sb.Address)
}
