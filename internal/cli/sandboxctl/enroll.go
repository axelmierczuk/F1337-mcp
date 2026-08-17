package sandboxctl

import (
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/axelmierczuk/fleet-mcp/internal/cli"

	"github.com/axelmierczuk/fleet-mcp/internal/security/ca"
	"github.com/axelmierczuk/fleet-mcp/internal/security/enroll"
)

func newEnrollCommand(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Mint and inspect single-use enrollment tokens",
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newEnrollMintCommand(out), newEnrollListCommand(out))
	return cmd
}

func newEnrollMintCommand(out io.Writer) *cobra.Command {
	var (
		name      string
		caDir     string
		tokenPath string
		labels    map[string]string
		addresses []string
		ttl       time.Duration
	)
	cmd := &cobra.Command{
		Use:   "mint",
		Short: "Mint a single-use enrollment token for a new sandbox",
		Long: "mint generates a token, stores only its hash, and prints the token once.\n\n" +
			"The --address values are the endpoints the enrolling host is authorized to\n" +
			"be certified for. An enrolling host cannot widen this set, which is what\n" +
			"stops one token from yielding a certificate that impersonates another\n" +
			"fleet member.",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			storePath, err := resolve(tokenPath, defaultTokenPath)
			if err != nil {
				return err
			}
			store, err := enroll.OpenTokenStore(storePath)
			if err != nil {
				return err
			}

			token, rec, err := store.Mint(enroll.MintOptions{
				Name:      name,
				Labels:    labels,
				Addresses: addresses,
				TTL:       ttl,
			})
			if err != nil {
				return err
			}

			p := cli.NewPrinter(out)
			p.Printf("token:     %s\n", token)
			p.Printf("name:      %s\n", rec.Name)
			p.Printf("expires:   %s\n", formatTime(rec.ExpiresAt))
			if len(rec.Addresses) > 0 {
				p.Printf("addresses: %v\n", rec.Addresses)
			}

			if dir, err := resolve(caDir, defaultCADir); err == nil {
				if authority, loadErr := ca.Load(dir); loadErr == nil {
					p.Printf("ca-fingerprint: %s\n", ca.FormatFingerprint(authority.Fingerprint()))
				}
			}

			p.Printf("\nThis token is shown once and is redeemable once.\n")
			if len(rec.Addresses) == 0 {
				// Say this at mint time rather than letting the agent fail
				// later: the leaf will carry only the sandbox name, so a
				// control plane dialling by address will reject it.
				p.Printf("No --address given, so the issued certificate will name only %q.\n", rec.Name)
				p.Printf("Re-mint with --address HOST:PORT if the control plane will dial this sandbox by address.\n")
			}
			return p.Err()
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "sandbox name to reserve for this token")
	cmd.Flags().StringVar(&caDir, "ca-dir", "", "directory holding the CA, for printing the fingerprint (default: <config dir>/ca)")
	cmd.Flags().StringVar(&tokenPath, "token-store", "", "path to the token store (default: <config dir>/enrollment-tokens.yaml)")
	cmd.Flags().StringToStringVar(&labels, "label", nil, "operator metadata as key=value; repeatable")
	cmd.Flags().StringArrayVar(&addresses, "address", nil, "host:port this sandbox is authorized to be certified for; repeatable")
	cmd.Flags().DurationVar(&ttl, "ttl", enroll.DefaultTokenTTL, "how long the token stays redeemable")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func newEnrollListCommand(out io.Writer) *cobra.Command {
	var tokenPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List minted enrollment tokens and their state",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			storePath, err := resolve(tokenPath, defaultTokenPath)
			if err != nil {
				return err
			}
			store, err := enroll.OpenTokenStore(storePath)
			if err != nil {
				return err
			}
			records, err := store.List()
			if err != nil {
				return err
			}
			p := cli.NewPrinter(out)
			if len(records) == 0 {
				p.Println("no enrollment tokens")
				return p.Err()
			}

			now := time.Now().UTC()
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			table := cli.NewPrinter(tw)
			table.Println("NAME\tSTATE\tEXPIRES\tADDRESSES")
			for _, rec := range records {
				state := "pending"
				switch {
				case rec.Used:
					state = "used"
				case rec.Expired(now):
					state = "expired"
				}
				table.Printf("%s\t%s\t%s\t%v\n", rec.Name, state, formatTime(rec.ExpiresAt), rec.Addresses)
			}
			if err := table.Err(); err != nil {
				return err
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&tokenPath, "token-store", "", "path to the token store (default: <config dir>/enrollment-tokens.yaml)")
	return cmd
}
