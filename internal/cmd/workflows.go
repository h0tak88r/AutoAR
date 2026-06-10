package cmd

import (
	"fmt"

	"github.com/h0tak88r/AutoAR/internal/scanner/subdomain"
	"github.com/spf13/cobra"
)

var (
	subdomainRunCmd = &cobra.Command{
		Use:   "subdomain",
		Short: "Deep-dive scan on a single subdomain",
		RunE: func(cmd *cobra.Command, args []string) error {
			sub, _ := cmd.Flags().GetString("subdomain")
			skipFFuf, _ := cmd.Flags().GetBool("skip-ffuf")
			if sub == "" {
				return fmt.Errorf("subdomain is required")
			}
			_, finalize := setupCurrentScanManaged("subdomain_run", sub)
			_, err := subdomain.RunSubdomainWithOptions(sub, subdomain.RunOptions{
				SkipFFuf: skipFFuf,
			})
			finalize(err)
			return err
		},
	}
)

func init() {
	rootCmd.AddCommand(subdomainRunCmd)

	subdomainRunCmd.Flags().StringP("subdomain", "s", "", "Target subdomain")
	subdomainRunCmd.Flags().Bool("skip-ffuf", false, "Skip FFuf fuzzing phase")
	subdomainRunCmd.MarkFlagRequired("subdomain")
}
