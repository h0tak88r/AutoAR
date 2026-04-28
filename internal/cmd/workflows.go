package cmd

import (
	"fmt"

	"github.com/h0tak88r/AutoAR/internal/scanner/fastlook"
	"github.com/h0tak88r/AutoAR/internal/scanner/subdomain"
	"github.com/spf13/cobra"
)

var (
	fastlookRunCmd = &cobra.Command{
		Use:   "fastlook",
		Short: "Quick reconnaissance workflow",
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, _ := cmd.Flags().GetString("domain")
			if domain == "" {
				return fmt.Errorf("domain is required")
			}

			_, finalize := setupCurrentScanManaged("fastlook", domain)

			_, err := fastlook.RunFastlook(domain, nil)
			finalize(err)
			return err
		},
	}

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
	rootCmd.AddCommand(fastlookRunCmd)
	rootCmd.AddCommand(subdomainRunCmd)

	fastlookRunCmd.Flags().StringP("domain", "d", "", "Target domain")
	fastlookRunCmd.MarkFlagRequired("domain")

	subdomainRunCmd.Flags().StringP("subdomain", "s", "", "Target subdomain")
	subdomainRunCmd.Flags().Bool("skip-ffuf", false, "Skip FFuf fuzzing phase")
	subdomainRunCmd.MarkFlagRequired("subdomain")
}
