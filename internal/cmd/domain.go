package cmd

import (
	"fmt"

	"github.com/h0tak88r/AutoAR/internal/modules/domain"
	"github.com/spf13/cobra"
)

var domainCmd = &cobra.Command{
	Use:   "domain",
	Short: "Domain-related operations",
}

var domainRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a full scan on a domain",
	RunE: func(cmd *cobra.Command, args []string) error {
		domainName, _ := cmd.Flags().GetString("domain")
		skipFFuf, _ := cmd.Flags().GetBool("skip-ffuf")

		if domainName == "" {
			return fmt.Errorf("domain (-d) is required")
		}

		_, finalize := setupCurrentScanManaged("domain_run", domainName)

		_, err := domain.RunDomain(domain.ScanOptions{
			Domain:   domainName,
			SkipFFuf: skipFFuf,
		})
		finalize(err)
		return err
	},
}

func init() {
	rootCmd.AddCommand(domainCmd)
	domainCmd.AddCommand(domainRunCmd)

	domainRunCmd.Flags().StringP("domain", "d", "", "Target domain to scan")
	domainRunCmd.Flags().Bool("skip-ffuf", false, "Skip FFuf fuzzing phase")
	domainRunCmd.MarkFlagRequired("domain")
}
