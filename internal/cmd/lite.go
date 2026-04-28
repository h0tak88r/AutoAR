package cmd

import (
	"fmt"

	"github.com/h0tak88r/AutoAR/internal/scanner/lite"
	"github.com/spf13/cobra"
)

var liteCmd = &cobra.Command{
	Use:   "lite",
	Short: "Lite-related operations",
}

var liteRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a lighter workflow on a domain",
	RunE: func(cmd *cobra.Command, args []string) error {
		domainName, _ := cmd.Flags().GetString("domain")
		skipJS, _ := cmd.Flags().GetBool("skip-js")

		if domainName == "" {
			return fmt.Errorf("domain (-d) is required")
		}

		_, finalize := setupCurrentScanManaged("lite", domainName)

		opts := lite.Options{
			Domain: domainName,
			SkipJS: skipJS,
		}

		_, err := lite.RunLite(opts)
		finalize(err)
		return err
	},
}

func init() {
	rootCmd.AddCommand(liteCmd)
	liteCmd.AddCommand(liteRunCmd)

	liteRunCmd.Flags().StringP("domain", "d", "", "Target domain to scan")
	liteRunCmd.Flags().Bool("skip-js", false, "Skip JavaScript analysis phase")
	liteRunCmd.MarkFlagRequired("domain")
}
