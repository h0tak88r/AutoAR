package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/h0tak88r/AutoAR/internal/modules/lite"
	"github.com/h0tak88r/AutoAR/internal/modules/db"
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

		scanID := os.Getenv("AUTOAR_CURRENT_SCAN_ID")
		if scanID == "" {
			scanID = fmt.Sprintf("lite-%d", os.Getpid())
			_ = db.Init()
			_ = db.InitSchema()
			_ = db.CreateScan(&db.ScanRecord{
				ScanID:   scanID,
				ScanType: "lite",
				Target:   domainName,
				Status:   "running",
			})
			os.Setenv("AUTOAR_CURRENT_SCAN_ID", scanID)
			defer func() {
				_ = db.UpdateScanStatus(scanID, "completed")
				os.Unsetenv("AUTOAR_CURRENT_SCAN_ID")
			}()
		}

		opts := lite.Options{
			Domain: domainName,
			SkipJS: skipJS,
		}

		_, err := lite.RunLite(opts)
		if err != nil {
			_ = db.UpdateScanStatus(scanID, "failed")
		}
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
