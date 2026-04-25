package cmd

import (
	"fmt"
	"os"

	"github.com/h0tak88r/AutoAR/internal/modules/db"
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

		// Handle scan ID and DB integration (logic ported from main.go)
		scanID := os.Getenv("AUTOAR_CURRENT_SCAN_ID")
		finalStatus := "completed"
		if scanID == "" {
			scanID = fmt.Sprintf("domain_run-%d", os.Getpid())
			_ = db.Init()
			_ = db.InitSchema()
			_ = db.CreateScan(&db.ScanRecord{
				ScanID:   scanID,
				ScanType: "domain_run",
				Target:   domainName,
				Status:   "running",
			})
			os.Setenv("AUTOAR_CURRENT_SCAN_ID", scanID)
			defer func() {
				_ = db.UpdateScanStatus(scanID, finalStatus)
				os.Unsetenv("AUTOAR_CURRENT_SCAN_ID")
			}()
		}

		_, err := domain.RunDomain(domain.ScanOptions{
			Domain:   domainName,
			SkipFFuf: skipFFuf,
		})

		if err != nil {
			finalStatus = "failed"
			_ = db.UpdateScanStatus(scanID, "failed")
		}
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
